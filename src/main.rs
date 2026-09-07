mod cgroup;
mod container;
mod error;
mod idmap;
mod init;
mod mount;
mod ns;
mod syscall;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::cgroup::{Limits, RootCgroup};
use crate::container::RunSpec;
use crate::error::{Context, Error, Result};
use crate::idmap::Identity;
use crate::init::InitSpec;
use crate::ns::Namespaces;

#[derive(Parser)]
#[command(name = "quilt", version, about = "a container runtime from scratch")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a container, start it, and wait for it to exit.
    Run(RunArgs),
    /// Set up the container and become the workload. Re-exec'd by `run`.
    #[command(hide = true)]
    Init(InitArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Directory holding the container's root filesystem.
    rootfs: PathBuf,

    #[arg(long, default_value = "quilt")]
    hostname: String,

    /// Bind a host path into the container read-only, as SRC or SRC:DST.
    #[arg(long = "ro", value_name = "SRC[:DST]")]
    readonly: Vec<String>,

    /// Memory ceiling, as 64M, 512K or a plain byte count.
    #[arg(long, value_name = "SIZE")]
    memory: Option<String>,

    /// CPU share, where 0.5 is half of one core.
    #[arg(long, value_name = "N")]
    cpus: Option<f64>,

    /// Maximum number of processes.
    #[arg(long, value_name = "N")]
    pids: Option<u64>,

    /// The command to run, and its arguments.
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

#[derive(Args)]
struct InitArgs {
    #[arg(long)]
    rootfs: PathBuf,

    #[arg(long)]
    hostname: String,

    #[arg(long = "ro", value_name = "SRC:DST")]
    readonly: Vec<String>,

    #[arg(trailing_var_arg = true, num_args = 1..)]
    command: Vec<String>,
}

fn main() {
    let code = match dispatch(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("quilt: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn dispatch(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Run(args) => run(args),
        Command::Init(args) => {
            init::exec(InitSpec {
                rootfs: args.rootfs,
                hostname: args.hostname,
                readonly_binds: args
                    .readonly
                    .iter()
                    .map(|v| init::parse_bind(v))
                    .collect::<Result<Vec<_>>>()?,
                argv: args.command,
            })?;
            unreachable!("init::exec only returns an error")
        }
    }
}

fn run(args: RunArgs) -> Result<i32> {
    let rootfs = args
        .rootfs
        .canonicalize()
        .context(|| format!("resolving rootfs {}", args.rootfs.display()))?;
    if !rootfs.is_dir() {
        return Err(Error::msg(format!("{} is not a directory", rootfs.display())));
    }

    let readonly_binds = args
        .readonly
        .iter()
        .map(|value| readonly_bind(value))
        .collect::<Result<Vec<_>>>()?;

    let limits = Limits {
        memory: args.memory.as_deref().map(cgroup::parse_size).transpose()?,
        cpus: args.cpus,
        pids: args.pids,
    };
    // Validated here so a bad --cpus fails before a container is built.
    if let Some(cpus) = limits.cpus {
        cgroup::cpu_max(cpus)?;
    }

    let spec =
        RunSpec { rootfs, hostname: args.hostname, readonly_binds, argv: args.command, limits };

    // One scope per invocation. Phase 4 takes the id from the OCI caller.
    let driver = RootCgroup::new(format!("run-{}", std::process::id()));
    container::run(&spec, &Identity, &driver, Namespaces::DEFAULT)
}

/// `SRC` mounts at the same path inside; `SRC:DST` mounts at `DST`. The pair is
/// passed to init on its command line, so neither side may contain a colon.
fn readonly_bind(value: &str) -> Result<mount::BindSpec> {
    let (source, destination) = match value.split_once(':') {
        Some((source, destination)) => (source, destination),
        None => (value, value),
    };
    if source.contains(':') || destination.contains(':') {
        return Err(Error::msg(format!("bind path {value:?} may not contain a colon")));
    }
    let source = PathBuf::from(source)
        .canonicalize()
        .context(|| format!("resolving bind source {source}"))?;
    let destination = PathBuf::from(destination);
    if !destination.is_absolute() {
        return Err(Error::msg(format!(
            "bind destination {} must be absolute",
            destination.display()
        )));
    }
    Ok(mount::BindSpec { source, destination })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_path_binds_at_the_same_place_inside() {
        let bind = readonly_bind("/etc/hosts").unwrap();
        assert_eq!(bind.destination, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn a_pair_binds_at_the_second_path() {
        let bind = readonly_bind("/etc/hosts:/etc/quilt-hosts").unwrap();
        assert_eq!(bind.source, PathBuf::from("/etc/hosts"));
        assert_eq!(bind.destination, PathBuf::from("/etc/quilt-hosts"));
    }

    #[test]
    fn a_relative_destination_is_rejected() {
        assert!(readonly_bind("/etc/hosts:etc/hosts").is_err());
    }

    #[test]
    fn a_missing_source_is_rejected_before_the_clone() {
        assert!(readonly_bind("/nonexistent/quilt-test-path").is_err());
    }

    #[test]
    fn cli_parses_the_phase_one_demo() {
        let cli = Cli::try_parse_from(["quilt", "run", "./rootfs", "/bin/sh"]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected run") };
        assert_eq!(args.rootfs, PathBuf::from("./rootfs"));
        assert_eq!(args.command, ["/bin/sh"]);
    }

    #[test]
    fn cli_keeps_the_workloads_own_flags() {
        let cli =
            Cli::try_parse_from(["quilt", "run", "./rootfs", "/bin/sh", "-c", "ps aux"]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected run") };
        assert_eq!(args.command, ["/bin/sh", "-c", "ps aux"]);
    }

    #[test]
    fn cli_requires_a_command() {
        assert!(Cli::try_parse_from(["quilt", "run", "./rootfs"]).is_err());
    }
}
