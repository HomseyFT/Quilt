mod caps;
mod cgroup;
mod container;
mod error;
mod idmap;
mod init;
mod mount;
mod net;
mod ns;
mod seccomp;
mod spec;
mod syscall;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::cgroup::Limits;
use crate::container::{Connectivity, RunSpec};
use crate::error::{Context, Error, Result};
use crate::idmap::{Identity, SubUid};
use crate::init::{InitSpec, OciInit as InitOci};
use crate::net::NetworkMode;
use crate::net::veth::{self, Endpoint};
use crate::ns::Namespaces;

#[derive(Parser)]
#[command(name = "quilt", version, about = "a container runtime from scratch")]
struct Cli {
    /// Where the runtime keeps container state.
    ///
    /// Defaults to /run/quilt as root, and /run/user/<uid>/quilt otherwise.
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Refused. quilt writes cgroup files directly; see SPEC.md's non-goals.
    #[arg(long, global = true)]
    systemd_cgroup: bool,

    /// Accepted and unused. Podman passes these to every runtime, and a
    /// runtime that rejected them could not be dropped in.
    #[arg(long, global = true, value_name = "PATH")]
    log: Option<PathBuf>,
    #[arg(long, global = true, value_name = "FORMAT")]
    log_format: Option<String>,
    #[arg(long, global = true)]
    debug: bool,

    /// Ask the kernel to log every seccomp denial to the audit log.
    ///
    /// A denied syscall otherwise surfaces as an unexplained failure deep
    /// inside a program you did not write.
    #[arg(long, global = true)]
    seccomp_log: bool,

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

    /// Create a container from an OCI bundle and wait on its exec fifo.
    Create(CreateArgs),
    /// Run the workload of a container that was created.
    Start { id: String },
    /// Print a container's state as JSON.
    State { id: String },
    /// Send a signal to a container's process.
    Kill {
        id: String,
        /// A name or number: KILL, SIGKILL and 9 are the same signal.
        #[arg(default_value = "SIGTERM")]
        signal: String,
    },
    /// Remove a container's state and cgroup.
    Delete {
        id: String,
        /// Kill the container first if it is still running.
        #[arg(long)]
        force: bool,
    },

    /// Set up a container from a bundle and become its workload. Re-exec'd by
    /// `create`.
    #[command(hide = true, name = "init-oci")]
    InitOci(InitOciArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// The directory holding config.json and the rootfs.
    #[arg(long)]
    bundle: PathBuf,

    /// Where to write the container process's pid.
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,

    /// Refused: a terminal needs a pty passed back over this socket.
    #[arg(long, value_name = "PATH")]
    console_socket: Option<PathBuf>,

    id: String,
}

#[derive(Args)]
struct InitOciArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    fifo: PathBuf,
    #[arg(long)]
    ready_fd: std::os::fd::RawFd,
    #[arg(long)]
    seccomp_log: bool,
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

    /// Networking: an empty namespace, or a veth onto the quilt0 bridge.
    #[arg(long, value_enum, default_value_t = NetworkMode::None)]
    net: NetworkMode,

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

    #[arg(long, value_name = "ADDRESS/PREFIX", requires = "net_gateway")]
    net_address: Option<String>,

    #[arg(long, value_name = "ADDRESS", requires = "net_address")]
    net_gateway: Option<String>,

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
    let root = cli.root.clone().unwrap_or_else(container::default_state_root);

    if cli.systemd_cgroup {
        return Err(Error::msg(
            "--systemd-cgroup asks quilt to have systemd own the container's scope, which it \
             cannot: podman --cgroup-manager=cgroupfs"
                .to_string(),
        ));
    }

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
                network: match (&args.net_address, &args.net_gateway) {
                    (Some(address), Some(gateway)) => Some(Endpoint::parse(address, gateway)?),
                    _ => None,
                },
            })?;
            unreachable!("init::exec only returns an error")
        }

        Command::Create(args) => {
            if let Some(path) = &args.console_socket {
                return Err(Error::msg(format!(
                    "--console-socket {} asks quilt to hand back a pty, which it does not \
                     create: run podman without -t",
                    path.display()
                )));
            }
            container::create(
                &root,
                &args.id,
                &args.bundle,
                args.pid_file.as_deref(),
                cli.seccomp_log,
            )?;
            Ok(0)
        }

        Command::Start { id } => {
            container::start(&root, &id)?;
            Ok(0)
        }

        Command::State { id } => {
            println!("{}", container::print_state(&root, &id)?);
            Ok(0)
        }

        Command::Kill { id, signal } => {
            container::kill(&root, &id, &signal)?;
            Ok(0)
        }

        Command::Delete { id, force } => {
            container::delete(&root, &id, force)?;
            Ok(0)
        }

        Command::InitOci(args) => {
            init::exec_oci(InitOci {
                bundle: args.bundle,
                fifo: args.fifo,
                ready_fd: args.ready_fd,
                seccomp_log: args.seccomp_log,
            })?;
            unreachable!("init::exec_oci only returns an error")
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

    let limits = Limits::from_cli(
        args.memory.as_deref().map(cgroup::parse_size).transpose()?,
        args.cpus,
        args.pids,
    )?;

    // The runtime's own pid is unique among the containers running at any one
    // time, which is all the address and interface name need.
    let network = match args.net {
        NetworkMode::None => None,
        NetworkMode::Bridge if !idmap::has_host_privilege() => {
            return Err(Error::msg(
                "--net bridge needs CAP_NET_ADMIN on the host to make a veth and a NAT rule: \
                 --net pasta does the same job from user space"
                    .to_string(),
            ));
        }
        NetworkMode::Bridge => Some(Connectivity::Bridge(veth::Plan::new(std::process::id()))),
        NetworkMode::Pasta => Some(Connectivity::Pasta),
    };

    let spec = RunSpec {
        rootfs,
        hostname: args.hostname,
        readonly_binds,
        argv: args.command,
        limits,
        network,
    };

    // One scope per invocation. Phase 4 takes the id from the OCI caller.
    let id = cgroup::run_id();
    let driver = cgroup::driver_for_this_user(&id, None)?;

    // The two seams pick their implementation from the same fact: whether this
    // process has privilege over the host or only over a namespace.
    if idmap::has_host_privilege() {
        container::run(&spec, &Identity, driver.as_ref(), Namespaces::DEFAULT)
    } else {
        container::run(&spec, &SubUid::for_current_user()?, driver.as_ref(), Namespaces::DEFAULT)
    }
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
    fn networking_is_off_unless_asked_for() {
        let cli = Cli::try_parse_from(["quilt", "run", "./rootfs", "/bin/sh"]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected run") };
        assert_eq!(args.net, NetworkMode::None);
    }

    #[test]
    fn cli_accepts_bridge_networking() {
        let cli =
            Cli::try_parse_from(["quilt", "run", "--net", "bridge", "./rootfs", "/bin/sh"]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected run") };
        assert_eq!(args.net, NetworkMode::Bridge);
    }

    #[test]
    fn cli_rejects_an_unknown_network_mode() {
        assert!(Cli::try_parse_from(["quilt", "run", "--net", "macvlan", "./rootfs", "sh"]).is_err());
    }

    #[test]
    fn cli_requires_a_command() {
        assert!(Cli::try_parse_from(["quilt", "run", "./rootfs"]).is_err());
    }
}
