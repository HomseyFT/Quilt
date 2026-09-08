//! The re-exec'd child: `quilt init`.
//!
//! A fresh image, already inside the new namespaces. Nothing from the parent
//! leaks in, and the mount plan runs where its effects belong. In phase 4 this
//! is also where the exec fifo blocks between `create` and `start`; phase 5
//! adds seccomp and the capability drop immediately before the `execve` below.

use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};

use crate::error::{Context, Error, Result};
use crate::mount::{BindSpec, MountStrategy, OciMounts, StandardMounts};
use crate::net::veth::{self, Endpoint};

pub struct InitSpec {
    pub rootfs: PathBuf,
    pub hostname: String,
    pub readonly_binds: Vec<BindSpec>,
    pub argv: Vec<String>,
    pub network: Option<Endpoint>,
}

/// Sets the container up and becomes the workload. Only returns on failure.
pub fn exec(spec: InitSpec) -> Result<std::convert::Infallible> {
    rustix::system::sethostname(spec.hostname.as_bytes())
        .context(|| format!("setting hostname to {:?}", spec.hostname))?;

    StandardMounts::new(spec.readonly_binds).prepare(&spec.rootfs)?.apply()?;

    // After the mount plan, because the interface index comes out of sysfs and
    // sysfs is mounted by that plan. It is the container's own sysfs, so it
    // shows the container's netns.
    if let Some(endpoint) = &spec.network {
        veth::configure(endpoint)?;
    }

    let (program, argv, envp) = workload(&spec.argv)?;
    let argv_ptrs = pointer_array(&argv);
    let envp_ptrs = pointer_array(&envp);

    // SAFETY: both arrays are NULL terminated and outlive the call.
    let errno = unsafe { rustix::runtime::execve(&program, argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    Err(errno).context(|| format!("exec {:?}", spec.argv[0]))
}

/// The workload's program path, argv and the environment inherited from `run`.
fn workload(argv: &[String]) -> Result<(CString, Vec<CString>, Vec<CString>)> {
    let program = argv
        .first()
        .ok_or_else(|| Error::msg("no command given".to_string()))?;
    let program = CString::new(program.as_str())
        .map_err(|_| Error::msg("the command contains a NUL byte".to_string()))?;

    let argv = argv
        .iter()
        .map(|a| {
            CString::new(a.as_str())
                .map_err(|_| Error::msg(format!("argument {a:?} contains a NUL byte")))
        })
        .collect::<Result<Vec<_>>>()?;

    let envp = std::env::vars()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}"))
                .map_err(|_| Error::msg(format!("environment variable {k:?} contains a NUL byte")))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok((program, argv, envp))
}

fn pointer_array(values: &[CString]) -> Vec<*const u8> {
    let mut ptrs: Vec<*const u8> = values.iter().map(|c| c.as_ptr().cast()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}

/// Parses the `SRC:DST` pairs `run` puts on init's command line.
pub fn parse_bind(value: &str) -> Result<BindSpec> {
    let (source, destination) = value
        .split_once(':')
        .ok_or_else(|| Error::msg(format!("bind {value:?} is not SRC:DST")))?;
    if source.is_empty() || destination.is_empty() {
        return Err(Error::msg(format!("bind {value:?} has an empty side")));
    }
    Ok(BindSpec {
        source: PathBuf::from(source),
        destination: PathBuf::from(destination),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bind_splits_on_the_first_colon() {
        let bind = parse_bind("/etc/hosts:/etc/hosts").unwrap();
        assert_eq!(bind.source, PathBuf::from("/etc/hosts"));
        assert_eq!(bind.destination, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn a_bind_without_a_colon_is_rejected() {
        assert!(parse_bind("/etc/hosts").is_err());
    }

    #[test]
    fn a_bind_with_an_empty_side_is_rejected() {
        assert!(parse_bind(":/etc/hosts").is_err());
        assert!(parse_bind("/etc/hosts:").is_err());
    }

    #[test]
    fn a_bare_command_is_searched_for_along_path() {
        // podman sends ["ls", "/"], not ["/bin/ls", "/"].
        let env = vec!["PATH=/usr/bin:/bin".to_string()];
        assert_eq!(
            program_candidates("ls", &env),
            [PathBuf::from("/usr/bin/ls"), PathBuf::from("/bin/ls")]
        );
    }

    #[test]
    fn a_command_with_a_slash_is_a_path_already() {
        let env = vec!["PATH=/usr/bin".to_string()];
        assert_eq!(program_candidates("/bin/sh", &env), [PathBuf::from("/bin/sh")]);
        assert_eq!(program_candidates("./run.sh", &env), [PathBuf::from("./run.sh")]);
    }

    #[test]
    fn empty_path_entries_are_skipped_rather_than_becoming_the_root() {
        let env = vec!["PATH=/bin::/usr/bin".to_string()];
        assert_eq!(
            program_candidates("ls", &env),
            [PathBuf::from("/bin/ls"), PathBuf::from("/usr/bin/ls")]
        );
    }

    #[test]
    fn a_bare_command_with_no_path_at_all_has_nowhere_to_look() {
        assert!(program_candidates("ls", &[]).is_empty());
        assert!(resolve_program("ls", &[]).is_err());
    }

    #[test]
    fn an_empty_command_is_rejected() {
        assert!(workload(&[]).is_err());
    }
}

// ---------------------------------------------------------------------------
// The OCI init process.
//
// Launched by `create`, it does the setup, reports that it survived it, and
// then parks on the exec fifo until `start` opens the other end. Everything
// that reduces privilege happens after that wait, because the setup needs the
// privileges the workload must not keep.
// ---------------------------------------------------------------------------

pub struct OciInit {
    pub bundle: PathBuf,
    pub fifo: PathBuf,
    /// Inherited from `create`, which is waiting to hear that setup worked.
    pub ready_fd: std::os::fd::RawFd,
    /// Ask the kernel to log every seccomp denial.
    pub seccomp_log: bool,
}

pub fn exec_oci(init: OciInit) -> Result<std::convert::Infallible> {
    let config_path = init.bundle.join("config.json");
    let json = std::fs::read_to_string(&config_path)
        .context(|| format!("reading {}", config_path.display()))?;
    let config = crate::spec::Config::parse(&json)?;

    // Namespaces the caller pre-created. First, because the sysctls below and
    // the sysfs mount in the plan are both scoped to whichever namespace this
    // process is in by then.
    crate::ns::join_all(&config.linux.namespaces)?;

    if !config.hostname.is_empty() {
        rustix::system::sethostname(config.hostname.as_bytes())
            .context(|| format!("setting hostname to {:?}", config.hostname))?;
    }

    // Before the mount plan, deliberately. These are written through /proc,
    // and the plan makes the container's own /proc/sys read-only.
    apply_sysctls(&config.linux.sysctl)?;

    // The fifo lives outside the container, and `pivot_root` is about to put it
    // out of reach by name. A directory descriptor survives that, and `openat`
    // through it does not go near path resolution.
    let fifo_dir = init.fifo.parent().ok_or_else(|| {
        Error::msg(format!("{} has no directory", init.fifo.display()))
    })?;
    let fifo_dir = rustix::fs::open(
        fifo_dir,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context(|| "opening the container's state directory".to_string())?;
    let fifo_name = init
        .fifo
        .file_name()
        .ok_or_else(|| Error::msg(format!("{} has no file name", init.fifo.display())))?
        .to_os_string();

    let rootfs = if config.root.path.is_absolute() {
        config.root.path.clone()
    } else {
        init.bundle.join(&config.root.path)
    };
    OciMounts::new(&config).prepare(&rootfs)?.apply()?;

    signal_ready(init.ready_fd)?;

    // Parks here until `start` opens the other end.
    let reader = rustix::fs::openat(
        &fifo_dir,
        fifo_name.as_os_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context(|| "waiting on the exec fifo".to_string())?;
    let mut byte = [0u8; 1];
    let _ = rustix::io::read(&reader, &mut byte[..]);
    drop(reader);
    drop(fifo_dir);

    apply_rlimits(&config.process.rlimits)?;

    if config.process.no_new_privileges {
        crate::caps::set_no_new_privs()?;
    }

    // The two capability passes straddle the user change, because each half
    // only works on its own side of it. See `caps::narrow_bounding`.
    if let Some(capabilities) = &config.process.capabilities {
        crate::caps::narrow_bounding(capabilities)?;
    }

    // Keeps the permitted set across the uid change, so the pass below has
    // something to raise the effective set out of.
    rustix::thread::set_keep_capabilities(true)
        .context(|| "asking to keep capabilities across the uid change".to_string())?;
    apply_user(&config.process.user)?;

    if let Some(capabilities) = &config.process.capabilities {
        crate::caps::apply_sets(capabilities)?;
    }

    rustix::process::chdir(&config.process.cwd)
        .context(|| format!("chdir to {}", config.process.cwd.display()))?;

    // Everything the filter would have to permit for quilt's own sake happens
    // first. Searching PATH stats candidate files, and `chdir` above is a
    // syscall the container has no reason to be allowed — resolving both now
    // leaves `execve` as the only thing between the filter and the workload.
    let (program, argv, envp) = oci_workload(&config.process.args, &config.process.env)?;
    let argv_ptrs = pointer_array(&argv);
    let envp_ptrs = pointer_array(&envp);

    // Last, and deliberately so: the setup above needs mount, pivot_root and
    // writes to cgroup files, which is exactly what a container's policy denies.
    if let Some(profile) = &config.linux.seccomp {
        let filter = crate::seccomp::compile(profile)?;
        crate::seccomp::install(&filter, init.seccomp_log)?;
    }

    // SAFETY: both arrays are NULL terminated and outlive the call.
    let errno =
        unsafe { rustix::runtime::execve(&program, argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
    Err(errno).context(|| format!("exec {:?}", config.process.args.first()))
}

/// Tells `create` the container survived setup.
fn signal_ready(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: `create` handed this descriptor over and is holding the far end.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    rustix::io::write(borrowed, &[1u8])
        .context(|| "reporting readiness to create".to_string())?;
    // SAFETY: taking ownership back so the descriptor closes here; `create`
    // reads EOF if anything after this point fails.
    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    Ok(())
}

/// Sysctls that belong to a namespace, and so are the container's to set.
///
/// Everything else reaches the whole machine. A bundle asking for one of those
/// is asking the runtime to reconfigure the host, and quietly obliging is worse
/// than refusing.
fn is_namespaced_sysctl(key: &str) -> bool {
    const NAMESPACED: &[&str] = &[
        "kernel.domainname",
        "kernel.hostname",
        "kernel.msgmax",
        "kernel.msgmnb",
        "kernel.msgmni",
        "kernel.sem",
        "kernel.shmall",
        "kernel.shmmax",
        "kernel.shmmni",
        "kernel.shm_rmid_forced",
    ];

    key.starts_with("net.") || key.starts_with("fs.mqueue.") || NAMESPACED.contains(&key)
}

fn apply_sysctls(sysctls: &std::collections::BTreeMap<String, String>) -> Result<()> {
    for (key, value) in sysctls {
        if !is_namespaced_sysctl(key) {
            return Err(Error::msg(format!(
                "config.json sets the sysctl {key}, which is not namespaced and would \
                 reconfigure the host"
            )));
        }
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        std::fs::write(&path, value)
            .context(|| format!("setting the sysctl {key} to {value:?}"))?;
    }
    Ok(())
}

fn rlimit_resource(name: &str) -> Result<rustix::process::Resource> {
    use rustix::process::Resource;

    Ok(match name {
        "RLIMIT_CPU" => Resource::Cpu,
        "RLIMIT_FSIZE" => Resource::Fsize,
        "RLIMIT_DATA" => Resource::Data,
        "RLIMIT_STACK" => Resource::Stack,
        "RLIMIT_CORE" => Resource::Core,
        "RLIMIT_RSS" => Resource::Rss,
        "RLIMIT_NPROC" => Resource::Nproc,
        "RLIMIT_NOFILE" => Resource::Nofile,
        "RLIMIT_MEMLOCK" => Resource::Memlock,
        "RLIMIT_AS" => Resource::As,
        "RLIMIT_LOCKS" => Resource::Locks,
        "RLIMIT_SIGPENDING" => Resource::Sigpending,
        "RLIMIT_MSGQUEUE" => Resource::Msgqueue,
        "RLIMIT_NICE" => Resource::Nice,
        "RLIMIT_RTPRIO" => Resource::Rtprio,
        "RLIMIT_RTTIME" => Resource::Rttime,
        other => {
            return Err(Error::msg(format!("config.json sets an unknown rlimit: {other}")));
        }
    })
}

/// Checks the rlimit names without setting anything, for `create`.
pub fn validate_rlimits(rlimits: &[crate::spec::Rlimit]) -> Result<()> {
    rlimits.iter().try_for_each(|rlimit| rlimit_resource(&rlimit.kind).map(|_| ()))
}

fn apply_rlimits(rlimits: &[crate::spec::Rlimit]) -> Result<()> {
    for rlimit in rlimits {
        rustix::process::setrlimit(
            rlimit_resource(&rlimit.kind)?,
            rustix::process::Rlimit { current: Some(rlimit.soft), maximum: Some(rlimit.hard) },
        )
        .context(|| format!("setting {}", rlimit.kind))?;
    }
    Ok(())
}

/// Becomes the user the bundle asked for. Groups first: dropping to a
/// non-root uid takes away the privilege needed to set them.
fn apply_user(user: &crate::spec::User) -> Result<()> {
    if let Some(mask) = user.umask {
        rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
    }

    let groups: Vec<rustix::process::Gid> = user
        .additional_gids
        .iter()
        .map(|gid| rustix::process::Gid::from_raw(*gid))
        .collect();
    rustix::thread::set_thread_groups(&groups).context(|| "setting supplementary groups".to_string())?;

    // The ids come from the bundle; the kernel decides whether this process is
    // allowed to assume them.
    let gid = rustix::process::Gid::from_raw(user.gid);
    let uid = rustix::process::Uid::from_raw(user.uid);
    rustix::thread::set_thread_res_gid(gid, gid, gid).context(|| "setting the group id".to_string())?;
    rustix::thread::set_thread_res_uid(uid, uid, uid).context(|| "setting the user id".to_string())
}

/// Where a bare `args[0]` might be, in the order PATH gives.
///
/// A name with a slash in it is a path already and is used as it stands, the
/// same rule a shell follows.
fn program_candidates(program: &str, env: &[String]) -> Vec<PathBuf> {
    if program.contains('/') {
        return vec![PathBuf::from(program)];
    }

    let path = env.iter().find_map(|entry| entry.strip_prefix("PATH=")).unwrap_or_default();
    path.split(':')
        .filter(|directory| !directory.is_empty())
        .map(|directory| Path::new(directory).join(program))
        .collect()
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Finds the program the bundle asked for, inside the container.
///
/// `process.args[0]` is a command name, not necessarily a path: podman sends
/// `["ls", "/"]` and expects the runtime to search `process.env`'s PATH, which
/// is why this runs after the pivot rather than before it.
fn resolve_program(program: &str, env: &[String]) -> Result<CString> {
    let candidates = program_candidates(program, env);

    for candidate in &candidates {
        if is_executable(candidate) {
            return CString::new(candidate.as_os_str().as_encoded_bytes())
                .map_err(|_| Error::msg(format!("{candidate:?} contains a NUL byte")));
        }
    }

    Err(Error::msg(match candidates.len() {
        0 => format!("{program:?} is not a path and process.env sets no PATH to search"),
        _ => format!("{program:?} is not an executable in the container: tried {candidates:?}"),
    }))
}

/// The workload's program, argv and environment, all from the bundle.
fn oci_workload(
    args: &[String],
    env: &[String],
) -> Result<(CString, Vec<CString>, Vec<CString>)> {
    let program = args
        .first()
        .ok_or_else(|| Error::msg("config.json has no process.args".to_string()))?;
    let program = resolve_program(program, env)?;

    let to_cstrings = |values: &[String]| -> Result<Vec<CString>> {
        values
            .iter()
            .map(|v| {
                CString::new(v.as_str())
                    .map_err(|_| Error::msg(format!("{v:?} contains a NUL byte")))
            })
            .collect()
    };

    Ok((program, to_cstrings(args)?, to_cstrings(env)?))
}
