//! Orchestration for one container: clone, map ids, hand off to init, wait.
//!
//! `create` and `start` are separate verbs in the OCI spec, so phase 4 splits
//! this and adds an exec fifo plus state on disk. Phase 1 only needs `run`,
//! which is the two of them back to back.

use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use rustix::process::{Pid, Signal, WaitOptions};

use crate::error::{Context, Error, Result};
use crate::idmap::IdMapper;
use crate::mount::BindSpec;
use crate::ns::{self, CloneArgs, Fork, Namespaces};

pub struct RunSpec {
    /// Absolute and canonical.
    pub rootfs: PathBuf,
    pub hostname: String,
    pub readonly_binds: Vec<BindSpec>,
    /// The workload and its arguments.
    pub argv: Vec<String>,
}

/// Exit code used when the init process could not be reached or execed. 127 is
/// what a shell reports for "command not found", which is the closest analogue.
const EXIT_INIT_FAILED: i32 = 127;
const EXIT_EXEC_FAILED: i32 = 126;

pub fn run(spec: &RunSpec, mapper: &dyn IdMapper, namespaces: Namespaces) -> Result<i32> {
    // Everything the child touches between `clone3` and `execve` is built here,
    // while allocation is still safe.
    let exe = CString::new("/proc/self/exe").expect("no interior NUL");
    let argv = cstrings(&init_argv(spec))?;
    let envp = cstrings(&container_env(spec))?;
    let argv_ptrs = pointer_array(&argv);
    let envp_ptrs = pointer_array(&envp);

    // CLOEXEC so the read end cannot outlive the child's own `execve`.
    let (map_wait, map_done) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .context(|| "creating the id-map sync pipe".to_string())?;

    let args = CloneArgs::new(namespaces.clone_flags());

    // SAFETY: `args.stack` is zero, so this is a fork. The child arm below does
    // nothing but close a descriptor, read one byte and `execve`.
    match unsafe { ns::clone3(&args) }? {
        Fork::Child => {
            drop(map_done);
            if !wait_for_maps(&map_wait) {
                rustix::runtime::exit_group(EXIT_INIT_FAILED);
            }
            // Only stdio should reach the container. The pipe above is CLOEXEC,
            // but descriptors quilt inherited from its own caller are not.
            // SAFETY: nothing below this point uses a descriptor above 2, and
            // every path from here ends in `execve` or `exit_group`, so no
            // `OwnedFd` destructor runs to close one of these twice.
            if unsafe { crate::syscall::close_range(3, u32::MAX, 0) }.is_err() {
                rustix::runtime::exit_group(EXIT_INIT_FAILED);
            }
            // SAFETY: the pointer arrays outlive this call and are NULL
            // terminated; `execve` only returns on failure.
            let _ = unsafe { rustix::runtime::execve(&exe, argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
            rustix::runtime::exit_group(EXIT_EXEC_FAILED);
        }

        Fork::Parent(child) => {
            drop(map_wait);
            // The child is blocked until the maps exist, because until they do
            // it has no usable uid and cannot create files in the new /dev.
            if let Err(e) = mapper.write_maps(child) {
                kill_and_reap(child);
                return Err(e);
            }
            if let Err(e) = rustix::io::write(&map_done, &[1u8])
                .context(|| "releasing the init process".to_string())
            {
                kill_and_reap(child);
                return Err(e);
            }
            drop(map_done);
            wait_for_exit(child)
        }
    }
}

/// The argv the re-exec'd `/proc/self/exe init` is given. Phase 4 replaces this
/// channel with the bundle's `config.json`.
fn init_argv(spec: &RunSpec) -> Vec<String> {
    let mut argv = vec![
        "quilt".to_string(),
        "init".to_string(),
        "--rootfs".to_string(),
        spec.rootfs.display().to_string(),
        "--hostname".to_string(),
        spec.hostname.clone(),
    ];
    for bind in &spec.readonly_binds {
        argv.push("--ro".to_string());
        argv.push(format!("{}:{}", bind.source.display(), bind.destination.display()));
    }
    argv.push("--".to_string());
    argv.extend(spec.argv.iter().cloned());
    argv
}

/// init inherits this and passes it straight to the workload.
fn container_env(spec: &RunSpec) -> Vec<String> {
    let mut env = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "HOME=/root".to_string(),
        format!("HOSTNAME={}", spec.hostname),
    ];
    if let Ok(term) = std::env::var("TERM") {
        env.push(format!("TERM={term}"));
    }
    env
}

fn cstrings(values: &[String]) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|v| {
            CString::new(v.as_str())
                .map_err(|_| Error::msg(format!("argument {v:?} contains a NUL byte")))
        })
        .collect()
}

fn pointer_array(values: &[CString]) -> Vec<*const u8> {
    let mut ptrs: Vec<*const u8> = values.iter().map(|c| c.as_ptr().cast()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}

/// Blocks until the parent signals that `uid_map` and `gid_map` are written.
/// Runs post-fork, so it allocates nothing.
fn wait_for_maps(fd: &OwnedFd) -> bool {
    let mut byte = [0u8; 1];
    loop {
        match rustix::io::read(fd, &mut byte[..]) {
            Ok(1) => return true,
            // Zero means the parent closed the pipe without writing: it failed.
            Ok(_) => return false,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return false,
        }
    }
}

fn wait_for_exit(child: Pid) -> Result<i32> {
    loop {
        match rustix::process::waitpid(Some(child), WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                if let Some(code) = exit_code(status.exit_status(), status.terminating_signal()) {
                    return Ok(code);
                }
                // Stopped or continued; keep waiting for a terminal status.
            }
            // Only WNOHANG can report "nothing yet", and this wait blocks.
            Ok(None) => {
                return Err(Error::msg("waitpid reported no status for a blocking wait"));
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e).context(|| "waiting for the container".to_string()),
        }
    }
}

/// A container's exit code, or `None` if it has not reached a terminal state.
///
/// A process killed by a signal has no exit status of its own, so quilt reports
/// the shell's `128 + signal`, which is what a caller of `run` expects.
fn exit_code(exit_status: Option<i32>, terminating_signal: Option<i32>) -> Option<i32> {
    exit_status.or_else(|| terminating_signal.map(|signal| 128 + signal))
}

fn kill_and_reap(child: Pid) {
    let _ = rustix::process::kill_process(child, Signal::KILL);
    let _ = rustix::process::waitpid(Some(child), WaitOptions::empty());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> RunSpec {
        RunSpec {
            rootfs: PathBuf::from("/srv/rootfs"),
            hostname: "quilt".into(),
            readonly_binds: vec![BindSpec {
                source: PathBuf::from("/etc/hosts"),
                destination: PathBuf::from("/etc/hosts"),
            }],
            argv: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
        }
    }

    #[test]
    fn init_argv_separates_the_workload_with_a_double_dash() {
        let argv = init_argv(&spec());
        let dash = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&argv[dash + 1..], &["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn init_argv_carries_rootfs_hostname_and_binds() {
        let argv = init_argv(&spec());
        assert_eq!(argv[0..2], ["quilt", "init"]);
        assert!(argv.windows(2).any(|w| w == ["--rootfs", "/srv/rootfs"]));
        assert!(argv.windows(2).any(|w| w == ["--hostname", "quilt"]));
        assert!(argv.windows(2).any(|w| w == ["--ro", "/etc/hosts:/etc/hosts"]));
    }

    #[test]
    fn the_pointer_array_is_null_terminated() {
        let owned = cstrings(&["a".into(), "b".into()]).unwrap();
        let ptrs = pointer_array(&owned);
        assert_eq!(ptrs.len(), 3);
        assert!(ptrs[2].is_null());
    }

    #[test]
    fn an_argument_containing_a_nul_is_rejected_rather_than_truncated() {
        assert!(cstrings(&["bad\0arg".into()]).is_err());
    }

    #[test]
    fn a_clean_exit_reports_its_own_code() {
        assert_eq!(exit_code(Some(42), None), Some(42));
        assert_eq!(exit_code(Some(0), None), Some(0));
    }

    #[test]
    fn a_signalled_exit_reports_128_plus_the_signal() {
        // SIGKILL is 9, SIGSEGV is 11.
        assert_eq!(exit_code(None, Some(9)), Some(137));
        assert_eq!(exit_code(None, Some(11)), Some(139));
    }

    #[test]
    fn a_stopped_child_has_no_exit_code_yet() {
        assert_eq!(exit_code(None, None), None);
    }

    #[test]
    fn container_env_sets_a_path_and_the_hostname() {
        let env = container_env(&spec());
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.contains(&"HOSTNAME=quilt".to_string()));
    }
}
