//! The re-exec'd child: `quilt init`.
//!
//! A fresh image, already inside the new namespaces. Nothing from the parent
//! leaks in, and the mount plan runs where its effects belong. In phase 4 this
//! is also where the exec fifo blocks between `create` and `start`; phase 5
//! adds seccomp and the capability drop immediately before the `execve` below.

use std::ffi::CString;
use std::path::PathBuf;

use crate::error::{Context, Error, Result};
use crate::mount::{BindSpec, MountStrategy, StandardMounts};

pub struct InitSpec {
    pub rootfs: PathBuf,
    pub hostname: String,
    pub readonly_binds: Vec<BindSpec>,
    pub argv: Vec<String>,
}

/// Sets the container up and becomes the workload. Only returns on failure.
pub fn exec(spec: InitSpec) -> Result<std::convert::Infallible> {
    rustix::system::sethostname(spec.hostname.as_bytes())
        .context(|| format!("setting hostname to {:?}", spec.hostname))?;

    StandardMounts::new(spec.readonly_binds).prepare(&spec.rootfs)?.apply()?;

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
    fn an_empty_command_is_rejected() {
        assert!(workload(&[]).is_err());
    }
}
