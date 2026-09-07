//! Writing `/proc/<pid>/uid_map` and `gid_map`.
//!
//! One of the three seams the spec keeps behind a trait. `Identity` needs
//! privilege and covers phases 1-5; `SubUid` (phase 6) will shell out to
//! `newuidmap`, which is setuid and is the only sanctioned way an unprivileged
//! process gets a range.

use crate::error::{Context, Result};
use rustix::process::Pid;

pub trait IdMapper {
    fn write_maps(&self, pid: Pid) -> Result<()>;
}

/// Maps the whole id space straight through. Requires CAP_SETUID/CAP_SETGID in
/// the parent user namespace, i.e. real root.
pub struct Identity;

const FULL_RANGE: u32 = u32::MAX;

impl IdMapper for Identity {
    fn write_maps(&self, pid: Pid) -> Result<()> {
        write_map(pid, "uid_map", &map_line(0, 0, FULL_RANGE))?;
        write_map(pid, "gid_map", &map_line(0, 0, FULL_RANGE))
    }
}

/// One `inside outside count` row of a uid/gid map.
fn map_line(inside: u32, outside: u32, count: u32) -> String {
    format!("{inside} {outside} {count}\n")
}

/// The map files accept exactly one `write`, so the whole map goes in a single
/// call — which is what `fs::write` does.
fn write_map(pid: Pid, file: &str, contents: &str) -> Result<()> {
    let path = format!("/proc/{}/{}", pid.as_raw_nonzero(), file);
    std::fs::write(&path, contents).context(|| format!("writing {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_maps_the_whole_range_from_zero() {
        assert_eq!(map_line(0, 0, FULL_RANGE), "0 0 4294967295\n");
    }

    #[test]
    fn a_map_line_is_newline_terminated() {
        assert_eq!(map_line(0, 524288, 65536), "0 524288 65536\n");
    }
}
