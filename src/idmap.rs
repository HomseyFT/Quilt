//! Writing `/proc/<pid>/uid_map` and `gid_map`.
//!
//! One of the three seams the spec keeps behind a trait. `Identity` needs
//! privilege and covers phases 1-5; `SubUid` (phase 6) will shell out to
//! `newuidmap`, which is setuid and is the only sanctioned way an unprivileged
//! process gets a range.

use crate::error::{Context, Error, Result};
use rustix::process::Pid;

/// Whether this process holds privilege over the host, rather than over a user
/// namespace that only looks like the host from inside.
///
/// Neither half answers this alone. `geteuid()` says 0 inside a namespace too —
/// rootless podman runs its runtime as uid 0 in one mapped to an unprivileged
/// user outside, so the runtime believes it is root and every write still lands
/// as the real user. And the identity mapping is not enough either, because an
/// ordinary user's shell has it. Both together are what root actually looks
/// like.
pub fn has_host_privilege() -> bool {
    rustix::process::geteuid().is_root() && in_initial_user_namespace()
}

/// Whether this process's user namespace is the one the kernel booted with.
///
/// Only that namespace passes the whole id space through unchanged, and a
/// namespace that did so was made by something which already had the privilege
/// to. On its own this is not enough — an ordinary user's shell is in the
/// initial namespace too — which is why [`has_host_privilege`] asks for both.
fn in_initial_user_namespace() -> bool {
    std::fs::read_to_string("/proc/self/uid_map").map(|map| is_identity_map(&map)).unwrap_or(false)
}

/// The uid this process has *outside* its user namespace.
///
/// A rootless runtime is uid 0 inside and something else outside, and the
/// things it has to name — `/run/user/<uid>`, `user@<uid>.service`, the owner
/// of a subordinate range — are named for the outside id. Asking `getuid()`
/// gets the wrong one and the failure is a permission error on a path that
/// belongs to root.
pub fn host_uid() -> u32 {
    outside_id("/proc/self/uid_map", rustix::process::getuid().as_raw())
}

/// The gid this process has outside its user namespace. See [`host_uid`]; the
/// same reasoning applies, and `newgidmap` checks the range against this id.
pub fn host_gid() -> u32 {
    outside_id("/proc/self/gid_map", rustix::process::getgid().as_raw())
}

/// Falls back to the inside id, which is the right answer in the namespace the
/// kernel booted with and the only answer available if `/proc` is unreadable.
fn outside_id(map: &str, inside: u32) -> u32 {
    std::fs::read_to_string(map).ok().and_then(|map| map_outward(&map, inside)).unwrap_or(inside)
}

/// One `inside outside count` row.
fn parse_map_row(line: &str) -> Option<(u32, u32, u32)> {
    let mut fields = line.split_whitespace();
    let inside = fields.next()?.parse().ok()?;
    let outside = fields.next()?.parse().ok()?;
    let count = fields.next()?.parse().ok()?;
    Some((inside, outside, count))
}

/// Translates an id inside this user namespace to the id outside it.
fn map_outward(map: &str, inside: u32) -> Option<u32> {
    map.lines().filter_map(parse_map_row).find_map(|(start, outside, count)| {
        // Not `then_some`: it evaluates its argument whatever the condition,
        // and the addition overflows for an id this row does not cover.
        let offset = inside.checked_sub(start)?;
        if offset >= count {
            return None;
        }
        outside.checked_add(offset)
    })
}

/// `0 0 4294967295`, however the kernel chose to pad it.
fn is_identity_map(map: &str) -> bool {
    let mut fields = map.split_whitespace();
    matches!(
        (fields.next(), fields.next(), fields.next(), fields.next()),
        (Some("0"), Some("0"), Some(count), None) if count == FULL_RANGE.to_string()
    )
}

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

/// One `inside outside count` row of a map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdRange {
    pub start: u32,
    pub count: u32,
}

/// Maps the user's own id to 0 inside, and their subordinate range to the rest.
///
/// An unprivileged process may only map its own id, which would give a
/// container exactly one usable id. The subordinate ranges in `/etc/subuid` are
/// how it gets more, and `newuidmap` is the only sanctioned way to claim them:
/// it is setuid, it checks the request against those files, and it is the
/// reason this shells out rather than writing `/proc/<pid>/uid_map` directly.
pub struct SubUid {
    uid: u32,
    gid: u32,
    uid_ranges: Vec<IdRange>,
    gid_ranges: Vec<IdRange>,
}

impl SubUid {
    pub fn for_current_user() -> Result<Self> {
        let uid = host_uid();
        let gid = host_gid();
        let name = username_for(uid);

        let uid_ranges = read_subids("/etc/subuid", name.as_deref(), uid)?;
        let gid_ranges = read_subids("/etc/subgid", name.as_deref(), gid)?;

        if uid_ranges.is_empty() || gid_ranges.is_empty() {
            return Err(Error::msg(format!(
                "no subordinate id range for {} in /etc/subuid and /etc/subgid, so a container \
                 could only ever have one usable id",
                name.unwrap_or_else(|| uid.to_string())
            )));
        }
        Ok(Self { uid, gid, uid_ranges, gid_ranges })
    }
}

impl IdMapper for SubUid {
    fn write_maps(&self, pid: Pid) -> Result<()> {
        let pid = pid.as_raw_nonzero().get();
        run_map_helper("newuidmap", &map_arguments(pid, self.uid, &self.uid_ranges))?;
        run_map_helper("newgidmap", &map_arguments(pid, self.gid, &self.gid_ranges))
    }
}

/// The argument list for `newuidmap`: the caller's own id becomes 0 inside, and
/// each subordinate range follows it.
fn map_arguments(pid: i32, own: u32, ranges: &[IdRange]) -> Vec<String> {
    let mut args = vec![pid.to_string(), "0".to_string(), own.to_string(), "1".to_string()];

    let mut inside = 1u32;
    for range in ranges {
        args.extend([inside.to_string(), range.start.to_string(), range.count.to_string()]);
        inside += range.count;
    }
    args
}

fn run_map_helper(helper: &str, args: &[String]) -> Result<()> {
    let output = std::process::Command::new(helper)
        .args(args)
        .output()
        .context(|| format!("running {helper}"))?;

    if !output.status.success() {
        return Err(Error::msg(format!(
            "{helper} refused the mapping ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn username_for(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let id: u32 = fields.nth(1)?.parse().ok()?;
        (id == uid).then(|| name.to_string())
    })
}

fn read_subids(path: &str, name: Option<&str>, id: u32) -> Result<Vec<IdRange>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(parse_subids(&contents, name, id)),
        // Not having the file is the same as having no range in it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).context(|| format!("reading {path}")),
    }
}

/// Reads the ranges belonging to a user out of `/etc/subuid` or `/etc/subgid`.
///
/// The first field is a name or a numeric id; both spellings are allowed and
/// both appear in the wild.
fn parse_subids(contents: &str, name: Option<&str>, id: u32) -> Vec<IdRange> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().split(':');
            let owner = fields.next()?;
            let start = fields.next()?.parse().ok()?;
            let count = fields.next()?.parse().ok()?;

            let mine = Some(owner) == name || owner.parse::<u32>() == Ok(id);
            (mine && count > 0).then_some(IdRange { start, count })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_maps_the_whole_range_from_zero() {
        assert_eq!(map_line(0, 0, FULL_RANGE), "0 0 4294967295\n");
    }

    #[test]
    fn the_initial_namespaces_map_is_the_whole_id_space() {
        assert!(is_identity_map("         0          0 4294967295\n"));
        assert!(is_identity_map("0 0 4294967295"));
    }

    #[test]
    fn a_rootless_map_is_not_mistaken_for_the_initial_one() {
        // What podman writes: uid 0 inside is the real user outside, and the
        // rest comes from /etc/subuid. The process is root, over nothing.
        assert!(!is_identity_map("         0       1000          1\n"));
        assert!(!is_identity_map(
            "         0       1000          1\n         1     524288      65536\n"
        ));
        assert!(!is_identity_map(""));
    }

    #[test]
    fn an_id_is_translated_out_through_the_row_that_covers_it() {
        // What podman writes: uid 0 inside is the invoking user outside, and
        // the subuid range follows it.
        let map = "         0       1000          1\n         1     524288      65536\n";
        assert_eq!(map_outward(map, 0), Some(1000));
        assert_eq!(map_outward(map, 1), Some(524_288));
        assert_eq!(map_outward(map, 65_536), Some(589_823));
    }

    #[test]
    fn an_id_outside_every_row_maps_nowhere() {
        let map = "         0       1000          1\n";
        assert_eq!(map_outward(map, 1), None);
        assert_eq!(map_outward(map, 4_294_967_295), None);
    }

    #[test]
    fn the_identity_map_translates_every_id_to_itself() {
        let map = "         0          0 4294967295\n";
        assert_eq!(map_outward(map, 0), Some(0));
        assert_eq!(map_outward(map, 1000), Some(1000));
    }

    #[test]
    fn a_users_subordinate_range_is_found_by_name_or_by_number() {
        let file = "root:0:1000\nnathan:524288:65536\n";
        assert_eq!(
            parse_subids(file, Some("nathan"), 1000),
            [IdRange { start: 524_288, count: 65_536 }]
        );
        assert_eq!(
            parse_subids("1000:524288:65536\n", None, 1000),
            [IdRange { start: 524_288, count: 65_536 }]
        );
    }

    #[test]
    fn another_users_range_is_not_claimed() {
        let file = "someone-else:100000:65536\n";
        assert!(parse_subids(file, Some("nathan"), 1000).is_empty());
    }

    #[test]
    fn malformed_or_empty_rows_are_skipped() {
        let file = "nathan:524288\nnathan:notanumber:5\nnathan:1000:0\nnathan:524288:65536\n";
        assert_eq!(
            parse_subids(file, Some("nathan"), 1000),
            [IdRange { start: 524_288, count: 65_536 }]
        );
    }

    #[test]
    fn the_helper_is_asked_for_zero_then_the_subordinate_range() {
        // 0 inside is the invoking user, so a container's root owns the files
        // that user owns; 1 upwards comes from /etc/subuid.
        let args = map_arguments(42, 1000, &[IdRange { start: 524_288, count: 65_536 }]);
        assert_eq!(args, ["42", "0", "1000", "1", "1", "524288", "65536"]);
    }

    #[test]
    fn several_ranges_are_laid_end_to_end_inside_the_container() {
        let args = map_arguments(
            42,
            1000,
            &[IdRange { start: 100_000, count: 10 }, IdRange { start: 200_000, count: 5 }],
        );
        assert_eq!(args, ["42", "0", "1000", "1", "1", "100000", "10", "11", "200000", "5"]);
    }

    #[test]
    fn a_map_line_is_newline_terminated() {
        assert_eq!(map_line(0, 524288, 65536), "0 524288 65536\n");
    }
}
