//! cgroup v2 scopes and resource limits.
//!
//! The third of the spec's seams. `RootCgroup` owns a subtree of the host's
//! unified hierarchy; phase 6 adds `Delegated`, which resolves the scope
//! systemd already hands to the user session instead.
//!
//! Two structural rules of cgroup v2 shape the layout below, and both surface
//! as a bare ENOENT or EBUSY rather than anything readable:
//!
//! 1. A controller's files only appear in a cgroup if its *parent* enabled the
//!    controller in `cgroup.subtree_control` first.
//! 2. A cgroup with children cannot hold processes of its own.
//!
//! So `quilt/` is a pure parent that enables controllers and holds no tasks,
//! and each container gets a leaf `quilt/<id>` that holds the limits and the
//! workload.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Context, Error, Result};
use crate::spec;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "quilt";

/// The controllers quilt needs enabled on the parent.
const CONTROLLERS: &[&str] = &["cpu", "memory", "pids"];

/// The CPU accounting period, in microseconds. `cpu.max` is a quota over this.
const CPU_PERIOD_US: u64 = 100_000;

/// How long teardown waits for a killed scope to empty before giving up.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const TEARDOWN_POLL: Duration = Duration::from_millis(1);

pub trait CgroupDriver {
    fn scope(&self) -> Result<PathBuf>;
}

/// Scopes under the unified hierarchy. Requires root.
pub struct RootCgroup {
    /// Where the scope sits relative to the cgroup root.
    pub(crate) relative: PathBuf,
}

impl RootCgroup {
    /// quilt's own layout, `quilt/<id>`, for the bespoke CLI.
    pub fn new(id: impl Into<String>) -> Self {
        Self { relative: Path::new(PARENT).join(id.into()) }
    }

    /// The scope an OCI bundle names, or quilt's own when it names none.
    ///
    /// The systemd form of `cgroupsPath` is refused earlier, by
    /// `spec::Config::validate`, so anything arriving here is a plain path.
    pub fn from_config(id: &str, cgroups_path: Option<&str>) -> Result<Self> {
        let Some(path) = cgroups_path else {
            return Ok(Self::new(id));
        };

        let relative = path.trim_start_matches('/');
        if relative.is_empty() {
            return Err(Error::msg(
                "cgroupsPath is the cgroup root, which cannot hold a container".to_string(),
            ));
        }
        if relative.split('/').any(|part| part == "." || part == ".." || part.is_empty()) {
            return Err(Error::msg(format!("cgroupsPath {path:?} is not a plain path")));
        }
        Ok(Self { relative: PathBuf::from(relative) })
    }
}

impl CgroupDriver for RootCgroup {
    fn scope(&self) -> Result<PathBuf> {
        make_scope(Path::new(CGROUP_ROOT), &self.relative)
    }
}

/// Scopes under the subtree systemd delegates to the user's session, for a
/// runtime with no write access to the cgroup root.
pub struct Delegated {
    base: PathBuf,
    relative: PathBuf,
}

impl Delegated {
    pub fn from_config(id: &str, cgroups_path: Option<&str>) -> Result<Self> {
        let own = std::fs::read_to_string("/proc/self/cgroup")
            .context(|| "reading /proc/self/cgroup".to_string())?;
        let uid = crate::idmap::host_uid();

        let base = delegated_root(&own, uid).ok_or_else(|| {
            Error::msg(format!(
                "this process is not inside a user@{uid}.service scope, so systemd has \
                 delegated no cgroup subtree to write in"
            ))
        })?;

        Ok(Self { base, relative: RootCgroup::from_config(id, cgroups_path)?.relative })
    }
}

impl CgroupDriver for Delegated {
    fn scope(&self) -> Result<PathBuf> {
        make_scope(&self.base, &self.relative)
    }
}

/// The point in this process's own cgroup path where systemd stops owning it.
///
/// Read rather than constructed: `user@<uid>.service` is where systemd hands
/// the subtree over, and taking it from `/proc/self/cgroup` means the layout
/// above it can be whatever this machine's systemd decided.
fn delegated_root(own_cgroup: &str, uid: u32) -> Option<PathBuf> {
    // A cgroup v2 line is `0::<path>`; there is only ever one.
    let path = own_cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let boundary = format!("user@{uid}.service");

    let mut base = PathBuf::from(CGROUP_ROOT);
    for component in path.trim().split('/').filter(|c| !c.is_empty()) {
        base.push(component);
        if component == boundary {
            return Some(base);
        }
    }
    None
}

/// Creates the leaf, and everything between `base` and it.
///
/// Every directory on the way has to have the controllers enabled for its
/// children, or the leaf's limit files never appear. That failure is an ENOENT
/// on a write much later, which says nothing about which ancestor caused it.
fn make_scope(base: &Path, relative: &Path) -> Result<PathBuf> {
    let components: Vec<_> = relative.iter().collect();
    let (leaf, ancestors) = components.split_last().expect("from_config rejects an empty path");

    let mut dir = base.to_path_buf();
    enable_controllers(&dir)?;
    for ancestor in ancestors {
        dir = dir.join(ancestor);
        std::fs::create_dir_all(&dir).context(|| format!("creating {}", dir.display()))?;
        enable_controllers(&dir)?;
    }

    // Deliberately not create_dir_all: a directory that is already there is a
    // scope some earlier run left behind, and its limit files are not this
    // container's. Reusing it would silently apply them, because `Limits::files`
    // only writes the limits that were actually asked for.
    let scope = dir.join(leaf);
    match std::fs::create_dir(&scope) {
        Ok(()) => Ok(scope),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::msg(format!(
            "{} already exists; refusing to reuse a scope whose limits are not this container's",
            scope.display()
        ))),
        Err(e) => Err(e).context(|| format!("creating {}", scope.display())),
    }
}

/// The driver for whoever is running: root writes under the cgroup root, and
/// anyone else writes in the subtree systemd delegated to their session.
pub fn driver_for_this_user(id: &str, cgroups_path: Option<&str>) -> Result<Box<dyn CgroupDriver>> {
    if crate::idmap::has_host_privilege() {
        Ok(Box::new(RootCgroup::from_config(id, cgroups_path)?))
    } else {
        Ok(Box::new(Delegated::from_config(id, cgroups_path)?))
    }
}

/// Turns on the controllers quilt writes limits for, so that their files exist
/// in the leaf below. Enabling one that is already on is a no-op.
fn enable_controllers(parent: &Path) -> Result<()> {
    let available = std::fs::read_to_string(parent.join("cgroup.controllers"))
        .context(|| format!("reading {}/cgroup.controllers", parent.display()))?;
    let available: Vec<&str> = available.split_whitespace().collect();

    if let Some(missing) = CONTROLLERS.iter().find(|c| !available.contains(c)) {
        return Err(Error::msg(format!(
            "the {missing} controller is not available in {}; \
             its own parent has not enabled it in cgroup.subtree_control",
            parent.display()
        )));
    }

    // Only the ones that are not on yet. The cgroup root belongs to systemd on
    // this machine, and there is no reason to write to it when the answer is
    // already what quilt wants.
    let enabled = std::fs::read_to_string(parent.join("cgroup.subtree_control"))
        .context(|| format!("reading {}/cgroup.subtree_control", parent.display()))?;
    let missing = missing_controllers(&enabled);
    if missing.is_empty() {
        return Ok(());
    }

    let directive = subtree_control_directive(&missing);
    std::fs::write(parent.join("cgroup.subtree_control"), &directive)
        .context(|| format!("enabling {directive:?} in {}", parent.display()))
}

/// Which of the controllers quilt needs are not yet enabled for children.
fn missing_controllers(enabled: &str) -> Vec<&'static str> {
    let enabled: Vec<&str> = enabled.split_whitespace().collect();
    CONTROLLERS.iter().copied().filter(|c| !enabled.contains(c)).collect()
}

fn subtree_control_directive(controllers: &[&str]) -> String {
    controllers.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ")
}

/// What to write into the scope. `None` leaves the cgroup default, `max`.
///
/// These are the cgroup files themselves rather than a friendlier shape,
/// because two callers translate onto them and they disagree: the bespoke CLI
/// takes `--cpus 0.5`, while an OCI bundle gives a quota and a period. Keeping
/// the translation at the edges leaves one thing to test here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub memory_max: Option<u64>,
    pub memory_swap_max: Option<u64>,
    /// Quota and period, both in microseconds.
    pub cpu_max: Option<(u64, u64)>,
    pub pids_max: Option<u64>,
}

impl Limits {
    /// From the bespoke CLI's flags.
    ///
    /// `--memory` covers swap as well: without that the kernel swaps anonymous
    /// pages out to stay under `memory.max` rather than OOM-killing, and on a
    /// machine with zram the ceiling is not a ceiling. The OCI path keeps the
    /// two apart, because the spec does.
    pub fn from_cli(memory: Option<u64>, cpus: Option<f64>, pids: Option<u64>) -> Result<Self> {
        Ok(Self {
            memory_max: memory,
            memory_swap_max: memory.map(|_| 0),
            cpu_max: cpus.map(quota_for).transpose()?,
            pids_max: pids,
        })
    }

    /// From an OCI bundle's `linux.resources`.
    pub fn from_oci(resources: Option<&spec::Resources>) -> Result<Self> {
        let Some(resources) = resources else {
            return Ok(Self::default());
        };

        let memory = resources.memory.as_ref();
        let memory_max = memory.and_then(|m| m.limit).and_then(positive);

        Ok(Self {
            memory_max,
            // The spec's `swap` is the combined memory+swap ceiling, while the
            // kernel file is swap alone. A negative value means unlimited, which
            // is the default, so nothing is written.
            memory_swap_max: match (memory.and_then(|m| m.swap), memory_max) {
                (Some(total), Some(limit)) if total >= 0 => {
                    Some((total as u64).saturating_sub(limit))
                }
                _ => None,
            },
            cpu_max: match resources.cpu.as_ref() {
                Some(cpu) => cpu.quota.and_then(positive).map(|quota| {
                    (quota, cpu.period.filter(|p| *p > 0).unwrap_or(CPU_PERIOD_US))
                }),
                None => None,
            },
            pids_max: resources.pids.as_ref().map(|p| p.limit).and_then(positive),
        })
    }

    /// The cgroup files to write, in the order they are written.
    fn files(&self) -> Vec<(&'static str, String)> {
        let mut files = Vec::new();
        if let Some(bytes) = self.memory_max {
            files.push(("memory.max", bytes.to_string()));
        }
        if let Some(bytes) = self.memory_swap_max {
            files.push(("memory.swap.max", bytes.to_string()));
        }
        if let Some((quota, period)) = self.cpu_max {
            files.push(("cpu.max", format!("{quota} {period}")));
        }
        if let Some(limit) = self.pids_max {
            files.push(("pids.max", limit.to_string()));
        }
        files
    }
}

/// The OCI spec uses a negative value for "no limit", which is the default.
fn positive(value: i64) -> Option<u64> {
    (value >= 0).then_some(value as u64)
}

/// A scope id unique to this invocation.
///
/// The pid alone is not enough. Pids recycle, and a scope a previous run left
/// behind would then be reused by a run that asked for different limits.
pub fn run_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    format!("run-{}-{nanos}", std::process::id())
}

/// A live cgroup scope. Removing it is the `Drop`, so it happens on the error
/// paths too.
pub struct Scope {
    path: PathBuf,
}

impl Scope {
    pub fn create(driver: &dyn CgroupDriver) -> Result<Self> {
        Ok(Self { path: driver.scope()? })
    }


    pub fn apply(&self, limits: &Limits) -> Result<()> {
        for (file, value) in limits.files() {
            self.write(file, &value)?;
        }
        Ok(())
    }

    /// A descriptor for `clone3`'s `CLONE_INTO_CGROUP`.
    pub fn open(&self) -> Result<OwnedFd> {
        rustix::fs::open(
            &self.path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .context(|| format!("opening {}", self.path.display()))
    }

    /// How many times the kernel OOM-killed something in this scope.
    pub fn oom_kills(&self) -> Result<u64> {
        let events = std::fs::read_to_string(self.path.join("memory.events"))
            .context(|| format!("reading {}/memory.events", self.path.display()))?;
        parse_flat_key(&events, "oom_kill")
            .ok_or_else(|| Error::msg("memory.events has no oom_kill row".to_string()))
    }

    fn write(&self, file: &str, value: &str) -> Result<()> {
        let path = self.path.join(file);
        std::fs::write(&path, value).context(|| format!("writing {value:?} to {}", path.display()))
    }
}

impl Scope {
    /// Kills whatever is left in the scope, waits for it to empty, and removes
    /// the directory.
    ///
    /// `waitpid` returns as soon as pid 1 is reaped, but the kernel kills the
    /// rest of that pid namespace asynchronously and reparents the survivors to
    /// host init. An `rmdir` issued straight after the wait races that teardown
    /// and loses with EBUSY, leaking the scope. `cgroup.kill` (5.14+) plus
    /// `cgroup.events:populated` turns the race into something to wait on.
    fn destroy(&self) -> Result<()> {
        self.write("cgroup.kill", "1")?;
        self.wait_until_empty()?;
        std::fs::remove_dir(&self.path)
            .context(|| format!("removing {}", self.path.display()))
    }

    fn wait_until_empty(&self) -> Result<()> {
        let deadline = Instant::now() + TEARDOWN_TIMEOUT;
        loop {
            let events = std::fs::read_to_string(self.path.join("cgroup.events"))
                .context(|| format!("reading {}/cgroup.events", self.path.display()))?;

            if parse_flat_key(&events, "populated") == Some(0) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::msg(format!(
                    "{} still had processes {TEARDOWN_TIMEOUT:?} after cgroup.kill",
                    self.path.display()
                )));
            }
            std::thread::sleep(TEARDOWN_POLL);
        }
    }
}

impl Scope {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hands back the path and disarms the guard.
    ///
    /// The OCI lifecycle owns a scope across separate processes: `create`
    /// builds it and exits, and only `delete` may take it away.
    pub fn keep(self) -> PathBuf {
        let path = self.path.clone();
        std::mem::forget(self);
        path
    }

    /// Picks up a scope an earlier `create` left behind, so that dropping this
    /// tears it down.
    pub fn adopt(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        // A destructor cannot return an error, but a leaked scope is worth
        // saying out loud rather than discarding.
        if let Err(e) = self.destroy() {
            eprintln!("quilt: {e}");
        }
    }
}

/// `cpu.max` is `<quota> <period>` in microseconds; 0.5 CPUs is half the period.
pub fn quota_for(cpus: f64) -> Result<(u64, u64)> {
    if !cpus.is_finite() || cpus <= 0.0 {
        return Err(Error::msg(format!("--cpus must be greater than zero, got {cpus}")));
    }
    Ok(((cpus * CPU_PERIOD_US as f64).round() as u64, CPU_PERIOD_US))
}

/// Parses a size with an optional binary suffix, as `--memory 64M`.
pub fn parse_size(value: &str) -> Result<u64> {
    let value = value.trim();
    let (digits, multiplier) = match value.chars().last() {
        Some('k' | 'K') => (&value[..value.len() - 1], 1024),
        Some('m' | 'M') => (&value[..value.len() - 1], 1024 * 1024),
        Some('g' | 'G') => (&value[..value.len() - 1], 1024 * 1024 * 1024),
        _ => (value, 1),
    };

    let size: u64 = digits
        .parse()
        .map_err(|_| Error::msg(format!("{value:?} is not a size, e.g. 64M or 1G")))?;
    if size == 0 {
        return Err(Error::msg("a size must be greater than zero".to_string()));
    }
    size.checked_mul(multiplier)
        .ok_or_else(|| Error::msg(format!("size {value:?} overflows")))
}

/// Reads one value out of a flat `key value` cgroup file, as used by
/// `memory.events` and `cgroup.events`.
fn parse_flat_key(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == key).then(|| value.trim().parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cpu_share_becomes_a_quota_over_the_period() {
        assert_eq!(quota_for(0.5).unwrap(), (50_000, 100_000));
        assert_eq!(quota_for(1.0).unwrap(), (100_000, 100_000));
        assert_eq!(quota_for(2.5).unwrap(), (250_000, 100_000));
    }

    #[test]
    fn a_nonsense_cpu_share_is_rejected() {
        assert!(quota_for(0.0).is_err());
        assert!(quota_for(-1.0).is_err());
        assert!(quota_for(f64::NAN).is_err());
    }

    #[test]
    fn sizes_use_binary_suffixes() {
        assert_eq!(parse_size("64M").unwrap(), 67_108_864);
        assert_eq!(parse_size("512k").unwrap(), 524_288);
        assert_eq!(parse_size("1G").unwrap(), 1_073_741_824);
    }

    #[test]
    fn a_bare_number_is_bytes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }

    #[test]
    fn a_bad_size_is_rejected_rather_than_guessed_at() {
        assert!(parse_size("64X").is_err());
        assert!(parse_size("").is_err());
        assert!(parse_size("0").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("18446744073709551615G").is_err());
    }

    #[test]
    fn controllers_are_enabled_with_a_plus_each() {
        assert_eq!(subtree_control_directive(&["cpu", "memory", "pids"]), "+cpu +memory +pids");
    }

    #[test]
    fn oom_kills_are_read_out_of_memory_events() {
        let events = "low 0\nhigh 0\nmax 3\noom 1\noom_kill 2\noom_group_kill 0\n";
        assert_eq!(parse_flat_key(events, "oom_kill"), Some(2));
        assert_eq!(parse_flat_key(events, "max"), Some(3));
    }

    #[test]
    fn a_missing_counter_is_none_rather_than_zero() {
        assert_eq!(parse_flat_key("low 0\nhigh 0\n", "oom_kill"), None);
    }

    #[test]
    fn oom_kill_is_not_confused_with_oom_group_kill() {
        // A prefix match would read the wrong row for either of these.
        let events = "oom_group_kill 7\noom_kill 1\n";
        assert_eq!(parse_flat_key(events, "oom_kill"), Some(1));
        assert_eq!(parse_flat_key(events, "oom_group_kill"), Some(7));
    }

    #[test]
    fn no_limits_writes_nothing() {
        assert!(Limits::default().files().is_empty());
    }

    #[test]
    fn the_cli_memory_flag_also_closes_the_swap_escape() {
        let files = Limits::from_cli(Some(67_108_864), None, None).unwrap().files();
        assert_eq!(
            files,
            [("memory.max", "67108864".to_string()), ("memory.swap.max", "0".to_string())]
        );
    }

    #[test]
    fn every_limit_maps_to_its_own_file() {
        let limits = Limits::from_cli(Some(1024), Some(0.5), Some(32)).unwrap();
        let names: Vec<&str> = limits.files().iter().map(|(f, _)| *f).collect();
        assert_eq!(names, ["memory.max", "memory.swap.max", "cpu.max", "pids.max"]);
    }

    #[test]
    fn nothing_is_written_when_the_controllers_are_already_on() {
        assert!(missing_controllers("cpuset cpu io memory pids").is_empty());
    }

    #[test]
    fn only_the_controllers_that_are_missing_are_enabled() {
        assert_eq!(missing_controllers("cpu"), ["memory", "pids"]);
        assert_eq!(missing_controllers(""), ["cpu", "memory", "pids"]);
    }

    #[test]
    fn a_bundle_without_a_cgroups_path_gets_quilts_own_layout() {
        let driver = RootCgroup::from_config("abc123", None).unwrap();
        assert_eq!(driver.relative, PathBuf::from("quilt/abc123"));
    }

    #[test]
    fn a_bundle_cgroups_path_is_taken_relative_to_the_cgroup_root() {
        let driver =
            RootCgroup::from_config("abc123", Some("/libpod_parent/libpod-abc123")).unwrap();
        assert_eq!(driver.relative, PathBuf::from("libpod_parent/libpod-abc123"));
    }

    #[test]
    fn the_delegated_root_stops_where_systemd_hands_over() {
        let own = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kitty.scope\n";
        assert_eq!(
            delegated_root(own, 1000).unwrap(),
            PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"
            )
        );
    }

    #[test]
    fn a_process_outside_a_user_service_has_nothing_delegated_to_it() {
        // A system service, or a session that systemd is not managing. Saying
        // so beats writing into a subtree that belongs to something else.
        assert_eq!(delegated_root("0::/system.slice/sshd.service\n", 1000), None);
        assert_eq!(delegated_root("", 1000), None);
    }

    #[test]
    fn the_boundary_is_this_users_service_and_not_another() {
        let own = "0::/user.slice/user-1001.slice/user@1001.service/app.slice\n";
        assert_eq!(delegated_root(own, 1000), None);
    }

    #[test]
    fn a_cgroups_path_that_climbs_out_is_refused() {
        assert!(RootCgroup::from_config("abc", Some("/../../escape")).is_err());
        assert!(RootCgroup::from_config("abc", Some("/")).is_err());
    }

    #[test]
    fn cgroup_events_is_read_by_the_same_parser() {
        assert_eq!(parse_flat_key("populated 1\nfrozen 0\n", "populated"), Some(1));
        assert_eq!(parse_flat_key("populated 0\nfrozen 0\n", "populated"), Some(0));
    }

    #[test]
    fn a_run_id_is_not_just_the_pid() {
        // Two runs a moment apart must not land on the same scope, or the
        // second inherits the first's limit files.
        let (first, second) = (run_id(), run_id());
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("run-{}-", std::process::id())));
    }

    #[test]
    fn a_bad_cpu_share_fails_before_anything_is_written() {
        assert!(Limits::from_cli(None, Some(0.0), None).is_err());
    }

    #[test]
    fn a_bundle_without_resources_asks_for_nothing() {
        assert_eq!(Limits::from_oci(None).unwrap(), Limits::default());
    }

    #[test]
    fn a_bundle_pids_limit_is_honoured() {
        let resources = spec::Resources {
            pids: Some(spec::Pids { limit: 2048 }),
            ..spec::Resources::default()
        };
        assert_eq!(Limits::from_oci(Some(&resources)).unwrap().pids_max, Some(2048));
    }

    #[test]
    fn a_negative_bundle_limit_means_unlimited_and_writes_nothing() {
        // The OCI spec spells "no limit" as a negative number; writing it
        // through would put a nonsense value in the cgroup file.
        let resources = spec::Resources {
            pids: Some(spec::Pids { limit: -1 }),
            ..spec::Resources::default()
        };
        assert_eq!(Limits::from_oci(Some(&resources)).unwrap().pids_max, None);
    }

    #[test]
    fn the_bundles_swap_field_is_the_combined_ceiling_not_the_swap_one() {
        // linux.resources.memory.swap is memory+swap; memory.swap.max is swap
        // alone, so the difference is what the kernel wants.
        let resources = spec::Resources {
            memory: Some(spec::Memory {
                limit: Some(64 * 1024 * 1024),
                swap: Some(96 * 1024 * 1024),
                ..Default::default()
            }),
            ..spec::Resources::default()
        };
        let limits = Limits::from_oci(Some(&resources)).unwrap();
        assert_eq!(limits.memory_max, Some(67_108_864));
        assert_eq!(limits.memory_swap_max, Some(33_554_432));
    }

    #[test]
    fn a_bundle_memory_limit_without_swap_leaves_swap_alone() {
        // Unlike the CLI flag: the spec says nothing about swap here, and
        // inventing a zero would be a limit the caller never asked for.
        let resources = spec::Resources {
            memory: Some(spec::Memory { limit: Some(1024), ..Default::default() }),
            ..spec::Resources::default()
        };
        let limits = Limits::from_oci(Some(&resources)).unwrap();
        assert_eq!(limits.memory_max, Some(1024));
        assert_eq!(limits.memory_swap_max, None);
    }

    #[test]
    fn a_bundle_cpu_quota_keeps_its_own_period() {
        let resources = spec::Resources {
            cpu: Some(spec::Cpu { quota: Some(25_000), period: Some(50_000), ..Default::default() }),
            ..spec::Resources::default()
        };
        assert_eq!(Limits::from_oci(Some(&resources)).unwrap().cpu_max, Some((25_000, 50_000)));
    }
}
