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

/// Scopes under `/sys/fs/cgroup/quilt/<id>`. Requires root.
pub struct RootCgroup {
    id: String,
}

impl RootCgroup {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl CgroupDriver for RootCgroup {
    fn scope(&self) -> Result<PathBuf> {
        let parent = Path::new(CGROUP_ROOT).join(PARENT);
        std::fs::create_dir_all(&parent)
            .context(|| format!("creating {}", parent.display()))?;
        enable_controllers(&parent)?;

        // Deliberately not create_dir_all: a directory that is already there is
        // a scope some earlier run left behind, and its limit files are not
        // this container's. Reusing it would silently apply them, because
        // `Limits::files` only writes the limits that were actually asked for.
        let scope = parent.join(&self.id);
        match std::fs::create_dir(&scope) {
            Ok(()) => Ok(scope),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::msg(format!(
                "{} already exists; refusing to reuse a scope whose limits are not this \
                 container's",
                scope.display()
            ))),
            Err(e) => Err(e).context(|| format!("creating {}", scope.display())),
        }
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

    let directive = subtree_control_directive(CONTROLLERS);
    std::fs::write(parent.join("cgroup.subtree_control"), &directive)
        .context(|| format!("enabling {directive:?} in {}", parent.display()))
}

fn subtree_control_directive(controllers: &[&str]) -> String {
    controllers.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" ")
}

/// What the caller asked for. `None` means the cgroup default, which is `max`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Limits {
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
}

impl Limits {
    /// The cgroup files to write, in the order they are written.
    fn files(&self) -> Result<Vec<(&'static str, String)>> {
        let mut files = Vec::new();

        if let Some(bytes) = self.memory {
            files.push(("memory.max", bytes.to_string()));
            // Without this the ceiling is escapable. Under pressure the kernel
            // swaps anonymous pages out to stay under memory.max rather than
            // OOM-killing, so `--memory` here means memory *and* swap. The OCI
            // spec has a separate field for the two, which phase 4 honours.
            files.push(("memory.swap.max", "0".to_string()));
        }
        if let Some(cpus) = self.cpus {
            files.push(("cpu.max", cpu_max(cpus)?));
        }
        if let Some(pids) = self.pids {
            files.push(("pids.max", pids.to_string()));
        }
        Ok(files)
    }
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
        for (file, value) in limits.files()? {
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
pub fn cpu_max(cpus: f64) -> Result<String> {
    if !cpus.is_finite() || cpus <= 0.0 {
        return Err(Error::msg(format!("--cpus must be greater than zero, got {cpus}")));
    }
    let quota = (cpus * CPU_PERIOD_US as f64).round() as u64;
    Ok(format!("{quota} {CPU_PERIOD_US}"))
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
        assert_eq!(cpu_max(0.5).unwrap(), "50000 100000");
        assert_eq!(cpu_max(1.0).unwrap(), "100000 100000");
        assert_eq!(cpu_max(2.5).unwrap(), "250000 100000");
    }

    #[test]
    fn a_nonsense_cpu_share_is_rejected() {
        assert!(cpu_max(0.0).is_err());
        assert!(cpu_max(-1.0).is_err());
        assert!(cpu_max(f64::NAN).is_err());
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
        assert!(Limits::default().files().unwrap().is_empty());
    }

    #[test]
    fn a_memory_limit_also_closes_the_swap_escape() {
        let files = Limits { memory: Some(67_108_864), ..Limits::default() }.files().unwrap();
        assert_eq!(
            files,
            [("memory.max", "67108864".to_string()), ("memory.swap.max", "0".to_string())]
        );
    }

    #[test]
    fn every_limit_maps_to_its_own_file() {
        let limits = Limits { memory: Some(1024), cpus: Some(0.5), pids: Some(32) };
        let names: Vec<&str> = limits.files().unwrap().iter().map(|(f, _)| *f).collect();
        assert_eq!(names, ["memory.max", "memory.swap.max", "cpu.max", "pids.max"]);
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
        assert!(Limits { cpus: Some(0.0), ..Limits::default() }.files().is_err());
    }
}
