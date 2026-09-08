//! Orchestration for one container: clone, map ids, hand off to init, wait.
//!
//! `create` and `start` are separate verbs in the OCI spec, so phase 4 splits
//! this and adds an exec fifo plus state on disk. Phase 1 only needs `run`,
//! which is the two of them back to back.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use rustix::process::{Pid, Signal, WaitOptions};

use crate::cgroup::{CgroupDriver, Limits, Scope};
use crate::error::{Context, Error, Result};
use crate::idmap::IdMapper;
use crate::mount::BindSpec;
use crate::net::veth;
use crate::ns::{self, CloneArgs, Fork, Namespaces};

pub struct RunSpec {
    /// Absolute and canonical.
    pub rootfs: PathBuf,
    pub hostname: String,
    pub readonly_binds: Vec<BindSpec>,
    /// The workload and its arguments.
    pub argv: Vec<String>,
    pub limits: Limits,
    /// `None` is `--net none`: a network namespace with only loopback in it.
    pub network: Option<Connectivity>,
}

/// How the container reaches the outside, if it does.
pub enum Connectivity {
    /// Privileged: a veth onto quilt's bridge, configured by init.
    Bridge(veth::Plan),
    /// Unprivileged: pasta configures the namespace from outside, so init has
    /// nothing to do.
    Pasta,
}

/// Exit code used when the init process could not be reached or execed. 127 is
/// what a shell reports for "command not found", which is the closest analogue.
const EXIT_INIT_FAILED: i32 = 127;
const EXIT_EXEC_FAILED: i32 = 126;

pub fn run(
    spec: &RunSpec,
    mapper: &dyn IdMapper,
    driver: &dyn CgroupDriver,
    namespaces: Namespaces,
) -> Result<i32> {
    // The scope exists before the workload does, and `Scope`'s `Drop` removes
    // it on every path out of this function, including the error ones.
    //
    // The clone below copies this guard into the child, but every path the
    // child takes ends in `execve` or `exit_group`, neither of which unwinds,
    // so the child never runs the destructor and never deletes the scope.
    let scope = Scope::create(driver)?;
    scope.apply(&spec.limits)?;
    let scope_fd = scope.open()?;

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

    let args = CloneArgs::new(namespaces.clone_flags()).into_cgroup(scope_fd.as_fd());

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

            // The host side needs the child's pid to name its netns, so it can
            // only happen now, and it must finish before the child is released:
            // init configures the container end and the veth has to be there.
            // `HostLink` deletes the pair on the way out of this scope.
            let _link = match &spec.network {
                Some(Connectivity::Bridge(plan)) => match veth::connect(plan, child) {
                    Ok(link) => Some(link),
                    Err(e) => {
                        kill_and_reap(child);
                        return Err(e);
                    }
                },
                Some(Connectivity::Pasta) => {
                    if let Err(e) = crate::net::pasta::connect(child) {
                        kill_and_reap(child);
                        return Err(e);
                    }
                    None
                }
                None => None,
            };
            if let Err(e) = rustix::io::write(&map_done, &[1u8])
                .context(|| "releasing the init process".to_string())
            {
                kill_and_reap(child);
                return Err(e);
            }
            drop(map_done);

            let code = wait_for_exit(child)?;
            report_oom_kills(&scope, &spec.limits);
            Ok(code)
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
    // Only the bridge needs init to do anything: pasta has already given the
    // namespace an address and a route by the time init is released.
    if let Some(Connectivity::Bridge(plan)) = &spec.network {
        argv.push("--net-address".to_string());
        argv.push(format!("{}/{}", plan.endpoint.address, plan.endpoint.prefix_len));
        argv.push("--net-gateway".to_string());
        argv.push(plan.endpoint.gateway.to_string());
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

/// Says so when the kernel OOM-killed something in the scope, which otherwise
/// reaches the caller only as an unexplained 137.
///
/// Read before the scope is removed, and only when a memory limit was set —
/// without the memory controller there is no `memory.events` to read.
fn report_oom_kills(scope: &Scope, limits: &Limits) {
    if limits.memory_max.is_none() {
        return;
    }
    match scope.oom_kills() {
        Ok(0) => {}
        Ok(kills) => eprintln!("quilt: memory limit exceeded, memory.events oom_kill={kills}"),
        Err(e) => eprintln!("quilt: could not read memory.events: {e}"),
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
            limits: Limits::default(),
            network: None,
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
    fn init_argv_carries_the_network_plan_when_there_is_one() {
        let mut spec = spec();
        spec.network = Some(Connectivity::Bridge(veth::Plan::new(7)));
        let argv = init_argv(&spec);

        let address = argv.iter().position(|a| a == "--net-address").unwrap();
        assert_eq!(argv[address + 1], "10.88.0.9/16");
        assert!(argv.windows(2).any(|w| w == ["--net-gateway", "10.88.0.1"]));
    }

    #[test]
    fn init_argv_says_nothing_about_the_network_when_there_is_none() {
        let argv = init_argv(&spec());
        assert!(!argv.iter().any(|a| a.starts_with("--net")));
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
    fn a_start_time_survives_a_command_name_with_spaces_and_brackets() {
        // Field 2 is unescaped, so splitting from the left lands in the middle
        // of the name. Everything after the last ')' is the only safe anchor.
        let stat = "42 (my (odd) name) S 1 42 42 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0                     987654 12345 0 0 0";
        assert_eq!(parse_start_time(stat), Some(987_654));
    }

    #[test]
    fn a_start_time_is_read_from_an_ordinary_stat_line() {
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 200 0 0 0 5 6 0 0 20 0 1 0                     17 22 0 0 0";
        assert_eq!(parse_start_time(stat), Some(17));
    }

    #[test]
    fn a_malformed_stat_line_yields_nothing_rather_than_a_wrong_pid_identity() {
        assert_eq!(parse_start_time(""), None);
        assert_eq!(parse_start_time("42 (sh) S 1 2 3"), None);
    }

    #[test]
    fn signal_names_are_accepted_in_every_form_the_spec_allows() {
        assert_eq!(parse_signal("KILL").unwrap(), Signal::KILL);
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::KILL);
        assert_eq!(parse_signal("9").unwrap(), Signal::KILL);
        assert_eq!(parse_signal("sigterm").unwrap(), Signal::TERM);
        assert_eq!(parse_signal("15").unwrap(), Signal::TERM);
    }

    #[test]
    fn an_unknown_signal_is_refused() {
        assert!(parse_signal("SIGNOTHING").is_err());
        assert!(parse_signal("0").is_err());
        assert!(parse_signal("9999").is_err());
    }

    #[test]
    fn a_container_id_cannot_climb_out_of_the_state_root() {
        let root = Path::new("/run/quilt");
        assert!(state_dir(root, "../../etc").is_err());
        assert!(state_dir(root, "..").is_err());
        assert!(state_dir(root, "").is_err());
        assert_eq!(state_dir(root, "abc123").unwrap(), Path::new("/run/quilt/abc123"));
    }

    #[test]
    fn a_dead_container_reports_stopped_whatever_was_written_down() {
        let state = SavedState {
            oci_version: "1.2.1".into(),
            id: "abc".into(),
            status: Status::Running,
            // Pid 1 is alive, but not with this start time, so this stands in
            // for a pid that has been reused since.
            pid: 1,
            pid_start_time: u64::MAX,
            bundle: PathBuf::from("/bundle"),
            cgroup_scope: PathBuf::from("/sys/fs/cgroup/quilt/abc"),
            annotations: BTreeMap::new(),
        };
        assert_eq!(current_status(&state), Status::Stopped);
    }

    #[test]
    fn container_env_sets_a_path_and_the_hostname() {
        let env = container_env(&spec());
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
        assert!(env.contains(&"HOSTNAME=quilt".to_string()));
    }
}

// ---------------------------------------------------------------------------
// The OCI lifecycle.
//
// `create` and `start` are separate verbs, so something has to exist between
// them holding the namespaces open with the workload not yet running. That is
// the init process, parked on an exec fifo. Unlike `run` above, the three verbs
// are three separate processes, so everything they share lives on disk.
// ---------------------------------------------------------------------------

/// Where the runtime keeps per-container state.
///
/// `/run` belongs to root, so an unprivileged runtime uses the per-user runtime
/// directory instead. Deliberately not `XDG_RUNTIME_DIR`: `create`, `start` and
/// `delete` are three separate processes and the caller does not have to give
/// them the same environment, so a state root read out of one would be a state
/// root they could disagree about.
pub fn default_state_root() -> PathBuf {
    if crate::idmap::has_host_privilege() {
        PathBuf::from("/run/quilt")
    } else {
        PathBuf::from(format!("/run/user/{}/quilt", crate::idmap::host_uid()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
}

/// What quilt records between verbs.
///
/// A superset of the state the OCI spec defines, because a runtime needs
/// bookkeeping the caller has no business seeing. [`print_state`] prints only
/// the standard fields.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedState {
    oci_version: String,
    id: String,
    status: Status,
    pid: i32,
    /// The init process's start time, from `/proc/<pid>/stat`.
    ///
    /// A pid on its own is not an identity: pids are reused, and a verb that
    /// arrives after the container died could otherwise signal an unrelated
    /// process that inherited the number.
    pid_start_time: u64,
    bundle: PathBuf,
    cgroup_scope: PathBuf,
    annotations: BTreeMap<String, String>,
}

/// The `state` verb's output, exactly as the runtime spec defines it.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OciState<'a> {
    oci_version: &'a str,
    id: &'a str,
    status: Status,
    pid: i32,
    bundle: &'a Path,
    annotations: &'a BTreeMap<String, String>,
}

/// Removes a half-built container's state directory unless it is kept.
struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// Fails if the id is already in use, which is what the spec requires.
    fn create(path: PathBuf) -> Result<Self> {
        match std::fs::create_dir_all(&path) {
            Ok(()) if is_empty_dir(&path) => Ok(Self { path }),
            Ok(()) => Err(Error::msg(format!(
                "a container is already registered at {}",
                path.display()
            ))),
            Err(e) => Err(e).context(|| format!("creating {}", path.display())),
        }
    }

    fn keep(self) -> PathBuf {
        let path = self.path.clone();
        std::mem::forget(self);
        path
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn is_empty_dir(path: &Path) -> bool {
    std::fs::read_dir(path).map(|mut entries| entries.next().is_none()).unwrap_or(false)
}

fn state_dir(root: &Path, id: &str) -> Result<PathBuf> {
    // The id lands in a path, so it must not be able to climb out of the root.
    if id.is_empty() || id.contains('/') || id == "." || id == ".." {
        return Err(Error::msg(format!("{id:?} is not a usable container id")));
    }
    Ok(root.join(id))
}

fn load(root: &Path, id: &str) -> Result<SavedState> {
    let path = state_dir(root, id)?.join("state.json");
    let json = std::fs::read_to_string(&path)
        .map_err(|_| Error::msg(format!("no container named {id}")))?;
    serde_json::from_str(&json)
        .map_err(|e| Error::msg(format!("{} is not readable state: {e}", path.display())))
}

fn save(root: &Path, state: &SavedState) -> Result<()> {
    let path = state_dir(root, &state.id)?.join("state.json");
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| Error::msg(format!("could not render state: {e}")))?;
    std::fs::write(&path, json).context(|| format!("writing {}", path.display()))
}

/// Field 22 of `/proc/<pid>/stat`, the process's start time in clock ticks.
///
/// The command name is field 2 and is wrapped in parentheses but is otherwise
/// unescaped, so it can contain spaces and its own parentheses. Splitting on
/// whitespace from the left is the classic way to get this wrong; everything
/// after the last `)` is the only safe place to start counting.
fn parse_start_time(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields resume at 3, so the start time is the 20th from here.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn start_time_of(pid: i32) -> Option<u64> {
    parse_start_time(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Whether the recorded process is still the one this container started.
fn is_alive(state: &SavedState) -> bool {
    start_time_of(state.pid) == Some(state.pid_start_time)
}

/// The status as it is now, rather than as it was last written.
fn current_status(state: &SavedState) -> Status {
    match state.status {
        Status::Created | Status::Running if !is_alive(state) => Status::Stopped,
        other => other,
    }
}

/// `create`: build the container and leave it waiting on the exec fifo.
pub fn create(
    root: &Path,
    id: &str,
    bundle: &Path,
    pid_file: Option<&Path>,
    seccomp_log: bool,
) -> Result<()> {
    let bundle = bundle
        .canonicalize()
        .context(|| format!("resolving the bundle at {}", bundle.display()))?;
    let config_path = bundle.join("config.json");
    let json = std::fs::read_to_string(&config_path)
        .context(|| format!("reading {}", config_path.display()))?;

    let config = crate::spec::Config::parse(&json)?;
    config.validate()?;

    // Anything that can be decided from the bundle alone is decided now.
    //
    // The rest of the setup happens in the init process, and init reports it
    // survived *before* it parks on the exec fifo — so a policy quilt cannot
    // carry out would otherwise not be discovered until `start`, long after
    // `create` told the caller the container exists. A seccomp profile using an
    // action quilt cannot assemble is the case that shows it: the container
    // would be created, started, and only then refuse to run.
    if let Some(profile) = &config.linux.seccomp {
        crate::seccomp::compile(profile)?;
    }
    if let Some(capabilities) = &config.process.capabilities {
        crate::caps::validate(capabilities)?;
    }
    crate::init::validate_rlimits(&config.process.rlimits)?;

    let namespaces = Namespaces::to_create(&config.linux.namespaces)?;
    if namespaces.user {
        return Err(Error::msg(
            "config.json asks quilt to create a user namespace, which is phase 6".to_string(),
        ));
    }

    let dir = StateDir::create(state_dir(root, id)?)?;
    let fifo = dir.path.join("exec.fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
        0,
    )
    .context(|| format!("creating the exec fifo at {}", fifo.display()))?;

    let driver = crate::cgroup::driver_for_this_user(id, config.linux.cgroups_path.as_deref())?;
    let scope = Scope::create(driver.as_ref())?;
    scope.apply(&Limits::from_oci(config.linux.resources.as_ref())?)?;
    let scope_fd = scope.open()?;

    // Not CLOEXEC: init inherits this and reports on it, which is the only way
    // `create` can fail for a setup problem that happens after the clone.
    let (ready_read, ready_write) =
        rustix::pipe::pipe().context(|| "creating the readiness pipe".to_string())?;
    let ready_number = ready_write.as_raw_fd();

    let exe = CString::new("/proc/self/exe").expect("no interior NUL");
    let mut init_argv = vec![
        "quilt".to_string(),
        "init-oci".to_string(),
        "--bundle".to_string(),
        bundle.display().to_string(),
        "--fifo".to_string(),
        fifo.display().to_string(),
        "--ready-fd".to_string(),
        ready_number.to_string(),
    ];
    if seccomp_log {
        init_argv.push("--seccomp-log".to_string());
    }
    let argv = cstrings(&init_argv)?;
    let envp = cstrings(&[])?;
    let argv_ptrs = pointer_array(&argv);
    let envp_ptrs = pointer_array(&envp);

    let args = CloneArgs::new(namespaces.clone_flags()).into_cgroup(scope_fd.as_fd());

    // SAFETY: as in `run` — fork semantics, and the child does nothing but
    // close descriptors and `execve`.
    match unsafe { ns::clone3(&args) }? {
        Fork::Child => {
            drop(ready_read);
            // Everything except stdio and the readiness pipe. Sweeping around
            // it rather than duplicating it keeps this to two syscalls.
            if sweep_except(ready_number).is_err() {
                rustix::runtime::exit_group(EXIT_INIT_FAILED);
            }
            let _ =
                unsafe { rustix::runtime::execve(&exe, argv_ptrs.as_ptr(), envp_ptrs.as_ptr()) };
            rustix::runtime::exit_group(EXIT_EXEC_FAILED);
        }

        Fork::Parent(child) => {
            drop(ready_write);

            if !wait_for_maps(&ready_read) {
                // init already said what went wrong on stderr, which the caller
                // is capturing; repeating a guess here would only obscure it.
                kill_and_reap(child);
                return Err(Error::msg(format!("container {id} failed to start")));
            }

            let pid = child.as_raw_nonzero().get();
            let state = SavedState {
                oci_version: config.oci_version.clone(),
                id: id.to_string(),
                status: Status::Created,
                pid,
                pid_start_time: start_time_of(pid).ok_or_else(|| {
                    Error::msg("the init process disappeared during create".to_string())
                })?,
                bundle: bundle.clone(),
                cgroup_scope: scope.path().to_path_buf(),
                annotations: config.annotations.clone(),
            };
            save(root, &state)?;

            if let Some(path) = pid_file {
                std::fs::write(path, pid.to_string())
                    .context(|| format!("writing the pid file {}", path.display()))?;
            }

            // Both now belong to the container, until `delete`.
            let _ = scope.keep();
            let _ = dir.keep();
            Ok(())
        }
    }
}

/// Closes every descriptor above stdio except one.
fn sweep_except(keep: RawFd) -> std::result::Result<(), rustix::io::Errno> {
    // SAFETY: as in `run` — immediately before `execve`, and nothing below uses
    // a descriptor other than `keep`.
    if keep > 3 {
        unsafe { crate::syscall::close_range(3, keep as u32 - 1, 0) }?;
    }
    unsafe { crate::syscall::close_range(keep as u32 + 1, u32::MAX, 0) }
}

/// `start`: let the waiting init process go on to `execve`.
pub fn start(root: &Path, id: &str) -> Result<()> {
    let mut state = load(root, id)?;
    match current_status(&state) {
        Status::Created => {}
        other => {
            return Err(Error::msg(format!("container {id} is {other:?}, not created")));
        }
    }

    let fifo = state_dir(root, id)?.join("exec.fifo");
    // Opening for writing is what unblocks init's read. Nothing about the byte
    // matters, only that the open pairs up.
    let writer = rustix::fs::open(
        &fifo,
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context(|| format!("opening {}", fifo.display()))?;
    rustix::io::write(&writer, &[1u8]).context(|| "releasing the container".to_string())?;
    drop(writer);

    state.status = Status::Running;
    save(root, &state)
}

/// `state`: the container's state, as JSON on stdout.
pub fn print_state(root: &Path, id: &str) -> Result<String> {
    let state = load(root, id)?;
    let status = current_status(&state);

    serde_json::to_string_pretty(&OciState {
        oci_version: &state.oci_version,
        id: &state.id,
        status,
        pid: state.pid,
        bundle: &state.bundle,
        annotations: &state.annotations,
    })
    .map_err(|e| Error::msg(format!("could not render state: {e}")))
}

/// `kill`: send a signal to the container process.
pub fn kill(root: &Path, id: &str, signal: &str) -> Result<()> {
    let state = load(root, id)?;
    if !is_alive(&state) {
        return Err(Error::msg(format!("container {id} is not running")));
    }

    let signal = parse_signal(signal)?;
    let pid = Pid::from_raw(state.pid)
        .ok_or_else(|| Error::msg(format!("container {id} has no valid pid")))?;
    rustix::process::kill_process(pid, signal)
        .context(|| format!("signalling container {id}"))
}

/// `delete`: take the container's state and cgroup away.
pub fn delete(root: &Path, id: &str, force: bool) -> Result<()> {
    let state = load(root, id)?;

    if is_alive(&state) {
        if !force {
            return Err(Error::msg(format!(
                "container {id} is still running; use --force to kill it first"
            )));
        }
        if let Some(pid) = Pid::from_raw(state.pid) {
            let _ = rustix::process::kill_process(pid, Signal::KILL);
        }
    }

    // Dropping the scope kills whatever is left in it and waits for the cgroup
    // to empty, so this covers the container's other processes too.
    drop(Scope::adopt(state.cgroup_scope.clone()));

    let dir = state_dir(root, id)?;
    std::fs::remove_dir_all(&dir).context(|| format!("removing {}", dir.display()))
}

/// Signal names as the OCI spec's `kill` verb accepts them: `KILL`, `SIGKILL`
/// or `9` all mean the same thing.
fn parse_signal(name: &str) -> Result<Signal> {
    if let Ok(number) = name.parse::<i32>() {
        return signal_from_number(number)
            .ok_or_else(|| Error::msg(format!("{number} is not a signal")));
    }

    // Upper-case before stripping, or a lower-case "sigterm" keeps its prefix
    // and matches nothing.
    let upper = name.to_ascii_uppercase();
    let number = match upper.strip_prefix("SIG").unwrap_or(&upper) {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "ABRT" => 6,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        _ => return Err(Error::msg(format!("{name:?} is not a signal quilt knows"))),
    };
    signal_from_number(number).ok_or_else(|| Error::msg(format!("{name:?} is not a signal")))
}

fn signal_from_number(number: i32) -> Option<Signal> {
    Signal::from_named_raw_nonzero(std::num::NonZeroI32::new(number)?)
}
