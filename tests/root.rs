//! Root-only acceptance, asserted on observable behaviour.
//!
//! Gated behind `QUILT_TEST_ROOT=1` so a plain `cargo test` stays safe. Run
//! them with `scripts/root-tests.sh`, which builds as you and runs as root.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Skips the test unless it was asked for explicitly.
macro_rules! requires_root {
    () => {
        if std::env::var("QUILT_TEST_ROOT").as_deref() != Ok("1") {
            eprintln!("skipped: set QUILT_TEST_ROOT=1 (see scripts/root-tests.sh)");
            return;
        }
    };
}

fn rootfs() -> PathBuf {
    match std::env::var("QUILT_TEST_ROOTFS") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rootfs"),
    }
}

fn quilt(flags: &[&str], script: &str) -> Output {
    let mut args: Vec<String> = vec!["run".into()];
    args.extend(flags.iter().map(|f| f.to_string()));
    args.push(rootfs().display().to_string());
    args.extend(["/bin/sh".to_string(), "-c".to_string(), script.to_string()]);

    Command::new(env!("CARGO_BIN_EXE_quilt")).args(&args).output().expect("failed to spawn quilt")
}

/// Runs `script` inside a container and returns its stdout, failing loudly if
/// the container did not exit cleanly.
fn inside(script: &str) -> String {
    inside_with(&[], script)
}

fn inside_with(flags: &[&str], script: &str) -> String {
    let out = quilt(flags, script);
    assert!(
        out.status.success(),
        "container failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every scope directory quilt currently owns.
fn scopes() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/sys/fs/cgroup/quilt") else {
        return Vec::new();
    };
    entries.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect()
}

/// Scopes made by `quilt run`, which names them `run-<pid>-<nanos>`.
///
/// Those tests assert they leave none behind; asserting on the whole `quilt/`
/// subtree would fail them for an OCI container mid-test instead.
fn run_scopes() -> Vec<PathBuf> {
    scopes()
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|n| n.to_string_lossy().starts_with("run-")))
        .collect()
}

fn scope_of(id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/quilt").join(id)
}

/// Clears anything an earlier interrupted run left under this container's name.
fn clear_container(state_root: &Path, id: &str) {
    std::fs::remove_dir_all(state_root.join(id)).ok();

    let scope = scope_of(id);
    if scope.exists() {
        std::fs::write(scope.join("cgroup.kill"), "1").ok();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::fs::remove_dir(&scope).is_err() && deadline > std::time::Instant::now() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

fn read_trim(path: PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_default().trim().to_string()
}

/// Spawns a container that touches a marker on the rootfs and then sleeps, so
/// the host can inspect it while it runs. The rootfs is a host directory, so
/// the marker appearing means setup finished and the workload is live.
fn spawn_running(flags: &[&str], name: &str) -> (std::process::Child, PathBuf) {
    let marker = rootfs().join(name);
    std::fs::remove_file(&marker).ok();

    let mut args: Vec<String> = vec!["run".into()];
    args.extend(flags.iter().map(|f| f.to_string()));
    args.push(rootfs().display().to_string());
    args.extend(["/bin/sh".to_string(), "-c".to_string(), format!("touch /{name}; sleep 3")]);

    let child = Command::new(env!("CARGO_BIN_EXE_quilt"))
        .args(&args)
        .spawn()
        .expect("failed to spawn quilt");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !marker.exists() && deadline > std::time::Instant::now() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    (child, marker)
}

/// Every interface on the host, by name.
fn host_links() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

fn host_reaches_the_internet() -> bool {
    Command::new("ping")
        .args(["-c", "1", "-W", "3", "1.1.1.1"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn host_mount_points() -> BTreeSet<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .expect("reading host mountinfo")
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4).map(str::to_string))
        .collect()
}

#[test]
fn the_workload_is_pid_one() {
    requires_root!();
    assert_eq!(inside("echo $$").trim(), "1");
}

#[test]
fn ps_sees_only_the_containers_own_processes() {
    requires_root!();
    let pids: Vec<i32> =
        inside("ps -o pid=").lines().filter_map(|line| line.trim().parse().ok()).collect();

    assert!(pids.contains(&1), "no pid 1 in {pids:?}");
    assert!(pids.len() <= 4, "the host's processes are visible: {pids:?}");
}

#[test]
fn the_network_namespace_holds_only_loopback() {
    requires_root!();
    // /proc/net/dev opens with two header lines, then one line per interface.
    let interfaces: Vec<String> = inside("cat /proc/net/dev")
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next().map(|n| n.trim().to_string()))
        .filter(|name| !name.is_empty())
        .collect();

    assert_eq!(interfaces, ["lo"], "expected only loopback");
}

#[test]
fn the_hostname_is_the_containers_own() {
    requires_root!();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let inside = inside_with(&["--hostname", "quilt-test"], "hostname");

    assert_eq!(inside.trim(), "quilt-test");
    assert_ne!(inside.trim(), host.trim());
}

#[test]
fn the_mount_table_is_the_containers_own() {
    requires_root!();
    let mountinfo = inside("cat /proc/self/mountinfo");
    let points: BTreeSet<&str> =
        mountinfo.lines().filter_map(|line| line.split_whitespace().nth(4)).collect();

    for expected in ["/", "/proc", "/sys", "/dev", "/dev/shm"] {
        assert!(points.contains(expected), "no {expected} in {points:?}");
    }
    assert!(
        !mountinfo.contains(&rootfs().display().to_string()),
        "the host path to the rootfs is still visible after pivot_root"
    );
}

#[test]
fn nothing_mounted_inside_reaches_the_host() {
    requires_root!();
    let before = host_mount_points();
    inside("mount -t tmpfs none /mnt && ls /");
    let after = host_mount_points();

    assert_eq!(before, after, "the container's mounts propagated to the host");
    assert!(
        !after.iter().any(|p| p.starts_with(&rootfs().display().to_string())),
        "a mount under the rootfs survived the container"
    );
}

#[test]
fn quilts_own_setup_mounts_are_invisible_to_the_host_while_the_container_runs() {
    requires_root!();
    // The check above would miss a mount that exists for the container's
    // lifetime and is torn down on exit. This one looks while it is up.
    let (mut child, marker) = spawn_running(&[], "quilt-running");
    let started = marker.exists();

    let prefix = rootfs().display().to_string();
    let leaked: Vec<String> =
        host_mount_points().into_iter().filter(|p| p.starts_with(&prefix)).collect();

    child.wait().expect("waiting for quilt");
    std::fs::remove_file(&marker).ok();

    assert!(started, "the container never reached its workload");
    assert!(
        leaked.is_empty(),
        "quilt's own setup mounts are visible on the host while it runs: {leaked:?}"
    );
}

#[test]
fn a_readonly_bind_cannot_be_written() {
    requires_root!();
    let dir = std::env::temp_dir().join("quilt-ro-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("marker"), "readable\n").unwrap();

    let bind = format!("{}:/mnt/ro", dir.display());
    assert_eq!(inside_with(&["--ro", &bind], "cat /mnt/ro/marker").trim(), "readable");

    let out = quilt(&["--ro", &bind], "echo nope > /mnt/ro/marker");
    assert!(!out.status.success(), "wrote to a read-only bind mount");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_readonly_bind_is_read_only_all_the_way_down() {
    requires_root!();
    // mount_setattr's AT_RECURSIVE is the difference: a MS_REMOUNT pass would
    // leave this submount writable.
    let dir = std::env::temp_dir().join("quilt-ro-recursive");
    let submount = dir.join("sub");
    std::fs::create_dir_all(&submount).unwrap();

    let mounted = Command::new("mount")
        .args(["-t", "tmpfs", "none", &submount.display().to_string()])
        .status()
        .expect("failed to run mount");
    if !mounted.success() {
        std::fs::remove_dir_all(&dir).ok();
        panic!("could not mount the test submount: {mounted}");
    }

    // Written after the mount, so it exists only on the tmpfs. Without reading
    // it from inside, a submount that never materialised would leave an
    // ordinary directory in a read-only bind, the write below would fail for
    // that reason, and the test would prove nothing about AT_RECURSIVE.
    std::fs::write(submount.join("marker"), "readable\n").unwrap();

    let bind = format!("{}:/mnt/ro", dir.display());
    let read = quilt(&["--ro", &bind], "cat /mnt/ro/sub/marker");
    let write = quilt(&["--ro", &bind], "echo nope > /mnt/ro/sub/file");

    let unmounted = Command::new("umount").arg(submount.display().to_string()).status();
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        read.status.success(),
        "the submount never reached the container: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&read.stdout).trim(), "readable");
    assert!(!write.status.success(), "wrote to a submount of a read-only bind");
    assert!(matches!(unmounted, Ok(status) if status.success()), "left the test tmpfs mounted");
}

#[test]
fn the_workloads_exit_code_is_the_runtimes_exit_code() {
    requires_root!();
    assert_eq!(quilt(&[], "exit 42").status.code(), Some(42));
}

#[test]
fn pid_one_ignores_a_signal_it_sends_itself() {
    requires_root!();
    // A pid namespace's init only takes delivery of signals it has a handler
    // for, when the sender is inside the namespace. Even SIGKILL is discarded.
    let out = quilt(&[], "kill -9 $$; echo survived");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "survived");
}

#[test]
fn a_process_other_than_pid_one_is_still_killable() {
    requires_root!();
    // The immunity above belongs to pid 1, not to the namespace.
    assert_eq!(inside("sh -c 'kill -9 $$'; echo $?").trim(), "137");
}

#[test]
fn the_workload_is_born_inside_its_own_scope() {
    requires_root!();
    // The unified hierarchy reports one line, "0::<path>".
    let cgroup = inside("cat /proc/self/cgroup");
    assert!(cgroup.trim().starts_with("0::/quilt/run-"), "pid 1 is not in a quilt scope: {cgroup}");
}

#[test]
fn the_limits_reach_the_scope_the_workload_is_in() {
    requires_root!();
    let (mut child, marker) =
        spawn_running(&["--memory", "64M", "--cpus", "0.5", "--pids", "32"], "quilt-limits");
    let started = marker.exists();

    let found = run_scopes();
    let values = found.first().map(|scope| {
        (
            read_trim(scope.join("memory.max")),
            read_trim(scope.join("memory.swap.max")),
            read_trim(scope.join("cpu.max")),
            read_trim(scope.join("pids.max")),
        )
    });

    child.wait().expect("waiting for quilt");
    std::fs::remove_file(&marker).ok();

    assert!(started, "the container never reached its workload");
    assert_eq!(found.len(), 1, "expected exactly one live scope, found {found:?}");

    let (memory, swap, cpu, pids) = values.unwrap();
    assert_eq!(memory, "67108864");
    assert_eq!(swap, "0");
    assert_eq!(cpu, "50000 100000");
    assert_eq!(pids, "32");
}

#[test]
fn a_memory_limit_oom_kills_the_workload() {
    requires_root!();
    // dd touches all of a bs-sized buffer, so 64M of anonymous memory against a
    // 16M ceiling has nowhere to go: reclaim cannot free it and
    // memory.swap.max is 0.
    let out = quilt(&["--memory", "16M"], "dd if=/dev/zero of=/dev/null bs=64M count=1");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let kills = stderr.split("oom_kill=").nth(1).and_then(|rest| rest.trim().parse::<u64>().ok());

    assert!(matches!(kills, Some(n) if n > 0), "no OOM kill was reported: {stderr}");
}

#[test]
fn a_pids_limit_blocks_a_fork_bomb() {
    requires_root!();
    // The pid namespace tears down when pid 1 exits, so the survivors of this
    // do not outlive the test.
    let out = quilt(
        &["--pids", "8"],
        "i=0; while [ $i -lt 40 ]; do sleep 1 & i=$((i+1)); done; echo finished",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(stderr.contains("fork"), "forks were never refused: {stderr}");
}

#[test]
fn the_scope_is_gone_once_the_container_exits() {
    requires_root!();
    assert_eq!(inside_with(&["--memory", "64M"], "echo done").trim(), "done");
    let leftover = run_scopes();
    assert!(leftover.is_empty(), "the scope outlived the container: {leftover:?}");
}

#[test]
fn a_straggler_outliving_pid_one_does_not_leak_the_scope() {
    requires_root!();
    // pid 1 exits while a child is still running, so the namespace is still
    // being torn down when the scope is. Without cgroup.kill and the populated
    // wait, the rmdir loses that race with EBUSY.
    assert!(quilt(&[], "sleep 100 & exit 0").status.success());

    let leftover = run_scopes();
    assert!(leftover.is_empty(), "a straggler left the scope behind: {leftover:?}");
}

#[test]
fn a_scope_is_removed_even_when_the_container_fails_to_start() {
    requires_root!();
    // The workload does not exist, so init fails after the scope was created.
    let failed = Command::new(env!("CARGO_BIN_EXE_quilt"))
        .args(["run", "--memory", "64M", &rootfs().display().to_string(), "/nonexistent-binary"])
        .output()
        .expect("failed to spawn quilt");

    assert!(!failed.status.success(), "a missing workload should have failed");
    let leftover = run_scopes();
    assert!(leftover.is_empty(), "a failed start left a scope behind: {leftover:?}");
}

#[test]
fn a_bridge_container_gets_an_address_and_a_default_route() {
    requires_root!();
    let addresses = inside_with(&["--net", "bridge"], "ip -4 addr show eth0");
    assert!(addresses.contains("10.88."), "eth0 has no address in the subnet: {addresses}");
    assert!(addresses.contains("/16"), "the prefix length did not survive: {addresses}");

    let routes = inside_with(&["--net", "bridge"], "ip route");
    assert!(
        routes.contains("default via 10.88.0.1"),
        "no default route through the bridge: {routes}"
    );
}

#[test]
fn a_bridge_container_reaches_its_gateway() {
    requires_root!();
    // The gateway is the bridge itself, so this needs no internet.
    let out = quilt(&["--net", "bridge"], "ping -c 1 -W 3 10.88.0.1");
    assert!(
        out.status.success(),
        "could not reach the bridge: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_bridge_container_reaches_the_internet() {
    requires_root!();
    if !host_reaches_the_internet() {
        // Only the NAT hop goes untested; the gateway test covers the rest.
        eprintln!("skipped: the host cannot reach 1.1.1.1 either, so neither can a container");
        return;
    }

    let out = quilt(&["--net", "bridge"], "ping -c 1 -W 5 1.1.1.1");
    assert!(
        out.status.success(),
        "masquerading did not carry the container out: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_veth_does_not_outlive_the_container() {
    requires_root!();
    assert_eq!(inside_with(&["--net", "bridge"], "echo done").trim(), "done");

    let leftover: Vec<String> =
        host_links().into_iter().filter(|name| name.starts_with("qv")).collect();
    assert!(leftover.is_empty(), "veth ends survived the container: {leftover:?}");
}

#[test]
fn the_bridge_is_shared_rather_than_recreated() {
    requires_root!();
    // quilt0 outlives containers on purpose: tearing it down would cut off
    // anything else still attached.
    assert_eq!(inside_with(&["--net", "bridge"], "echo done").trim(), "done");
    assert!(host_links().contains(&"quilt0".to_string()), "the bridge went away");
}

#[test]
fn two_containers_at_once_do_not_collide() {
    requires_root!();
    let (mut first, first_marker) = spawn_running(&["--net", "bridge"], "quilt-net-a");
    let (mut second, second_marker) = spawn_running(&["--net", "bridge"], "quilt-net-b");
    let started = first_marker.exists() && second_marker.exists();

    let veths: Vec<String> =
        host_links().into_iter().filter(|name| name.starts_with("qv")).collect();

    first.wait().expect("waiting for the first container");
    second.wait().expect("waiting for the second container");
    std::fs::remove_file(&first_marker).ok();
    std::fs::remove_file(&second_marker).ok();

    assert!(started, "both containers should have reached their workload");
    assert_eq!(veths.len(), 2, "expected one veth each, found {veths:?}");
}

// --- Phase 4: the OCI runtime interface -----------------------------------

/// A bundle with the smallest config.json that is still a real container.
fn write_bundle(dir: &PathBuf, args: &str) -> PathBuf {
    write_bundle_with(dir, args, "", "")
}

fn write_bundle_as(dir: &PathBuf, args: &str, process_extra: &str) -> PathBuf {
    write_bundle_with(dir, args, process_extra, "")
}

/// `process_extra` and `linux_extra` are spliced into their objects, for the
/// fields a particular test cares about.
fn write_bundle_with(dir: &PathBuf, args: &str, process_extra: &str, linux_extra: &str) -> PathBuf {
    write_bundle_in(dir, args, process_extra, linux_extra, DEFAULT_NAMESPACES)
}

const DEFAULT_NAMESPACES: &str = r#"{"type": "pid"}, {"type": "ipc"}, {"type": "uts"},
                                    {"type": "mount"}, {"type": "network"}"#;

/// As [`write_bundle_with`], but with the namespace list spelled out, for the
/// tests that care which namespaces the container has.
fn write_bundle_in(
    dir: &PathBuf,
    args: &str,
    process_extra: &str,
    linux_extra: &str,
    namespaces: &str,
) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let config = format!(
        r#"{{
            "ociVersion": "1.2.1",
            "process": {{
                {process_extra}
                "args": [{args}],
                "cwd": "/",
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "capabilities": {{"bounding": ["CAP_CHOWN"], "effective": ["CAP_CHOWN"],
                                  "permitted": ["CAP_CHOWN"]}},
                "rlimits": [{{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}}],
                "noNewPrivileges": true
            }},
            "root": {{"path": "{rootfs}"}},
            "hostname": "quilt-oci",
            "mounts": [
                {{"destination": "/proc", "type": "proc", "source": "proc",
                  "options": ["nosuid", "noexec", "nodev"]}},
                {{"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                  "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}}
            ],
            "linux": {{
                {linux_extra}
                "namespaces": [{namespaces}],
                "resources": {{"pids": {{"limit": 64}}}},
                "maskedPaths": ["/proc/kcore"],
                "readonlyPaths": ["/proc/sys"]
            }}
        }}"#,
        args = args,
        process_extra = process_extra,
        linux_extra = linux_extra,
        namespaces = namespaces,
        rootfs = rootfs().display()
    );
    std::fs::write(dir.join("config.json"), config).unwrap();
    dir.clone()
}

/// Runs `create`, keeping the container's stdio off pipes.
///
/// init inherits create's descriptors and outlives it, parked on the exec
/// fifo. `Command::output()` waits for EOF on the pipes it makes, so piping
/// either stream deadlocks: the test waits on init, which waits on the `start`
/// the test has not reached. Conmon hands over descriptors for the same reason.
fn create_container(state_root: &PathBuf, bundle: &PathBuf, id: &str, log: &PathBuf) -> String {
    let stdout = std::fs::File::create(log).unwrap();
    let errors = log.with_extension("err");

    let status = Command::new(env!("CARGO_BIN_EXE_quilt"))
        .arg("--root")
        .arg(state_root)
        .args(["create", "--bundle"])
        .arg(bundle)
        .arg(id)
        .stdout(stdout)
        .stderr(std::fs::File::create(&errors).unwrap())
        .status()
        .expect("failed to spawn quilt");

    let stderr = std::fs::read_to_string(&errors).unwrap_or_default();
    assert!(status.success(), "create failed: {stderr}");
    stderr
}

/// `create` where the bundle is expected to be refused. Returns its stderr.
///
/// Redirected for the same reason as `create_container`: where create
/// *succeeds*, `Command::output()` would wait on an init parked on the fifo.
fn try_create_container(state_root: &PathBuf, bundle: &PathBuf, id: &str) -> (bool, String) {
    let work = state_root.with_extension("create-log");
    std::fs::create_dir_all(&work).unwrap();
    let errors = work.join(format!("{id}.err"));

    let status = Command::new(env!("CARGO_BIN_EXE_quilt"))
        .arg("--root")
        .arg(state_root)
        .args(["create", "--bundle"])
        .arg(bundle)
        .arg(id)
        .stdout(std::fs::File::create(work.join(format!("{id}.out"))).unwrap())
        .stderr(std::fs::File::create(&errors).unwrap())
        .status()
        .expect("failed to spawn quilt");

    (status.success(), std::fs::read_to_string(&errors).unwrap_or_default())
}

fn quilt_oci(state_root: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_quilt"))
        .arg("--root")
        .arg(state_root)
        .args(args)
        .output()
        .expect("failed to spawn quilt")
}

fn status_of(state_root: &PathBuf, id: &str) -> String {
    let out = quilt_oci(state_root, &["state", id]);
    assert!(out.status.success(), "state failed: {}", String::from_utf8_lossy(&out.stderr));
    let json = String::from_utf8_lossy(&out.stdout);
    // Small enough not to want a JSON parser in the test.
    for line in json.lines() {
        if let Some(rest) = line.trim().strip_prefix("\"status\": \"") {
            return rest.trim_end_matches("\",").trim_end_matches('"').to_string();
        }
    }
    panic!("no status in {json}");
}

#[test]
fn the_lifecycle_verbs_drive_a_container_from_create_to_delete() {
    requires_root!();
    let work = std::env::temp_dir().join("quilt-oci-lifecycle");
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle(&work.join("bundle"), r#""/bin/sh", "-c", "echo hello""#);
    let state_root = work.join("state");
    let log = work.join("stdout");
    std::fs::create_dir_all(&state_root).unwrap();

    clear_container(&state_root, "lifecycle-test");
    create_container(&state_root, &bundle, "lifecycle-test", &log);

    // Created, not running: the workload must not have run yet.
    assert_eq!(status_of(&state_root, "lifecycle-test"), "created");
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "", "the workload ran before start");

    let started = quilt_oci(&state_root, &["start", "lifecycle-test"]);
    assert!(started.status.success(), "start failed: {}", String::from_utf8_lossy(&started.stderr));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while status_of(&state_root, "lifecycle-test") != "stopped"
        && deadline > std::time::Instant::now()
    {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let output = std::fs::read_to_string(&log).unwrap();
    // init's stderr, the only place a failure between `start` and `execve`
    // says anything.
    let errors = std::fs::read_to_string(log.with_extension("err")).unwrap_or_default();
    let deleted = quilt_oci(&state_root, &["delete", "lifecycle-test"]);
    let leftover = scope_of("lifecycle-test").exists();
    std::fs::remove_dir_all(&work).ok();

    assert_eq!(output.trim(), "hello", "the workload did not run on start: {errors}");
    assert!(
        deleted.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(!state_root.join("lifecycle-test").exists(), "delete left state behind");
    assert!(!leftover, "delete left a cgroup scope behind");
}

#[test]
fn a_container_can_run_as_a_user_other_than_root() {
    requires_root!();
    // Everything else runs as uid 0, where the two capability passes can be in
    // either order. Moving off uid 0 empties the effective set, so a
    // bounding-set sweep after the user change fails every drop with EPERM.
    let work = std::env::temp_dir().join("quilt-oci-user");
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle_as(
        &work.join("bundle"),
        r#""/bin/sh", "-c", "id -u""#,
        r#""user": {"uid": 1000, "gid": 1000},"#,
    );
    let state_root = work.join("state");
    let log = work.join("stdout");
    std::fs::create_dir_all(&state_root).unwrap();

    clear_container(&state_root, "user-test");
    create_container(&state_root, &bundle, "user-test", &log);
    quilt_oci(&state_root, &["start", "user-test"]);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while status_of(&state_root, "user-test") != "stopped" && deadline > std::time::Instant::now() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let output = std::fs::read_to_string(&log).unwrap();
    let errors = std::fs::read_to_string(log.with_extension("err")).unwrap_or_default();
    quilt_oci(&state_root, &["delete", "--force", "user-test"]);
    std::fs::remove_dir_all(&work).ok();

    assert_eq!(output.trim(), "1000", "the container did not become uid 1000: {errors}");
}

#[test]
fn a_container_that_is_still_running_is_not_deleted_without_force() {
    requires_root!();
    let work = std::env::temp_dir().join("quilt-oci-force");
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle(&work.join("bundle"), r#""/bin/sh", "-c", "sleep 30""#);
    let state_root = work.join("state");
    std::fs::create_dir_all(&state_root).unwrap();

    clear_container(&state_root, "force-test");
    create_container(&state_root, &bundle, "force-test", &work.join("stdout"));
    quilt_oci(&state_root, &["start", "force-test"]);

    let refused = quilt_oci(&state_root, &["delete", "force-test"]);
    let forced = quilt_oci(&state_root, &["delete", "--force", "force-test"]);
    let leftover = scope_of("force-test").exists();
    std::fs::remove_dir_all(&work).ok();

    assert!(!refused.status.success(), "a running container was deleted without --force");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--force"),
        "the refusal should say what to do: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(forced.status.success(), "{}", String::from_utf8_lossy(&forced.stderr));
    assert!(!leftover, "--force left a cgroup scope behind");
}

#[test]
fn an_unknown_container_is_an_error_not_a_panic() {
    requires_root!();
    let state_root = std::env::temp_dir().join("quilt-oci-missing");
    std::fs::create_dir_all(&state_root).unwrap();

    for verb in [vec!["state", "nope"], vec!["start", "nope"], vec!["delete", "nope"]] {
        let out = quilt_oci(&state_root, &verb);
        assert!(!out.status.success(), "{verb:?} should fail");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("nope"),
            "the error should name the container: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::remove_dir_all(&state_root).ok();
}

/// The podman demo with the container's real seccomp profile applied. The two
/// flags left are non-goals, explained in SPEC.md.
///
/// The headline acceptance criterion, so it may not skip itself into the green
/// over a missing image: `scripts/root-tests.sh` sets QUILT_TEST_PODMAN=1 and
/// this then insists on running. Leaving it unset says the criterion went
/// unchecked.
#[test]
fn podman_runs_a_container_end_to_end_through_quilt() {
    requires_root!();
    if std::env::var("QUILT_TEST_PODMAN").as_deref() != Ok("1") {
        eprintln!(
            "skipped: phase 4's acceptance criterion is UNVERIFIED without QUILT_TEST_PODMAN=1"
        );
        return;
    }

    let present = Command::new("podman")
        .args(["image", "exists", "alpine"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !present {
        let pulled = Command::new("podman")
            .args(["pull", "-q", "alpine"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(pulled, "root podman has no alpine image and could not pull one");
    }

    let out = Command::new("podman")
        .args([
            "--cgroup-manager=cgroupfs",
            "--runtime",
            env!("CARGO_BIN_EXE_quilt"),
            "run",
            "--rm",
            "--security-opt",
            "label=disable",
            "alpine",
            "ls",
            "/",
        ])
        .output()
        .expect("failed to spawn podman");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "podman could not drive quilt: {}{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("etc"), "the container did not list its root: {stdout}");
}

/// The write goes through the *host's* `/proc`, because the mount plan has not
/// run yet — but `/proc/sys/net` is resolved through the calling task's network
/// namespace, not through the superblock it was mounted from. So the value
/// lands in the container. Nothing else in the tree records that, and the
/// failure if it were wrong is a container silently reconfiguring the host.
#[test]
fn a_namespaced_sysctl_lands_in_the_container_and_not_on_the_host() {
    requires_root!();
    const KEY: &str = "/proc/sys/net/ipv4/ping_group_range";
    let before = std::fs::read_to_string(KEY).unwrap();

    let (output, errors) = run_bundle(
        "sysctl-netns",
        r#""/bin/sh", "-c", "cat /proc/sys/net/ipv4/ping_group_range""#,
        r#""sysctl": {"net.ipv4.ping_group_range": "100 200"},"#,
    );

    let inside: Vec<&str> = output.split_whitespace().collect();
    assert_eq!(inside, ["100", "200"], "the container did not see its own sysctl: {errors}");
    assert_eq!(std::fs::read_to_string(KEY).unwrap(), before, "the host's sysctl was changed");
}

/// `net.*` is namespaced, which only helps if the container is in a network
/// namespace of its own. Without one the write reaches the host.
#[test]
fn a_namespaced_sysctl_is_refused_when_its_namespace_was_not_asked_for() {
    requires_root!();
    let work = std::env::temp_dir().join("quilt-sysctl-no-netns");
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle_in(
        &work.join("bundle"),
        r#""/bin/true""#,
        "",
        r#""sysctl": {"net.ipv4.ping_group_range": "100 200"},"#,
        r#"{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}"#,
    );
    let state_root = work.join("state");
    std::fs::create_dir_all(&state_root).unwrap();

    let (ok, stderr) = try_create_container(&state_root, &bundle, "sysctl-no-netns");
    assert!(!ok, "a net.* sysctl without a network namespace was accepted");
    assert!(
        stderr.contains("network namespace") && stderr.contains("land on the host"),
        "the refusal should say why: {stderr}"
    );
    std::fs::remove_dir_all(&work).ok();
}

// --- Phase 5: seccomp -----------------------------------------------------

/// Runs a bundle with `seccomp` as its `linux.seccomp` and returns what the
/// workload wrote, plus init's own stderr.
fn run_with_seccomp(name: &str, args: &str, seccomp: &str) -> (String, String) {
    run_bundle(name, args, &format!(r#""seccomp": {seccomp},"#))
}

/// Runs a bundle with `linux_extra` spliced into its `linux` object, and
/// returns what the workload wrote plus init's own stderr.
fn run_bundle(name: &str, args: &str, linux_extra: &str) -> (String, String) {
    let work = std::env::temp_dir().join(format!("quilt-bundle-{name}"));
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle_with(&work.join("bundle"), args, "", linux_extra);
    let state_root = work.join("state");
    let log = work.join("stdout");
    std::fs::create_dir_all(&state_root).unwrap();

    clear_container(&state_root, name);
    create_container(&state_root, &bundle, name, &log);
    quilt_oci(&state_root, &["start", name]);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while status_of(&state_root, name) != "stopped" && deadline > std::time::Instant::now() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let output = std::fs::read_to_string(&log).unwrap_or_default();
    let errors = std::fs::read_to_string(log.with_extension("err")).unwrap_or_default();

    quilt_oci(&state_root, &["delete", "--force", name]);
    std::fs::remove_dir_all(&work).ok();
    (output, errors)
}

#[test]
fn a_denied_syscall_returns_an_errno_rather_than_killing_the_container() {
    requires_root!();
    // Why an errno beats a kill: the workload keeps running and says which
    // call failed.
    let (output, errors) = run_with_seccomp(
        "seccomp-errno",
        r#""/bin/sh", "-c", "chmod 777 /tmp 2>/dev/null; echo rc=$?; echo alive""#,
        r#"{
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{"names": ["chmod", "fchmodat", "fchmodat2"],
                          "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
        }"#,
    );

    assert!(output.contains("rc=1"), "chmod should have failed with EPERM: {output}{errors}");
    assert!(output.contains("alive"), "the workload should have survived: {output}{errors}");
}

#[test]
fn an_allowed_syscall_is_untouched_by_the_filter() {
    requires_root!();
    let (output, errors) = run_with_seccomp(
        "seccomp-allow",
        r#""/bin/sh", "-c", "echo hello""#,
        r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 38,
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{"names": ["read", "write", "execve", "exit", "exit_group",
                                    "brk", "mmap", "munmap", "mprotect", "arch_prctl",
                                    "rt_sigaction", "rt_sigprocmask", "openat", "close",
                                    "fstat", "newfstatat", "getpid", "wait4", "clone",
                                    "set_tid_address", "set_robust_list", "rseq",
                                    "prlimit64", "getuid", "getgid", "geteuid", "getegid",
                                    "ioctl", "readlink", "readlinkv", "getrandom",
                                    "pread64", "lseek", "uname", "fcntl", "sysinfo",
                                    "dup2", "dup3", "pipe2", "vfork", "getppid", "setpgid"],
                          "action": "SCMP_ACT_ALLOW"}]
        }"#,
    );

    assert_eq!(output.trim(), "hello", "an allowlisted workload should run: {errors}");
}

#[test]
fn a_kill_action_kills_the_caller_rather_than_returning_an_error() {
    requires_root!();
    // SCMP_ACT_KILL_PROCESS ends the process that made the call — the `chmod`
    // the shell forked, not the shell — so the shell reports how its child
    // died. That status tells the outcomes apart: 0 means the filter never
    // applied, 1 means EPERM as in the test above, 159 is 128 + SIGSYS.
    let (output, errors) = run_with_seccomp(
        "seccomp-kill",
        r#""/bin/sh", "-c", "chmod 777 /tmp; echo rc=$?""#,
        r#"{
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{"names": ["chmod", "fchmodat", "fchmodat2"],
                          "action": "SCMP_ACT_KILL_PROCESS"}]
        }"#,
    );

    assert!(
        output.contains("rc=159"),
        "chmod should have died of SIGSYS, got {output:?}: {errors}"
    );
}

#[test]
fn a_profile_quilt_cannot_build_is_refused_before_the_container_starts() {
    requires_root!();
    // SCMP_ACT_NOTIFY needs a user-space agent on the other end of a
    // descriptor. Running it unfiltered would look exactly like success.
    let work = std::env::temp_dir().join("quilt-seccomp-notify");
    std::fs::remove_dir_all(&work).ok();
    let bundle = write_bundle_with(
        &work.join("bundle"),
        r#""/bin/sh", "-c", "echo ran""#,
        "",
        r#""seccomp": {"defaultAction": "SCMP_ACT_ALLOW",
                       "syscalls": [{"names": ["chmod"], "action": "SCMP_ACT_NOTIFY"}]},"#,
    );
    let state_root = work.join("state");
    std::fs::create_dir_all(&state_root).unwrap();
    clear_container(&state_root, "notify-test");

    let (created, stderr) = try_create_container(&state_root, &bundle, "notify-test");
    let started = state_root.join("notify-test").exists();
    std::fs::remove_dir_all(&work).ok();

    assert!(!created, "a profile quilt cannot build should refuse the container");
    assert!(stderr.contains("SCMP_ACT_NOTIFY"), "the error should name the action: {stderr}");
    assert!(!started, "the refusal must happen before any container state exists");
}
