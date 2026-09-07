//! Phase 1 acceptance, asserted on observable behaviour.
//!
//! Gated behind `QUILT_TEST_ROOT=1` so a plain `cargo test` stays safe. Run
//! them with `scripts/root-tests.sh`, which builds as you and runs as root.

use std::collections::BTreeSet;
use std::path::PathBuf;
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

    Command::new(env!("CARGO_BIN_EXE_quilt"))
        .args(&args)
        .output()
        .expect("failed to spawn quilt")
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
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

fn read_trim(path: PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_default().trim().to_string()
}

/// Spawns a container that signals readiness by touching a marker on the
/// rootfs, then sleeps, so the host can inspect it while it is running. The
/// rootfs is a host directory, so the marker appearing means the mount setup
/// finished and the workload is live.
fn spawn_running(flags: &[&str], name: &str) -> (std::process::Child, PathBuf) {
    let marker = rootfs().join(name);
    std::fs::remove_file(&marker).ok();

    let mut args: Vec<String> = vec!["run".into()];
    args.extend(flags.iter().map(|f| f.to_string()));
    args.push(rootfs().display().to_string());
    args.extend([
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("touch /{name}; sleep 3"),
    ]);

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
    let pids: Vec<i32> = inside("ps -o pid=")
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();

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
    // The after-the-fact check above would miss a mount that exists for the
    // container's lifetime and is only torn down on exit. This one looks while
    // the container is up, which is what the spec's phase 1 actually claims.
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

    // Written after the mount, so it exists only on the tmpfs. Reading it from
    // inside is what keeps this test honest: without it, a submount that never
    // materialised leaves /mnt/ro/sub an ordinary directory in a read-only
    // bind, the write below fails for the boring reason, and the test passes
    // having proven nothing about AT_RECURSIVE.
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
    // A pid namespace's init only takes delivery of signals it has installed a
    // handler for, when the sender is inside the namespace. Even SIGKILL is
    // discarded, which is why a container cannot kill itself this way.
    let out = quilt(&[], "kill -9 $$; echo survived");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "survived");
}

#[test]
fn a_process_other_than_pid_one_is_still_killable() {
    requires_root!();
    // The immunity above belongs to pid 1, not to the namespace: a child dies
    // normally, and its shell reports 128 + SIGKILL.
    assert_eq!(inside("sh -c 'kill -9 $$'; echo $?").trim(), "137");
}

#[test]
fn the_workload_is_born_inside_its_own_scope() {
    requires_root!();
    // The unified hierarchy reports one line, "0::<path>".
    let cgroup = inside("cat /proc/self/cgroup");
    assert!(
        cgroup.trim().starts_with("0::/quilt/run-"),
        "pid 1 is not in a quilt scope: {cgroup}"
    );
}

#[test]
fn the_limits_reach_the_scope_the_workload_is_in() {
    requires_root!();
    let (mut child, marker) =
        spawn_running(&["--memory", "64M", "--cpus", "0.5", "--pids", "32"], "quilt-limits");
    let started = marker.exists();

    let found = scopes();
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
    // dd allocates a bs-sized buffer and touches all of it, so 64M of anonymous
    // memory against a 16M ceiling has nowhere to go: reclaim cannot free it
    // and memory.swap.max is 0, so the kernel has to kill something.
    let out = quilt(&["--memory", "16M"], "dd if=/dev/zero of=/dev/null bs=64M count=1");
    let stderr = String::from_utf8_lossy(&out.stderr);

    let kills = stderr
        .split("oom_kill=")
        .nth(1)
        .and_then(|rest| rest.trim().parse::<u64>().ok());

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
    let leftover = scopes();
    assert!(leftover.is_empty(), "the scope outlived the container: {leftover:?}");
}

#[test]
fn a_straggler_outliving_pid_one_does_not_leak_the_scope() {
    requires_root!();
    // pid 1 exits at once while a child is still running. waitpid returns as
    // soon as pid 1 is reaped, so the rest of the namespace is still being
    // killed and reparented when the scope is torn down. Without cgroup.kill
    // and the populated wait, the rmdir loses that race with EBUSY.
    assert!(quilt(&[], "sleep 100 & exit 0").status.success());

    let leftover = scopes();
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
    let leftover = scopes();
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
    // The gateway is the bridge itself, so this passes with no internet and
    // isolates the veth and routing from anything upstream.
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
        // Only the NAT hop goes untested here; the veth, the bridge and the
        // routing are covered by the gateway test, which needs no internet.
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
    // quilt0 outlives containers on purpose: it is the shared fabric, and
    // tearing it down would cut off anything else still attached.
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
