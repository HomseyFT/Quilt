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
    let marker = rootfs().join("quilt-running");
    std::fs::remove_file(&marker).ok();

    let mut child = Command::new(env!("CARGO_BIN_EXE_quilt"))
        .args([
            "run",
            &rootfs().display().to_string(),
            "/bin/sh",
            "-c",
            "touch /quilt-running; sleep 3",
        ])
        .spawn()
        .expect("failed to spawn quilt");

    // The rootfs is a host directory, so the marker appearing means the mount
    // setup finished and the workload is running.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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

    Command::new("mount")
        .args(["-t", "tmpfs", "none", &submount.display().to_string()])
        .status()
        .expect("mounting the test submount");

    let bind = format!("{}:/mnt/ro", dir.display());
    let out = quilt(&["--ro", &bind], "echo nope > /mnt/ro/sub/file");

    Command::new("umount").arg(submount.display().to_string()).status().ok();
    std::fs::remove_dir_all(&dir).ok();

    assert!(!out.status.success(), "wrote to a submount of a read-only bind");
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
