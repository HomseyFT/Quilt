//! Phase 6: the same runtime, driven by an unprivileged user.
//!
//! Gated behind `QUILT_TEST_ROOTLESS=1` because these create cgroups and
//! containers in the invoking user's session, which a plain `cargo test` on
//! every save should not do. Run them with `scripts/rootless-tests.sh`.
//!
//! Deliberately not part of the root tier: every seam here picks its second
//! implementation precisely because the caller is *not* root, so running these
//! under sudo would exercise the other half.

use std::path::PathBuf;
use std::process::{Command, Output};

macro_rules! requires_rootless {
    () => {
        if std::env::var("QUILT_TEST_ROOTLESS").as_deref() != Ok("1") {
            eprintln!("skipped: set QUILT_TEST_ROOTLESS=1 (see scripts/rootless-tests.sh)");
            return;
        }
        assert!(
            !nix_is_root(),
            "the rootless tier must run as an ordinary user, or it tests the privileged seams"
        );
    };
}

fn nix_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|ids| ids.split_whitespace().next().map(|uid| uid == "0"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn host_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let ids = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
            ids.split_whitespace().next()?.parse().ok()
        })
        .expect("a uid")
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

fn inside(flags: &[&str], script: &str) -> String {
    let out = quilt(flags, script);
    assert!(out.status.success(), "container failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn delegated_root() -> PathBuf {
    let uid = host_uid();
    PathBuf::from(format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"))
}

#[test]
fn an_unprivileged_user_gets_a_container_whose_root_is_root() {
    requires_rootless!();
    // The whole point of the phase: uid 0 inside, an ordinary user outside.
    let id = inside(&[], "id -u");
    assert_eq!(id.trim(), "0");
}

#[test]
fn the_containers_root_is_the_invoking_user_on_the_host() {
    requires_rootless!();
    // The map is the proof, and it is what `newuidmap` was asked for: 0 inside
    // is this user outside, and the subordinate range follows.
    let map = inside(&[], "cat /proc/self/uid_map");
    let mut rows = map.lines();

    let first: Vec<&str> = rows.next().expect("a first row").split_whitespace().collect();
    assert_eq!(first[0], "0", "container root");
    assert_eq!(first[1], host_uid().to_string(), "is the invoking user");
    assert_eq!(first[2], "1");

    let second: Vec<&str> = rows.next().expect("a subordinate range").split_whitespace().collect();
    assert_eq!(second[0], "1", "and the rest comes from /etc/subuid");
    assert!(second[2].parse::<u32>().unwrap() > 1);
}

#[test]
fn the_workload_is_still_pid_one_and_isolated() {
    requires_rootless!();
    assert_eq!(inside(&[], "echo $$").trim(), "1");
    assert_eq!(inside(&["--hostname", "rootless-test"], "hostname").trim(), "rootless-test");
}

#[test]
fn the_scope_lands_in_the_subtree_systemd_delegated() {
    requires_rootless!();
    // /sys/fs/cgroup is not writable by this user; user@<uid>.service is.
    let cgroup = inside(&[], "cat /proc/self/cgroup");
    assert!(
        cgroup.contains(&format!("user@{}.service", host_uid())),
        "the container is not in the delegated subtree: {cgroup}"
    );

    // The run above created this, and make_scope never removes an ancestor, so
    // a missing directory is a broken assumption rather than an empty result.
    let quilt_dir = delegated_root().join("quilt");
    let entries = std::fs::read_dir(&quilt_dir)
        .unwrap_or_else(|e| panic!("{} should exist after a run: {e}", quilt_dir.display()));
    let leftover: Vec<PathBuf> =
        entries.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect();
    assert!(leftover.is_empty(), "a scope outlived its container: {leftover:?}");
}

#[test]
fn a_resource_limit_still_applies_without_privilege() {
    requires_rootless!();
    let out = quilt(&["--pids", "8"], "i=0; while [ $i -lt 40 ]; do sleep 1 & i=$((i+1)); done");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("fork"), "the delegated pids limit did not bite: {stderr}");
}

#[test]
fn bridge_networking_is_refused_with_the_flag_that_works_instead() {
    requires_rootless!();
    // A veth and a NAT rule need CAP_NET_ADMIN on the host, which no user
    // namespace confers. Saying so, and saying what does work, beats failing
    // somewhere inside netlink.
    let out = quilt(&["--net", "bridge"], "true");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(stderr.contains("--net pasta"), "the error should point at the answer: {stderr}");
}

#[test]
fn pasta_gives_the_container_an_address_and_a_route() {
    requires_rootless!();
    let output = inside(&["--net", "pasta"], "ip -4 route 2>/dev/null");
    assert!(output.contains("default via"), "pasta configured no default route: {output}");
}

#[test]
fn a_rootless_container_reaches_the_internet_through_pasta() {
    requires_rootless!();
    if !Command::new("ping")
        .args(["-c", "1", "-W", "3", "1.1.1.1"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
    {
        eprintln!("skipped: the host cannot reach 1.1.1.1 either, so neither can a container");
        return;
    }

    let out = quilt(&["--net", "pasta"], "ping -c 1 -W 5 1.1.1.1");
    assert!(
        out.status.success(),
        "pasta did not carry the container out: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn podman_drives_quilt_without_sudo_anywhere() {
    requires_rootless!();
    // The phase 6 acceptance criterion: the phase 4 demo, as an ordinary user.
    if !Command::new("podman")
        .args(["image", "exists", "alpine"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let pulled = Command::new("podman")
            .args(["pull", "-q", "alpine"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(pulled, "podman has no alpine image and could not pull one");
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
            "sh",
            "-c",
            "id -u",
        ])
        .output()
        .expect("failed to spawn podman");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "podman could not drive quilt unprivileged: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout.trim(), "0", "the container should be root inside");
}
