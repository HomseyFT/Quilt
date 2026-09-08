//! The OCI runtime `config.json`.
//!
//! The runtime spec is large and most of it does not apply here, so this covers
//! what podman actually sends for a `podman run` — captured from a real
//! invocation, not guessed; `tests/fixtures/` holds those captures and the unit
//! tests parse them.
//!
//! `process` and `linux` deny unknown fields on purpose. They are where the
//! security-bearing settings live, and a field quilt has never heard of is
//! exactly the one it must not skip past. The cost is that a future podman
//! adding a field makes quilt complain rather than quietly ignore it, which is
//! the trade the spec asks for.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub linux: Linux,
    /// Commands the runtime would run around the container's lifecycle.
    #[serde(default)]
    pub hooks: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Process {
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub user: User,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "root_dir")]
    pub cwd: PathBuf,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    #[serde(default)]
    pub no_new_privileges: bool,
    #[serde(default)]
    pub oom_score_adj: Option<i32>,
    #[serde(default)]
    pub selinux_label: Option<String>,
    #[serde(default)]
    pub apparmor_profile: Option<String>,
    #[serde(default)]
    pub scheduler: Option<serde_json::Value>,
    #[serde(default)]
    pub io_priority: Option<serde_json::Value>,
    #[serde(default)]
    pub exec_cpu_affinity: Option<serde_json::Value>,
    #[serde(default)]
    pub console_size: Option<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct User {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub umask: Option<u32>,
    #[serde(default)]
    pub additional_gids: Vec<u32>,
    /// Informational: the uid and gid above are what the runtime acts on.
    #[serde(default)]
    #[allow(dead_code)]
    pub username: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub bounding: Vec<String>,
    #[serde(default)]
    pub effective: Vec<String>,
    #[serde(default)]
    pub permitted: Vec<String>,
    #[serde(default)]
    pub inheritable: Vec<String>,
    #[serde(default)]
    pub ambient: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub kind: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    pub path: PathBuf,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mount {
    pub destination: PathBuf,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Linux {
    #[serde(default)]
    pub namespaces: Vec<Namespace>,
    #[serde(default)]
    pub resources: Option<Resources>,
    #[serde(default)]
    pub cgroups_path: Option<String>,
    #[serde(default)]
    pub masked_paths: Vec<PathBuf>,
    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,
    #[serde(default)]
    pub sysctl: BTreeMap<String, String>,
    #[serde(default)]
    pub mount_label: Option<String>,
    #[serde(default)]
    pub rootfs_propagation: Option<String>,
    #[serde(default)]
    pub seccomp: Option<Seccomp>,
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub devices: Vec<serde_json::Value>,
    #[serde(default)]
    pub intel_rdt: Option<serde_json::Value>,
    #[serde(default)]
    pub personality: Option<serde_json::Value>,
    #[serde(default)]
    pub time_offsets: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seccomp {
    pub default_action: String,
    #[serde(default)]
    pub default_errno_ret: Option<u32>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub listener_path: Option<String>,
    #[serde(default)]
    pub listener_metadata: Option<String>,
    #[serde(default)]
    pub syscalls: Vec<SyscallRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyscallRule {
    pub names: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub errno_ret: Option<u32>,
    #[serde(default)]
    pub args: Vec<SyscallArg>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyscallArg {
    pub index: u32,
    pub value: u64,
    /// Only meaningful for the masked and range comparisons, which the filter
    /// builder refuses before this is ever looked at.
    #[serde(default)]
    #[allow(dead_code)]
    pub value_two: Option<u64>,
    pub op: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub kind: NamespaceKind,
    /// An existing namespace to join, rather than a new one to create.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceKind {
    Pid,
    Network,
    Mount,
    Ipc,
    Uts,
    User,
    Cgroup,
    Time,
}

/// Only ever appears where quilt refuses the bundle outright, so nothing reads
/// the rows; they exist so that such a bundle parses far enough to be refused
/// with a useful message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    #[serde(default)]
    pub memory: Option<Memory>,
    #[serde(default)]
    pub cpu: Option<Cpu>,
    #[serde(default)]
    pub pids: Option<Pids>,
    #[serde(default)]
    pub block_io: Option<serde_json::Value>,
    #[serde(default)]
    pub hugepage_limits: Vec<serde_json::Value>,
    #[serde(default)]
    pub network: Option<serde_json::Value>,
    #[serde(default)]
    pub rdma: Option<serde_json::Value>,
    #[serde(default)]
    pub devices: Vec<DeviceRule>,
    #[serde(default)]
    pub unified: BTreeMap<String, String>,
}

/// One row of the cgroup device allowlist.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
pub struct DeviceRule {
    pub allow: bool,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub major: Option<i64>,
    #[serde(default)]
    pub minor: Option<i64>,
    #[serde(default)]
    pub access: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Memory {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub swap: Option<i64>,
    #[serde(default)]
    pub reservation: Option<i64>,
    #[serde(default)]
    pub kernel: Option<i64>,
    #[serde(default)]
    pub kernel_tcp: Option<i64>,
    #[serde(default)]
    pub swappiness: Option<u64>,
    #[serde(default)]
    pub disable_oom_killer: Option<bool>,
    #[serde(default)]
    pub use_hierarchy: Option<bool>,
    #[serde(default)]
    pub check_before_update: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cpu {
    #[serde(default)]
    pub quota: Option<i64>,
    #[serde(default)]
    pub period: Option<u64>,
    #[serde(default)]
    pub shares: Option<u64>,
    #[serde(default)]
    pub burst: Option<u64>,
    #[serde(default)]
    pub realtime_runtime: Option<i64>,
    #[serde(default)]
    pub realtime_period: Option<u64>,
    #[serde(default)]
    pub cpus: Option<String>,
    #[serde(default)]
    pub mems: Option<String>,
    #[serde(default)]
    pub idle: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pids {
    pub limit: i64,
}

impl Resources {
    /// The first resource control that is set and that quilt does not write.
    ///
    /// Some of these are only performance, but `devices` is the cgroup device
    /// allowlist and `unified` writes arbitrary cgroup files, so the set has to
    /// be refused as a whole rather than sorted into important and not.
    fn unsupported(&self) -> Option<&'static str> {
        let listed = [
            ("linux.resources.blockIO", self.block_io.is_some()),
            ("linux.resources.hugepageLimits", !self.hugepage_limits.is_empty()),
            ("linux.resources.network", self.network.is_some()),
            ("linux.resources.rdma", self.rdma.is_some()),
            // Not simply "is it set". Every podman bundle carries a single
            // blanket deny and leaves the runtime to permit the nodes it then
            // creates. quilt reaches that same end by construction: the
            // container's /dev holds exactly the nodes the runtime put there
            // and nothing else, so a list that permits nothing is a list quilt
            // already satisfies. A rule that *allows* a device is one it would
            // have to enforce, and cannot — cgroup v2 does that with an eBPF
            // program attached to the scope.
            ("linux.resources.devices", self.devices.iter().any(|rule| rule.allow)),
            ("linux.resources.unified", !self.unified.is_empty()),
        ];
        if let Some((field, _)) = listed.iter().find(|(_, present)| *present) {
            return Some(field);
        }

        if let Some(memory) = &self.memory {
            let listed = [
                ("memory.reservation", memory.reservation.is_some()),
                ("memory.kernel", memory.kernel.is_some()),
                ("memory.kernelTCP", memory.kernel_tcp.is_some()),
                ("memory.swappiness", memory.swappiness.is_some()),
                ("memory.disableOOMKiller", memory.disable_oom_killer.is_some()),
                ("memory.useHierarchy", memory.use_hierarchy.is_some()),
                ("memory.checkBeforeUpdate", memory.check_before_update.is_some()),
            ];
            if let Some((field, _)) = listed.iter().find(|(_, present)| *present) {
                return Some(field);
            }
        }

        if let Some(cpu) = &self.cpu {
            let listed = [
                ("cpu.shares", cpu.shares.is_some()),
                ("cpu.burst", cpu.burst.is_some()),
                ("cpu.realtimeRuntime", cpu.realtime_runtime.is_some()),
                ("cpu.realtimePeriod", cpu.realtime_period.is_some()),
                ("cpu.cpus", cpu.cpus.is_some()),
                ("cpu.mems", cpu.mems.is_some()),
                ("cpu.idle", cpu.idle.is_some()),
            ];
            if let Some((field, _)) = listed.iter().find(|(_, present)| *present) {
                return Some(field);
            }
        }
        None
    }
}

fn root_dir() -> PathBuf {
    PathBuf::from("/")
}

impl Config {
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| Error::msg(format!("config.json is not a config quilt understands: {e}")))
    }

    /// Refuses anything security-bearing that quilt does not implement.
    ///
    /// The failure this guards against is not a wrong answer, it is a quiet
    /// one: accepting a bundle that asks for a syscall filter and running it
    /// without any filter at all looks exactly like success.
    pub fn validate(&self) -> Result<()> {
        if !self.oci_version.starts_with("1.") {
            return Err(Error::msg(format!(
                "config.json is runtime spec {}, and quilt implements 1.x",
                self.oci_version
            )));
        }

        if self.process.selinux_label.is_some() {
            return Err(Error::msg(
                "config.json asks for an SELinux process label, which quilt cannot apply: \
                 podman run --security-opt label=disable"
                    .to_string(),
            ));
        }
        if self.process.apparmor_profile.is_some() {
            return Err(Error::msg(
                "config.json asks for an AppArmor profile, which quilt cannot apply".to_string(),
            ));
        }
        if self.hooks.is_some() {
            return Err(Error::msg(
                "config.json declares hooks, which quilt does not run".to_string(),
            ));
        }
        if !self.linux.devices.is_empty() {
            return Err(Error::msg(
                "config.json declares devices, which quilt does not create".to_string(),
            ));
        }
        if !self.linux.uid_mappings.is_empty() || !self.linux.gid_mappings.is_empty() {
            return Err(Error::msg(
                "config.json declares id mappings, which quilt does not honour until phase 6"
                    .to_string(),
            ));
        }
        // Named so the bundle parses, and refused so it is not quietly dropped.
        // `deny_unknown_fields` guarantees quilt has *seen* every field; these
        // are the ones it has seen and cannot carry out.
        for (field, present) in [
            ("process.oomScoreAdj", self.process.oom_score_adj.is_some()),
            ("process.scheduler", self.process.scheduler.is_some()),
            ("process.ioPriority", self.process.io_priority.is_some()),
            ("process.execCPUAffinity", self.process.exec_cpu_affinity.is_some()),
            ("process.consoleSize", self.process.console_size.is_some()),
            ("linux.personality", self.linux.personality.is_some()),
            ("linux.intelRdt", self.linux.intel_rdt.is_some()),
            ("linux.timeOffsets", self.linux.time_offsets.is_some()),
            ("linux.rootfsPropagation", self.linux.rootfs_propagation.is_some()),
        ] {
            if present {
                return Err(Error::msg(format!(
                    "config.json sets {field}, which quilt does not apply"
                )));
            }
        }

        // Per-mount id mappings are idmapped mounts, which need CAP_SYS_ADMIN in
        // the namespace owning the filesystem's superblock — see the phase 6
        // notes in SPEC.md for why that is not something quilt can arrange.
        if self.mounts.iter().any(|m| !m.uid_mappings.is_empty() || !m.gid_mappings.is_empty()) {
            return Err(Error::msg(
                "config.json asks for an idmapped mount, which quilt does not create".to_string(),
            ));
        }

        if let Some(field) = self.linux.resources.as_ref().and_then(Resources::unsupported) {
            return Err(Error::msg(format!(
                "config.json sets {field}, which quilt does not write to the cgroup"
            )));
        }

        if self.process.terminal {
            return Err(Error::msg(
                "config.json asks for a terminal, which needs a console socket quilt does not \
                 implement: run podman without -t"
                    .to_string(),
            ));
        }
        if let Some(path) = &self.linux.cgroups_path {
            // The systemd form is slice:prefix:name, and honouring it means
            // asking systemd for a transient scope over dbus rather than
            // writing cgroup files. That is a different project, and doing it
            // by hand underneath systemd would fight the manager.
            if path.contains(':') {
                return Err(Error::msg(format!(
                    "cgroupsPath {path:?} is the systemd form, and quilt writes cgroup files \
                     directly: podman --cgroup-manager=cgroupfs"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{} is a committed capture of podman's config.json: {e}", path.display())
        })
    }

    #[test]
    fn the_config_podman_sends_by_default_parses() {
        let config = Config::parse(&fixture("podman-default.json")).unwrap();

        assert_eq!(config.oci_version, "1.2.1");
        assert_eq!(config.process.args, ["true"]);
        assert!(!config.process.terminal);
        assert_eq!(config.linux.namespaces.len(), 6);
        assert!(config.linux.seccomp.is_some());
    }

    /// Every field podman sends must be named by a struct, or `deny_unknown_fields`
    /// fails the parse. That is the point: an unrecognised field in `process`
    /// or `linux` is the one most likely to matter.
    #[test]
    fn the_config_podman_sends_with_security_options_off_parses() {
        let config = Config::parse(&fixture("podman-unconfined.json")).unwrap();
        assert!(config.linux.seccomp.is_none());
        assert!(config.process.selinux_label.is_none());
    }

    #[test]
    fn a_default_bundle_is_still_refused_for_its_selinux_label() {
        // Seccomp is no longer a reason to refuse; the process label is, and
        // the error names the flag that removes it.
        let config = Config::parse(&fixture("podman-default.json")).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("SELinux"), "{error}");
        assert!(error.contains("--security-opt"), "the error should say how to proceed: {error}");
    }

    #[test]
    fn the_seccomp_profile_podman_sends_is_fully_understood() {
        // `deny_unknown_fields` makes this a completeness check: every key in
        // the profile, down to the argument comparisons, has a field here.
        let config = Config::parse(&fixture("podman-default.json")).unwrap();
        let seccomp = config.linux.seccomp.as_ref().expect("podman sends a profile");

        assert_eq!(seccomp.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(seccomp.default_errno_ret, Some(38));
        assert_eq!(seccomp.syscalls.len(), 24);
        assert!(seccomp.syscalls.iter().any(|rule| !rule.args.is_empty()));
    }

    #[test]
    fn a_field_quilt_cannot_apply_is_refused_rather_than_dropped() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"], "oomScoreAdj": -500},
            "root": {"path": "/rootfs"}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("oomScoreAdj"), "{error}");
    }

    #[test]
    fn a_resource_control_quilt_does_not_write_is_refused() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"resources": {"cpu": {"cpus": "0-3"}}}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("cpu.cpus"), "{error}");
    }

    #[test]
    fn a_device_list_that_permits_nothing_is_the_one_podman_sends() {
        // A blanket deny asks for no access quilt grants, so accepting it does
        // not weaken anything.
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"resources": {"devices": [{"allow": false, "access": "rwm"}]}}
        }"#;
        Config::parse(json).unwrap().validate().unwrap();
    }

    #[test]
    fn a_device_rule_that_permits_something_is_refused() {
        // This one quilt would have to enforce, and cgroup v2 enforces it with
        // an eBPF program attached to the scope.
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"resources": {"devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "b", "major": 8, "minor": 0, "access": "rw"}
            ]}}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("resources.devices"), "{error}");
    }

    #[test]
    fn the_resource_controls_quilt_does_write_are_accepted() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"resources": {"pids": {"limit": 2048},
                                    "memory": {"limit": 1024},
                                    "cpu": {"quota": 50000, "period": 100000}}}
        }"#;
        Config::parse(json).unwrap().validate().unwrap();
    }

    #[test]
    fn a_bundle_with_the_security_options_off_is_accepted() {
        let config = Config::parse(&fixture("podman-unconfined.json")).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn a_network_namespace_given_by_path_is_one_to_join() {
        let config = Config::parse(&fixture("podman-unconfined.json")).unwrap();
        let by_path: Vec<NamespaceKind> = config
            .linux
            .namespaces
            .iter()
            .filter(|ns| ns.path.is_some())
            .map(|ns| ns.kind)
            .collect();

        assert_eq!(by_path, [NamespaceKind::Network], "podman pre-creates only the netns");
    }

    #[test]
    fn the_mounts_podman_sends_are_all_understood() {
        let config = Config::parse(&fixture("podman-unconfined.json")).unwrap();
        let kinds: Vec<&str> = config.mounts.iter().filter_map(|m| m.kind.as_deref()).collect();

        assert!(kinds.contains(&"proc"));
        assert!(kinds.contains(&"devpts"), "this is where /dev/pts finally arrives");
        assert!(kinds.contains(&"cgroup"));
        assert!(config.mounts.iter().any(|m| m.destination == Path::new("/etc/resolv.conf")));
    }

    #[test]
    fn an_unknown_field_in_linux_is_refused_rather_than_skipped() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"someNewSecurityKnob": {"enabled": true}}
        }"#;
        let error = Config::parse(json).unwrap_err().to_string();
        assert!(error.contains("someNewSecurityKnob"), "{error}");
    }

    #[test]
    fn the_systemd_cgroup_form_is_refused_with_the_flag_that_fixes_it() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"cgroupsPath": "user.slice:libpod:abc123"}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("--cgroup-manager=cgroupfs"), "{error}");
    }

    #[test]
    fn a_plain_cgroups_path_is_accepted() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "linux": {"cgroupsPath": "/libpod_parent/libpod-abc123"}
        }"#;
        Config::parse(json).unwrap().validate().unwrap();
    }

    #[test]
    fn a_future_spec_version_is_refused() {
        let json = r#"{
            "ociVersion": "2.0.0",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("2.0.0"), "{error}");
    }

    #[test]
    fn hooks_are_refused_because_they_would_silently_not_run() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "hooks": {"createRuntime": [{"path": "/bin/true"}]}
        }"#;
        let error = Config::parse(json).unwrap().validate().unwrap_err().to_string();
        assert!(error.contains("hooks"), "{error}");
    }
}
