//! Building and applying the container's mount table.
//!
//! `prepare` produces a `MountPlan` without touching the system, so the
//! ordering — the part that fails quietly when it is wrong — is unit-testable
//! without root. `apply` runs it inside the new mount namespace and is dumb.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::mount::{self, MountFlags, MountPropagationFlags, UnmountFlags};

use crate::error::{Context, Error, Result};
use crate::spec;
use crate::syscall;

/// What `apply` must do to make a mount point exist before mounting on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Create {
    Nothing,
    Dir,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountOp {
    /// `mount(NULL, target, NULL, flags, NULL)` — propagation only.
    Propagation {
        target: PathBuf,
        flags: MountPropagationFlags,
    },
    Filesystem {
        source: String,
        target: PathBuf,
        fstype: String,
        flags: MountFlags,
        data: Option<String>,
        create: Create,
    },
    Bind {
        source: PathBuf,
        target: PathBuf,
        recursive: bool,
        readonly: bool,
        create: Create,
    },
    Symlink {
        original: String,
        link: PathBuf,
    },
    PivotRoot {
        new_root: PathBuf,
    },
    /// Hide a path inside the container. Applied after the pivot, so the path
    /// is container-absolute.
    Mask {
        path: PathBuf,
    },
    /// Make a path inside the container read-only, likewise after the pivot.
    Freeze {
        path: PathBuf,
    },
}

impl MountOp {
    /// The path this op mounts on. Only the ordering tests need it.
    #[cfg(test)]
    fn target(&self) -> &Path {
        match self {
            MountOp::Propagation { target, .. }
            | MountOp::Filesystem { target, .. }
            | MountOp::Bind { target, .. } => target,
            MountOp::Symlink { link, .. } => link,
            MountOp::PivotRoot { new_root } => new_root,
            MountOp::Mask { path } | MountOp::Freeze { path } => path,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountPlan {
    pub ops: Vec<MountOp>,
}

/// A host path made visible inside the container, read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindSpec {
    pub source: PathBuf,
    /// Absolute, as seen from inside the container.
    pub destination: PathBuf,
}

pub trait MountStrategy {
    fn prepare(&self, rootfs: &Path) -> Result<MountPlan>;
}

/// The device nodes the spec calls minimal.
const DEVICES: &[&str] = &["null", "zero", "random", "urandom", "tty"];

/// The devices the runtime spec says a runtime MUST provide.
///
/// A bundle does not list these — podman's `linux.devices` is empty and its
/// mount list stops at putting a tmpfs on `/dev`. Leaving them out is not a
/// missing convenience: masking a path binds `/dev/null` over it, so without
/// this the whole `maskedPaths` pass fails on a container that has no `/dev`.
const OCI_DEFAULT_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// `/dev` symlinks every shell expects to find.
const DEV_SYMLINKS: &[(&str, &str)] = &[
    ("/proc/self/fd", "fd"),
    ("/proc/self/fd/0", "stdin"),
    ("/proc/self/fd/1", "stdout"),
    ("/proc/self/fd/2", "stderr"),
];

/// The root-privileged mount setup. Phase 6 adds an idmapped-mount strategy
/// alongside it.
pub struct StandardMounts {
    pub readonly_binds: Vec<BindSpec>,
}

impl StandardMounts {
    pub fn new(readonly_binds: Vec<BindSpec>) -> Self {
        Self { readonly_binds }
    }
}

impl MountStrategy for StandardMounts {
    fn prepare(&self, rootfs: &Path) -> Result<MountPlan> {
        if !rootfs.is_absolute() {
            return Err(Error::msg(format!("rootfs {} must be absolute", rootfs.display())));
        }

        let nosuid_noexec_nodev = MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;
        // Nothing done below may propagate back to the host. This has to be
        // first, and it has to be recursive.
        let mut ops = vec![MountOp::Propagation {
            target: PathBuf::from("/"),
            flags: MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        }];

        // pivot_root requires new_root to be a mount point distinct from its
        // parent, so the rootfs is bound onto itself.
        ops.push(MountOp::Bind {
            source: rootfs.to_path_buf(),
            target: rootfs.to_path_buf(),
            recursive: true,
            readonly: false,
            create: Create::Nothing,
        });

        ops.push(MountOp::Filesystem {
            source: "proc".into(),
            target: rootfs.join("proc"),
            fstype: "proc".into(),
            flags: nosuid_noexec_nodev,
            data: None,
            create: Create::Dir,
        });

        ops.push(MountOp::Filesystem {
            source: "sysfs".into(),
            target: rootfs.join("sys"),
            fstype: "sysfs".into(),
            flags: nosuid_noexec_nodev | MountFlags::RDONLY,
            data: None,
            create: Create::Dir,
        });

        // /dev is a tmpfs so the device nodes below are ours, not the image's.
        ops.push(MountOp::Filesystem {
            source: "tmpfs".into(),
            target: rootfs.join("dev"),
            fstype: "tmpfs".into(),
            flags: MountFlags::NOSUID | MountFlags::STRICTATIME,
            data: Some("mode=0755,size=65536k".into()),
            create: Create::Dir,
        });

        for device in DEVICES {
            ops.push(MountOp::Bind {
                source: PathBuf::from("/dev").join(device),
                target: rootfs.join("dev").join(device),
                recursive: false,
                readonly: false,
                create: Create::File,
            });
        }

        for (original, link) in DEV_SYMLINKS {
            ops.push(MountOp::Symlink {
                original: (*original).into(),
                link: rootfs.join("dev").join(link),
            });
        }

        ops.push(MountOp::Filesystem {
            source: "shm".into(),
            target: rootfs.join("dev/shm"),
            fstype: "tmpfs".into(),
            flags: nosuid_noexec_nodev,
            data: Some("mode=1777,size=65536k".into()),
            create: Create::Dir,
        });

        for bind in &self.readonly_binds {
            let destination = bind.destination.strip_prefix("/").map_err(|_| {
                Error::msg(format!(
                    "bind destination {} must be absolute",
                    bind.destination.display()
                ))
            })?;
            let create = if bind.source.is_dir() { Create::Dir } else { Create::File };
            ops.push(MountOp::Bind {
                source: bind.source.clone(),
                target: rootfs.join(destination),
                recursive: true,
                readonly: true,
                create,
            });
        }

        ops.push(MountOp::PivotRoot { new_root: rootfs.to_path_buf() });

        Ok(MountPlan { ops })
    }
}

/// The mount table an OCI bundle asks for.
///
/// Unlike [`StandardMounts`], nothing here is quilt's idea of a sensible
/// container: every filesystem, every option string and every masked path comes
/// out of `config.json`, because the caller is entitled to decide those.
pub struct OciMounts {
    mounts: Vec<OciMount>,
    masked_paths: Vec<PathBuf>,
    readonly_paths: Vec<PathBuf>,
    mount_label: Option<String>,
    readonly_root: bool,
}

/// One entry of the config's mount list, reduced to what `prepare` needs.
struct OciMount {
    destination: PathBuf,
    kind: Option<String>,
    source: Option<String>,
    options: Vec<String>,
}

impl OciMounts {
    pub fn new(config: &spec::Config) -> Self {
        Self {
            mounts: config
                .mounts
                .iter()
                .map(|m| OciMount {
                    destination: m.destination.clone(),
                    kind: m.kind.clone(),
                    source: m.source.clone(),
                    options: m.options.clone(),
                })
                .collect(),
            masked_paths: config.linux.masked_paths.clone(),
            readonly_paths: config.linux.readonly_paths.clone(),
            mount_label: config.linux.mount_label.clone(),
            readonly_root: config.root.readonly,
        }
    }
}

impl MountStrategy for OciMounts {
    fn prepare(&self, rootfs: &Path) -> Result<MountPlan> {
        if !rootfs.is_absolute() {
            return Err(Error::msg(format!("rootfs {} must be absolute", rootfs.display())));
        }

        let mut ops = vec![
            MountOp::Propagation {
                target: PathBuf::from("/"),
                flags: MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            },
            MountOp::Bind {
                source: rootfs.to_path_buf(),
                target: rootfs.to_path_buf(),
                recursive: true,
                readonly: false,
                create: Create::Nothing,
            },
        ];

        for mount in &self.mounts {
            ops.push(self.op_for(mount, rootfs)?);
        }

        // After the bundle's own mounts, so that the tmpfs on /dev is there to
        // put them in, and any devpts is mounted for /dev/ptmx to point at.
        if self.mounts.iter().any(|m| m.destination == Path::new("/dev")) {
            ops.extend(default_devices(rootfs));
            if self.mounts.iter().any(|m| m.destination == Path::new("/dev/pts")) {
                ops.push(MountOp::Symlink {
                    original: "pts/ptmx".into(),
                    link: rootfs.join("dev/ptmx"),
                });
            }
        }

        ops.push(MountOp::PivotRoot { new_root: rootfs.to_path_buf() });

        // Masked and read-only paths name locations inside the container, so
        // they only mean anything once the pivot has happened.
        for path in &self.masked_paths {
            ops.push(MountOp::Mask { path: path.clone() });
        }
        for path in &self.readonly_paths {
            ops.push(MountOp::Freeze { path: path.clone() });
        }
        if self.readonly_root {
            ops.push(MountOp::Freeze { path: PathBuf::from("/") });
        }

        Ok(MountPlan { ops })
    }
}

impl OciMounts {
    fn op_for(&self, mount: &OciMount, rootfs: &Path) -> Result<MountOp> {
        let destination = mount.destination.strip_prefix("/").map_err(|_| {
            Error::msg(format!(
                "mount destination {} must be absolute",
                mount.destination.display()
            ))
        })?;
        let target = rootfs.join(destination);
        let (flags, propagation, data) = parse_options(&mount.options);

        let kind = mount.kind.as_deref().unwrap_or("none");
        if kind == "bind" || flags.contains(MountFlags::BIND) {
            let source = mount
                .source
                .as_deref()
                .ok_or_else(|| Error::msg(format!("bind to {} has no source", target.display())))?;
            let source = PathBuf::from(source);
            let create = if source.is_dir() { Create::Dir } else { Create::File };

            return Ok(MountOp::Bind {
                source,
                target,
                recursive: propagation.is_some_and(|p| p.contains(MountPropagationFlags::REC))
                    || flags.contains(MountFlags::REC),
                readonly: flags.contains(MountFlags::RDONLY),
                create,
            });
        }

        // The OCI type "cgroup" predates the unified hierarchy. With cgroup v2
        // there is one filesystem and it is called cgroup2; mounting the v1
        // "cgroup" type here would fail on a v2-only host.
        let fstype = if kind == "cgroup" { "cgroup2" } else { kind };

        Ok(MountOp::Filesystem {
            source: mount.source.clone().unwrap_or_else(|| kind.to_string()),
            target,
            fstype: fstype.to_string(),
            flags,
            data: self.data_for(fstype, data),
            create: Create::Dir,
        })
    }

    /// `linux.mountLabel` is an SELinux context, and applying it is nothing
    /// more than passing `context=` through to `mount(2)`. Only the filesystems
    /// quilt creates take it; a bind inherits the label of what it binds, and
    /// proc and sysfs have labels of their own.
    fn data_for(&self, fstype: &str, mut data: Vec<String>) -> Option<String> {
        // Not mqueue: it rejects the option outright with EINVAL, which surfaces
        // as an unexplained mount failure several steps into the plan. SELinux
        // only accepts a mount-point label on filesystems it can label that
        // way, and mqueue is not one of them.
        const LABELLED: &[&str] = &["tmpfs", "devpts"];

        if let Some(label) = &self.mount_label
            && LABELLED.contains(&fstype)
        {
            data.push(format!("context=\"{label}\""));
        }
        (!data.is_empty()).then(|| data.join(","))
    }
}

/// Binds the host's device nodes into the container's `/dev`.
fn default_devices(rootfs: &Path) -> Vec<MountOp> {
    let mut ops = Vec::new();

    for device in OCI_DEFAULT_DEVICES {
        ops.push(MountOp::Bind {
            source: PathBuf::from("/dev").join(device),
            target: rootfs.join("dev").join(device),
            recursive: false,
            readonly: false,
            create: Create::File,
        });
    }
    for (original, link) in DEV_SYMLINKS {
        ops.push(MountOp::Symlink {
            original: (*original).into(),
            link: rootfs.join("dev").join(link),
        });
    }
    ops
}

/// Splits an OCI mount's option strings into mount flags, propagation flags,
/// and the filesystem-specific data that is left over.
///
/// Anything unrecognised is data, not an error: `mode=0755`, `newinstance` and
/// `ptmxmode=0666` are all filesystem options, and a runtime has no business
/// keeping a list of every option every filesystem accepts.
fn parse_options(options: &[String]) -> (MountFlags, Option<MountPropagationFlags>, Vec<String>) {
    let mut flags = MountFlags::empty();
    let mut propagation: Option<MountPropagationFlags> = None;
    let mut data = Vec::new();

    for option in options {
        let set = |flags: &mut MountFlags, flag| *flags |= flag;
        let clear = |flags: &mut MountFlags, flag| flags.remove(flag);

        match option.as_str() {
            "ro" => set(&mut flags, MountFlags::RDONLY),
            "rw" => clear(&mut flags, MountFlags::RDONLY),
            "nosuid" => set(&mut flags, MountFlags::NOSUID),
            "suid" => clear(&mut flags, MountFlags::NOSUID),
            "noexec" => set(&mut flags, MountFlags::NOEXEC),
            "exec" => clear(&mut flags, MountFlags::NOEXEC),
            "nodev" => set(&mut flags, MountFlags::NODEV),
            "dev" => clear(&mut flags, MountFlags::NODEV),
            "noatime" => set(&mut flags, MountFlags::NOATIME),
            "atime" => clear(&mut flags, MountFlags::NOATIME),
            "nodiratime" => set(&mut flags, MountFlags::NODIRATIME),
            "diratime" => clear(&mut flags, MountFlags::NODIRATIME),
            "relatime" => set(&mut flags, MountFlags::RELATIME),
            "strictatime" => set(&mut flags, MountFlags::STRICTATIME),
            "nosymfollow" => set(&mut flags, MountFlags::NOSYMFOLLOW),
            "sync" => set(&mut flags, MountFlags::SYNCHRONOUS),
            "dirsync" => set(&mut flags, MountFlags::DIRSYNC),
            "lazytime" => set(&mut flags, MountFlags::LAZYTIME),
            "bind" => set(&mut flags, MountFlags::BIND),
            "rbind" => {
                set(&mut flags, MountFlags::BIND);
                set(&mut flags, MountFlags::REC);
            }
            "private" => propagation = Some(MountPropagationFlags::PRIVATE),
            "rprivate" => {
                propagation = Some(MountPropagationFlags::PRIVATE | MountPropagationFlags::REC)
            }
            "shared" => propagation = Some(MountPropagationFlags::SHARED),
            "rshared" => {
                propagation = Some(MountPropagationFlags::SHARED | MountPropagationFlags::REC)
            }
            "slave" => propagation = Some(MountPropagationFlags::DOWNSTREAM),
            "rslave" => {
                propagation = Some(MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC)
            }
            "unbindable" => propagation = Some(MountPropagationFlags::UNBINDABLE),
            "runbindable" => {
                propagation = Some(MountPropagationFlags::UNBINDABLE | MountPropagationFlags::REC)
            }
            other => data.push(other.to_string()),
        }
    }

    (flags, propagation, data)
}

impl MountPlan {
    pub fn apply(&self) -> Result<()> {
        for op in &self.ops {
            apply_op(op)?;
        }
        Ok(())
    }
}

fn apply_op(op: &MountOp) -> Result<()> {
    match op {
        MountOp::Propagation { target, flags } => mount::mount_change(target, *flags)
            .context(|| format!("setting propagation on {}", target.display())),

        MountOp::Filesystem { source, target, fstype, flags, data, create } => {
            ensure_target(target, *create)?;
            let data = data.as_deref().map(std::ffi::CString::new).transpose().map_err(|_| {
                Error::msg(format!("mount data for {} contains a NUL", target.display()))
            })?;
            mount::mount(source.as_str(), target, fstype.as_str(), *flags, data.as_deref())
                .context(|| format!("mounting {fstype} on {}", target.display()))
        }

        MountOp::Bind { source, target, recursive, readonly, create } => {
            ensure_target(target, *create)?;
            if *recursive {
                mount::mount_bind_recursive(source, target)
            } else {
                mount::mount_bind(source, target)
            }
            .context(|| format!("binding {} to {}", source.display(), target.display()))?;

            if *readonly {
                set_readonly(target, *recursive)?;
            }
            Ok(())
        }

        MountOp::Symlink { original, link } => match std::os::unix::fs::symlink(original, link) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e).context(|| format!("symlinking {}", link.display())),
        },

        MountOp::PivotRoot { new_root } => pivot_root(new_root),

        MountOp::Mask { path } => mask(path),

        MountOp::Freeze { path } => {
            // A path that is not in the image is nothing to protect. runc skips
            // these too: config.json lists the union of what any image might
            // have.
            if !path.exists() {
                return Ok(());
            }
            mount::mount_bind(path, path)
                .context(|| format!("binding {} onto itself", path.display()))?;
            set_readonly(path, false)
        }
    }
}

/// Hides a path from the container: an empty read-only tmpfs over a directory,
/// `/dev/null` over anything else.
fn mask(path: &Path) -> Result<()> {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };

    if metadata.is_dir() {
        let data = std::ffi::CString::new("mode=0755").expect("no interior NUL");
        mount::mount("tmpfs", path, "tmpfs", MountFlags::RDONLY, Some(data.as_c_str()))
            .context(|| format!("masking the directory {}", path.display()))
    } else {
        mount::mount_bind("/dev/null", path).context(|| format!("masking {}", path.display()))
    }
}

/// `pivot_root(".", ".")` with the old root stacked on the new one, then
/// detached. Avoids needing a `put_old` directory inside the image, and unlike
/// `chroot` it actually removes the host tree from the namespace.
fn pivot_root(new_root: &Path) -> Result<()> {
    rustix::process::chdir(new_root).context(|| format!("chdir to {}", new_root.display()))?;
    rustix::process::pivot_root(".", ".").context(|| "pivot_root(\".\", \".\")".to_string())?;
    // The old root is now covering the new one at ".". Detaching it is what
    // makes the host tree unreachable.
    mount::unmount(".", UnmountFlags::DETACH).context(|| "detaching the old root".to_string())?;
    rustix::process::chdir("/").context(|| "chdir to the new root".to_string())
}

/// `struct mount_attr`, `MOUNT_ATTR_SIZE_VER0`. `userns_fd` is what phase 6
/// fills in for idmapped mounts.
#[repr(C, align(8))]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_RDONLY: u64 = 0x1;

/// Marks a mount read-only, and with `recursive` its whole subtree.
///
/// A bind mount cannot be created read-only in one call: the kernel takes
/// MS_RDONLY from the source mount, not from the bind. The classic fix is a
/// second `mount(MS_REMOUNT | MS_BIND | MS_RDONLY)` pass, but that covers only
/// the top mount, and inside a user namespace it must also carry forward every
/// flag the kernel locked on the way in or it fails with a bare EPERM.
///
/// `mount_setattr` only sets an attribute and clears nothing, so no locked flag
/// is at stake, and `AT_RECURSIVE` reaches the submounts in the same call.
fn set_readonly(target: &Path, recursive: bool) -> Result<()> {
    let path = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::msg(format!("{} contains a NUL byte", target.display())))?;
    let attr = MountAttr { attr_set: MOUNT_ATTR_RDONLY, ..MountAttr::default() };
    let flags = if recursive { syscall::AT_RECURSIVE } else { 0 };

    let ret = unsafe {
        syscall::syscall5(
            syscall::SYS_MOUNT_SETATTR,
            syscall::AT_FDCWD,
            path.as_ptr() as u64,
            flags,
            &attr as *const MountAttr as u64,
            size_of::<MountAttr>() as u64,
        )
    };

    syscall::result(ret).map(|_| ()).context(|| format!("setting {} read-only", target.display()))
}

fn ensure_target(target: &Path, create: Create) -> Result<()> {
    match create {
        Create::Nothing => Ok(()),
        Create::Dir => {
            std::fs::create_dir_all(target).context(|| format!("creating {}", target.display()))
        }
        Create::File => {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .context(|| format!("creating {}", parent.display()))?;
            }
            match std::fs::File::create_new(target) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e).context(|| format!("creating {}", target.display())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> MountPlan {
        StandardMounts::new(Vec::new()).prepare(Path::new("/srv/rootfs")).unwrap()
    }

    fn position(plan: &MountPlan, target: &str) -> usize {
        plan.ops
            .iter()
            .position(|op| op.target() == Path::new(target))
            .unwrap_or_else(|| panic!("no op targets {target}"))
    }

    #[test]
    fn root_is_made_private_before_anything_else() {
        let plan = plan();
        assert_eq!(
            plan.ops[0],
            MountOp::Propagation {
                target: PathBuf::from("/"),
                flags: MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            }
        );
    }

    #[test]
    fn rootfs_is_bound_onto_itself_before_any_mount_inside_it() {
        let plan = plan();
        assert_eq!(position(&plan, "/srv/rootfs"), 1);
        assert!(position(&plan, "/srv/rootfs") < position(&plan, "/srv/rootfs/proc"));
    }

    #[test]
    fn pivot_root_is_last() {
        let plan = plan();
        let last = plan.ops.last().unwrap();
        assert_eq!(last, &MountOp::PivotRoot { new_root: PathBuf::from("/srv/rootfs") });
    }

    #[test]
    fn dev_tmpfs_precedes_everything_placed_in_it() {
        let plan = plan();
        let dev = position(&plan, "/srv/rootfs/dev");
        for name in DEVICES {
            assert!(dev < position(&plan, &format!("/srv/rootfs/dev/{name}")));
        }
        assert!(dev < position(&plan, "/srv/rootfs/dev/shm"));
        assert!(dev < position(&plan, "/srv/rootfs/dev/fd"));
    }

    #[test]
    fn every_op_after_the_root_propagation_stays_under_the_rootfs() {
        let plan = plan();
        for op in &plan.ops[1..] {
            assert!(
                op.target().starts_with("/srv/rootfs"),
                "{} escapes the rootfs",
                op.target().display()
            );
        }
    }

    #[test]
    fn proc_and_sysfs_are_nosuid_noexec_nodev() {
        let plan = plan();
        for target in ["/srv/rootfs/proc", "/srv/rootfs/sys"] {
            let MountOp::Filesystem { flags, .. } = &plan.ops[position(&plan, target)] else {
                panic!("{target} is not a filesystem mount");
            };
            assert!(flags.contains(MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV));
        }
    }

    #[test]
    fn readonly_binds_land_inside_the_rootfs_and_are_marked_readonly() {
        let strategy = StandardMounts::new(vec![BindSpec {
            source: PathBuf::from("/etc/resolv.conf"),
            destination: PathBuf::from("/etc/resolv.conf"),
        }]);
        let plan = strategy.prepare(Path::new("/srv/rootfs")).unwrap();
        let op = &plan.ops[position(&plan, "/srv/rootfs/etc/resolv.conf")];
        let MountOp::Bind { readonly, source, .. } = op else {
            panic!("expected a bind");
        };
        assert!(readonly);
        assert_eq!(source, Path::new("/etc/resolv.conf"));
    }

    #[test]
    fn readonly_binds_are_mounted_before_the_pivot() {
        let strategy = StandardMounts::new(vec![BindSpec {
            source: PathBuf::from("/etc/hosts"),
            destination: PathBuf::from("/etc/hosts"),
        }]);
        let plan = strategy.prepare(Path::new("/srv/rootfs")).unwrap();
        let bind = position(&plan, "/srv/rootfs/etc/hosts");
        let pivot = plan.ops.len() - 1;
        assert!(bind < pivot);
    }

    #[test]
    fn mount_attr_matches_mount_attr_size_ver0() {
        assert_eq!(size_of::<MountAttr>(), 32);
        assert_eq!(align_of::<MountAttr>(), 8);
    }

    fn oci_plan() -> MountPlan {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/podman-unconfined.json");
        let json = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is a committed capture: {e}", path.display()));
        let config = spec::Config::parse(&json).unwrap();
        OciMounts::new(&config).prepare(Path::new("/srv/rootfs")).unwrap()
    }

    #[test]
    fn option_words_become_flags_and_the_rest_becomes_data() {
        let options: Vec<String> = ["nosuid", "strictatime", "mode=755", "size=65536k"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (flags, propagation, data) = parse_options(&options);

        assert_eq!(flags, MountFlags::NOSUID | MountFlags::STRICTATIME);
        assert_eq!(propagation, None);
        assert_eq!(data, ["mode=755", "size=65536k"]);
    }

    #[test]
    fn devpts_options_are_data_not_unknown_flags() {
        // newinstance and ptmxmode belong to the filesystem. Treating an
        // unrecognised word as an error would reject a legal bundle.
        let options: Vec<String> = ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "gid=5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (flags, _, data) = parse_options(&options);

        assert_eq!(flags, MountFlags::NOSUID | MountFlags::NOEXEC);
        assert_eq!(data, ["newinstance", "ptmxmode=0666", "gid=5"]);
    }

    #[test]
    fn rw_and_exec_undo_their_negatives() {
        let options: Vec<String> =
            ["ro", "rw", "noexec", "exec"].iter().map(|s| s.to_string()).collect();
        let (flags, _, _) = parse_options(&options);
        assert_eq!(flags, MountFlags::empty());
    }

    #[test]
    fn rbind_is_a_recursive_bind() {
        let (flags, _, _) = parse_options(&["rbind".to_string()]);
        assert!(flags.contains(MountFlags::BIND | MountFlags::REC));
    }

    #[test]
    fn propagation_words_are_kept_apart_from_mount_flags() {
        let (flags, propagation, data) = parse_options(&["rprivate".to_string()]);
        assert_eq!(flags, MountFlags::empty());
        assert_eq!(propagation, Some(MountPropagationFlags::PRIVATE | MountPropagationFlags::REC));
        assert!(data.is_empty());
    }

    #[test]
    fn the_bundle_podman_produces_becomes_a_plan() {
        let plan = oci_plan();

        assert_eq!(
            plan.ops[0],
            MountOp::Propagation {
                target: PathBuf::from("/"),
                flags: MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            }
        );
        assert!(matches!(plan.ops[1], MountOp::Bind { .. }), "the rootfs binds onto itself");
        assert!(plan.ops.iter().any(|op| op.target() == Path::new("/srv/rootfs/proc")));
        assert!(plan.ops.iter().any(|op| op.target() == Path::new("/srv/rootfs/dev/pts")));
    }

    #[test]
    fn the_default_devices_are_created_because_no_bundle_lists_them() {
        let plan = oci_plan();
        for device in OCI_DEFAULT_DEVICES {
            let target = format!("/srv/rootfs/dev/{device}");
            assert!(
                plan.ops.iter().any(|op| op.target() == Path::new(&target)),
                "the runtime spec requires /dev/{device}"
            );
        }
    }

    #[test]
    fn the_default_devices_land_after_the_dev_tmpfs_and_before_the_pivot() {
        let plan = oci_plan();
        let dev = position(&plan, "/srv/rootfs/dev");
        let null = position(&plan, "/srv/rootfs/dev/null");
        let pivot = plan.ops.iter().position(|op| matches!(op, MountOp::PivotRoot { .. })).unwrap();

        assert!(dev < null, "the device nodes need the tmpfs to be there first");
        assert!(null < pivot);
    }

    #[test]
    fn masking_a_path_has_a_dev_null_to_bind_over_it() {
        // The two are connected: `mask` binds /dev/null over a file, so a
        // container with masked paths and no /dev/null cannot be created.
        let plan = oci_plan();
        let null = position(&plan, "/srv/rootfs/dev/null");
        let masked = plan.ops.iter().position(|op| matches!(op, MountOp::Mask { .. })).unwrap();
        assert!(null < masked);
    }

    #[test]
    fn ptmx_points_into_the_devpts_instance() {
        let plan = oci_plan();
        let op = &plan.ops[position(&plan, "/srv/rootfs/dev/ptmx")];
        assert_eq!(
            op,
            &MountOp::Symlink {
                original: "pts/ptmx".into(),
                link: PathBuf::from("/srv/rootfs/dev/ptmx"),
            }
        );
    }

    #[test]
    fn a_bundle_that_does_not_mount_dev_is_left_alone() {
        // Without a tmpfs on /dev the image's own /dev is what the container
        // gets, and binding over it would be quilt inventing policy.
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "mounts": [{"destination": "/proc", "type": "proc", "source": "proc",
                        "options": []}]
        }"#;
        let config = spec::Config::parse(json).unwrap();
        let plan = OciMounts::new(&config).prepare(Path::new("/srv/rootfs")).unwrap();
        assert!(!plan.ops.iter().any(|op| op.target() == Path::new("/srv/rootfs/dev/null")));
    }

    #[test]
    fn mqueue_is_not_given_an_selinux_context() {
        // It answers EINVAL, which arrives as an unexplained mount failure
        // partway through the plan.
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "mounts": [
                {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []},
                {"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue",
                 "options": ["nosuid", "noexec", "nodev"]}
            ],
            "linux": {"mountLabel": "system_u:object_r:container_file_t:s0:c1,c2"}
        }"#;
        let config = spec::Config::parse(json).unwrap();
        let plan = OciMounts::new(&config).prepare(Path::new("/srv/rootfs")).unwrap();

        let op = &plan.ops[position(&plan, "/srv/rootfs/dev/mqueue")];
        let MountOp::Filesystem { data, .. } = op else { panic!("expected a filesystem") };
        assert_eq!(*data, None);

        // The tmpfs still gets it.
        let dev = &plan.ops[position(&plan, "/srv/rootfs/dev")];
        let MountOp::Filesystem { data, .. } = dev else { panic!("expected a filesystem") };
        assert!(data.as_deref().unwrap().contains("context="));
    }

    #[test]
    fn the_oci_cgroup_type_becomes_cgroup2() {
        let plan = oci_plan();
        let op = plan
            .ops
            .iter()
            .find(|op| op.target() == Path::new("/srv/rootfs/sys/fs/cgroup"))
            .expect("podman mounts the cgroup hierarchy");

        let MountOp::Filesystem { fstype, .. } = op else { panic!("expected a filesystem") };
        assert_eq!(fstype, "cgroup2", "the v1 type would fail on a unified host");
    }

    #[test]
    fn masked_and_readonly_paths_come_after_the_pivot() {
        let plan = oci_plan();
        let pivot = plan
            .ops
            .iter()
            .position(|op| matches!(op, MountOp::PivotRoot { .. }))
            .expect("the plan pivots");

        let masked = plan.ops.iter().position(|op| matches!(op, MountOp::Mask { .. })).unwrap();
        let frozen = plan.ops.iter().position(|op| matches!(op, MountOp::Freeze { .. })).unwrap();

        assert!(pivot < masked, "a masked path names a location inside the container");
        assert!(pivot < frozen);
        assert!(plan.ops.iter().any(|op| op.target() == Path::new("/proc/kcore")));
    }

    #[test]
    fn the_mount_label_reaches_the_filesystems_that_take_one() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs"},
            "mounts": [
                {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                 "options": ["mode=755"]},
                {"destination": "/proc", "type": "proc", "source": "proc", "options": []}
            ],
            "linux": {"mountLabel": "system_u:object_r:container_file_t:s0:c1,c2"}
        }"#;
        let config = spec::Config::parse(json).unwrap();
        let plan = OciMounts::new(&config).prepare(Path::new("/srv/rootfs")).unwrap();

        let tmpfs = plan.ops.iter().find(|op| op.target() == Path::new("/srv/rootfs/dev")).unwrap();
        let MountOp::Filesystem { data, .. } = tmpfs else { panic!("expected a filesystem") };
        let data = data.as_deref().unwrap();
        assert!(data.contains("mode=755"));
        assert!(data.contains(r#"context="system_u:object_r:container_file_t:s0:c1,c2""#));

        // proc carries its own label; handing it a context= would be wrong.
        let proc = plan.ops.iter().find(|op| op.target() == Path::new("/srv/rootfs/proc")).unwrap();
        let MountOp::Filesystem { data, .. } = proc else { panic!("expected a filesystem") };
        assert_eq!(*data, None);
    }

    #[test]
    fn a_readonly_root_is_frozen_last() {
        let json = r#"{
            "ociVersion": "1.2.1",
            "process": {"args": ["true"]},
            "root": {"path": "/rootfs", "readonly": true},
            "mounts": []
        }"#;
        let config = spec::Config::parse(json).unwrap();
        let plan = OciMounts::new(&config).prepare(Path::new("/srv/rootfs")).unwrap();
        assert_eq!(plan.ops.last(), Some(&MountOp::Freeze { path: PathBuf::from("/") }));
    }

    #[test]
    fn a_relative_rootfs_is_rejected() {
        assert!(StandardMounts::new(Vec::new()).prepare(Path::new("rootfs")).is_err());
    }

    #[test]
    fn a_relative_bind_destination_is_rejected() {
        let strategy = StandardMounts::new(vec![BindSpec {
            source: PathBuf::from("/etc/hosts"),
            destination: PathBuf::from("etc/hosts"),
        }]);
        assert!(strategy.prepare(Path::new("/srv/rootfs")).is_err());
    }
}
