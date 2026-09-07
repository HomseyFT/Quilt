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
    Propagation { target: PathBuf, flags: MountPropagationFlags },
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
    Symlink { original: String, link: PathBuf },
    PivotRoot { new_root: PathBuf },
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

        let nosuid_noexec_nodev =
            MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;
        let mut ops = Vec::new();

        // Nothing done below may propagate back to the host. This has to be
        // first, and it has to be recursive.
        ops.push(MountOp::Propagation {
            target: PathBuf::from("/"),
            flags: MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        });

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

        MountOp::Symlink { original, link } => {
            match std::os::unix::fs::symlink(original, link) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e).context(|| format!("symlinking {}", link.display())),
            }
        }

        MountOp::PivotRoot { new_root } => pivot_root(new_root),
    }
}

/// `pivot_root(".", ".")` with the old root stacked on the new one, then
/// detached. Avoids needing a `put_old` directory inside the image, and unlike
/// `chroot` it actually removes the host tree from the namespace.
fn pivot_root(new_root: &Path) -> Result<()> {
    rustix::process::chdir(new_root)
        .context(|| format!("chdir to {}", new_root.display()))?;
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

    syscall::result(ret)
        .map(|_| ())
        .context(|| format!("setting {} read-only", target.display()))
}

fn ensure_target(target: &Path, create: Create) -> Result<()> {
    match create {
        Create::Nothing => Ok(()),
        Create::Dir => std::fs::create_dir_all(target)
            .context(|| format!("creating {}", target.display())),
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
