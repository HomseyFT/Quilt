//! Namespace flags and the `clone3` call that creates them.
//!
//! `rustix` deliberately does not wrap `clone3` (see its `not_implemented!`
//! list), so the syscall is issued here by hand. That is on-theme: the shape of
//! `struct clone_args` is the interface this project exists to learn.

use crate::error::{Context, Error, Result};
use crate::syscall;
use rustix::process::Pid;
use std::os::fd::{AsRawFd, BorrowedFd};

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Births the child directly inside a cgroup named by a descriptor, rather than
/// writing its pid to `cgroup.procs` after the fact.
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

const SIGCHLD: u64 = 17;

/// Which namespaces the container gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Namespaces {
    pub mount: bool,
    pub pid: bool,
    pub net: bool,
    pub uts: bool,
    pub ipc: bool,
    pub user: bool,
    pub cgroup: bool,
}

impl Namespaces {
    /// The phase 1 set: everything the spec lists, minus the cgroup namespace,
    /// which only becomes interesting once phase 2 has a scope to hide.
    pub const DEFAULT: Self = Self {
        mount: true,
        pid: true,
        net: true,
        uts: true,
        ipc: true,
        user: true,
        cgroup: false,
    };

    pub fn clone_flags(&self) -> u64 {
        let mut flags = 0;
        // CLONE_NEWUSER is listed first only for readability; the kernel creates
        // the user namespace first regardless, which is what lets an
        // unprivileged caller ask for the rest in the same call.
        if self.user {
            flags |= CLONE_NEWUSER;
        }
        if self.mount {
            flags |= CLONE_NEWNS;
        }
        if self.pid {
            flags |= CLONE_NEWPID;
        }
        if self.net {
            flags |= CLONE_NEWNET;
        }
        if self.uts {
            flags |= CLONE_NEWUTS;
        }
        if self.ipc {
            flags |= CLONE_NEWIPC;
        }
        if self.cgroup {
            flags |= CLONE_NEWCGROUP;
        }
        flags
    }
}

/// `struct clone_args` as of `CLONE_ARGS_SIZE_VER2`.
///
/// The kernel reads `size` bytes and rejects a size it does not recognise, so
/// the field order and the trailing `cgroup` member both matter.
#[repr(C, align(8))]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

impl CloneArgs {
    pub fn new(flags: u64) -> Self {
        Self { flags, exit_signal: SIGCHLD, ..Self::default() }
    }

    /// Puts the child in `cgroup` at birth.
    ///
    /// The alternative — clone, then write the child's pid to `cgroup.procs` —
    /// leaves a window in which the workload is running under no limits at all.
    /// That window is not hypothetical for a fork bomb or a large allocation in
    /// the first milliseconds.
    ///
    /// This is why `CloneArgs` is `CLONE_ARGS_SIZE_VER2`: 88 bytes is exactly
    /// the version that added the `cgroup` member.
    pub fn into_cgroup(mut self, cgroup: BorrowedFd<'_>) -> Self {
        self.flags |= CLONE_INTO_CGROUP;
        self.cgroup = cgroup.as_raw_fd() as u64;
        self
    }
}

pub enum Fork {
    Parent(Pid),
    Child,
}

/// `clone3(&args, sizeof args)`.
///
/// # Safety
///
/// `args.stack` must be zero, so the child shares fork semantics: it gets a
/// copy-on-write image of this process and returns from here on its own stack.
/// Between that return and `execve` the child is subject to the usual post-fork
/// restrictions — no allocation, no locks, nothing another thread could have
/// held. Callers must keep that window to `read` and `execve`.
pub unsafe fn clone3(args: &CloneArgs) -> Result<Fork> {
    debug_assert_eq!(args.stack, 0, "clone3 here relies on fork semantics");

    let ret = unsafe {
        syscall::syscall2(
            syscall::SYS_CLONE3,
            args as *const CloneArgs as u64,
            size_of::<CloneArgs>() as u64,
        )
    };

    // The errno stays structured: EPERM means user namespaces are off, EUSERS
    // means the nesting limit, and phase 4 has to tell those apart.
    let pid = syscall::result(ret)
        .context(|| format!("clone3 with namespace flags {:#x}", args.flags))?;

    if pid == 0 {
        return Ok(Fork::Child);
    }
    Pid::from_raw(pid as i32)
        .map(Fork::Parent)
        .ok_or_else(|| Error::msg(format!("clone3 returned an invalid pid {pid}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_is_the_six_namespaces_phase_one_promises() {
        assert_eq!(
            Namespaces::DEFAULT.clone_flags(),
            CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC
        );
    }

    #[test]
    fn cgroup_namespace_is_off_until_phase_two() {
        assert_eq!(Namespaces::DEFAULT.clone_flags() & CLONE_NEWCGROUP, 0);
    }

    #[test]
    fn empty_set_asks_for_nothing() {
        let none = Namespaces {
            mount: false,
            pid: false,
            net: false,
            uts: false,
            ipc: false,
            user: false,
            cgroup: false,
        };
        assert_eq!(none.clone_flags(), 0);
    }

    #[test]
    fn clone_args_matches_clone_args_size_ver2() {
        assert_eq!(size_of::<CloneArgs>(), 88);
        assert_eq!(align_of::<CloneArgs>(), 8);
    }

    #[test]
    fn a_scope_descriptor_sets_the_flag_and_the_cgroup_member() {
        // SAFETY: the fd is never used, only recorded in the struct.
        let fd = unsafe { BorrowedFd::borrow_raw(7) };
        let args = CloneArgs::new(CLONE_NEWPID).into_cgroup(fd);

        assert_eq!(args.cgroup, 7);
        assert_eq!(args.flags, CLONE_NEWPID | CLONE_INTO_CGROUP);
    }

    #[test]
    fn without_a_scope_the_cgroup_member_stays_zero() {
        let args = CloneArgs::new(CLONE_NEWPID);
        assert_eq!(args.cgroup, 0);
        assert_eq!(args.flags & CLONE_INTO_CGROUP, 0);
    }

    #[test]
    fn new_requests_sigchld_so_waitpid_works() {
        assert_eq!(CloneArgs::new(0).exit_signal, SIGCHLD);
        assert_eq!(CloneArgs::new(0).stack, 0);
    }
}
