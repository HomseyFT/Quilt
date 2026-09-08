//! Raw syscalls for the interfaces `rustix` does not wrap.
//!
//! `clone3`, `close_range` and `mount_setattr` all sit on rustix's
//! `not_implemented!` list. The register convention is written out once here;
//! the typed wrappers live next to the code that uses them.

use rustix::io::Errno;

pub const SYS_CLONE3: u64 = 435;
pub const SYS_CLOSE_RANGE: u64 = 436;
pub const SYS_MOUNT_SETATTR: u64 = 442;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_SECCOMP: u64 = 317;

/// `prctl` option: remove one capability from the bounding set.
pub const PR_CAPBSET_DROP: u64 = 24;

pub const AT_FDCWD: u64 = -100i64 as u64;
pub const AT_RECURSIVE: u64 = 0x8000;

/// Splits a raw syscall return into a value or an errno. The kernel returns
/// `-errno` in the same register as the result, and no valid return lands in
/// the last page of the address space.
pub fn result(ret: i64) -> Result<i64, Errno> {
    if (-4095..0).contains(&ret) { Err(Errno::from_raw_os_error(-ret as i32)) } else { Ok(ret) }
}

/// # Safety
///
/// Issues an arbitrary syscall. The caller is responsible for the number, the
/// arguments and anything the kernel does with them.
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

/// # Safety
///
/// See [`syscall2`].
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

/// # Safety
///
/// See [`syscall2`]. Note the fourth argument goes in `r10`, not `rcx`: the
/// `syscall` instruction clobbers `rcx` with the return address.
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

/// `close_range(first, last, flags)` — closes every descriptor in the range.
///
/// # Safety
///
/// Closes descriptors this process may not own. Only safe where nothing else
/// will use them again, which in practice means immediately before `execve`.
pub unsafe fn close_range(first: u32, last: u32, flags: u32) -> Result<(), Errno> {
    let ret =
        unsafe { syscall3(SYS_CLOSE_RANGE, u64::from(first), u64::from(last), u64::from(flags)) };
    result(ret).map(|_| ())
}

/// `prctl(option, arg2, 0, 0, 0)`.
///
/// rustix wraps most of `prctl`, but its capability calls are keyed by a
/// `Capability` enum, and quilt works in the raw numbers the OCI spec's
/// capability names map onto. The unused arguments are passed as zero rather
/// than left undefined: several options do read them.
pub fn prctl_2(option: u64, arg2: u64) -> Result<(), Errno> {
    let ret = unsafe { syscall5(SYS_PRCTL, option, arg2, 0, 0, 0) };
    result(ret).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_errno_return_becomes_an_error() {
        assert_eq!(result(-1), Err(Errno::PERM));
        assert_eq!(result(-13), Err(Errno::ACCESS));
    }

    #[test]
    fn a_value_return_passes_through() {
        assert_eq!(result(0), Ok(0));
        assert_eq!(result(16287), Ok(16287));
    }

    #[test]
    fn a_return_below_the_errno_window_is_a_value_not_an_error() {
        // -4096 and below are legitimate results, e.g. from mmap.
        assert_eq!(result(-4096), Ok(-4096));
    }
}
