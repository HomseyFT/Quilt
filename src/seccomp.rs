//! A classic-BPF assembler, and the seccomp filters built with it.
//!
//! No `libseccomp`. The filter is assembled instruction by instruction, which
//! is the single most on-theme piece of work in the project: a seccomp program
//! is a tiny virtual machine's worth of code, and the interesting failures are
//! all in how it is laid out rather than in any one syscall.

use crate::error::{Error, Result};

// Classic BPF opcodes, as `BPF_CLASS | BPF_SIZE | BPF_MODE`.
/// `BPF_LD | BPF_W | BPF_ABS` — load a 32-bit word from the seccomp data.
const LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
const JMP_JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JGE | BPF_K`.
const JMP_JGE_K: u16 = 0x35;
/// `BPF_RET | BPF_K`.
const RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARGS: u32 = 16;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// x86-64 exposes the x32 ABI under the same `AUDIT_ARCH_X86_64` value, with
/// this bit set in the syscall number. Checking the architecture alone would
/// let an x32 caller reach the allowlist with numbers that mean something else.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// The mask the kernel applies to pull the errno out of a `SECCOMP_RET_ERRNO`.
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

/// `struct sock_filter`, the one instruction a classic-BPF program is made of.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// A jump destination, resolved once the program is laid out.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// The instruction after this one.
    Next,
    Label(Label),
}

/// A position in the program that jumps can name before it exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(usize);

enum Emit {
    Stmt(Instruction),
    Jump { code: u16, k: u32, jt: Target, jf: Target },
}

/// Builds a program, resolving forward jumps at the end.
///
/// Classic BPF jumps are relative offsets counted from the *following*
/// instruction and held in a single byte, so they only go forward and only 255
/// instructions at a time. Both limits are real, and both are checked here
/// rather than discovered when the kernel rejects the program.
#[derive(Default)]
pub struct Assembler {
    code: Vec<Emit>,
    labels: Vec<Option<usize>>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves a label. It must be placed before the program is assembled.
    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    /// Binds a label to the next instruction emitted.
    pub fn place(&mut self, label: Label) {
        self.labels[label.0] = Some(self.code.len());
    }

    pub fn stmt(&mut self, code: u16, k: u32) {
        self.code.push(Emit::Stmt(Instruction { code, jt: 0, jf: 0, k }));
    }

    pub fn jump(&mut self, code: u16, k: u32, jt: Target, jf: Target) {
        self.code.push(Emit::Jump { code, k, jt, jf });
    }

    /// Loads the syscall number into the accumulator.
    pub fn load_nr(&mut self) {
        self.stmt(LD_W_ABS, DATA_NR);
    }

    /// Loads the architecture token into the accumulator.
    pub fn load_arch(&mut self) {
        self.stmt(LD_W_ABS, DATA_ARCH);
    }

    /// Loads one 32-bit half of a syscall argument.
    ///
    /// `seccomp_data.args` is an array of 64-bit values and BPF only works in
    /// 32-bit words, so every argument comparison is two comparisons.
    pub fn load_arg_half(&mut self, index: u32, high: bool) {
        self.stmt(LD_W_ABS, DATA_ARGS + index * 8 + if high { 4 } else { 0 });
    }

    pub fn ret(&mut self, action: u32) {
        self.stmt(RET_K, action);
    }

    /// Jumps to `equal` when the accumulator holds `k`, and to `differs`
    /// otherwise.
    pub fn if_eq(&mut self, k: u32, equal: Target, differs: Target) {
        self.jump(JMP_JEQ_K, k, equal, differs);
    }

    /// Jumps to `at_least` when the accumulator is `k` or more.
    pub fn if_ge(&mut self, k: u32, at_least: Target, below: Target) {
        self.jump(JMP_JGE_K, k, at_least, below);
    }

    pub fn assemble(self) -> Result<Vec<Instruction>> {
        let total = self.code.len();
        let mut out = Vec::with_capacity(total);

        for (index, emit) in self.code.iter().enumerate() {
            match emit {
                Emit::Stmt(instruction) => out.push(*instruction),
                Emit::Jump { code, k, jt, jf } => out.push(Instruction {
                    code: *code,
                    jt: self.offset(index, *jt)?,
                    jf: self.offset(index, *jf)?,
                    k: *k,
                }),
            }
        }
        Ok(out)
    }

    fn offset(&self, from: usize, target: Target) -> Result<u8> {
        let to = match target {
            Target::Next => return Ok(0),
            Target::Label(Label(id)) => self.labels[id]
                .ok_or_else(|| Error::msg(format!("label {id} was never placed")))?,
        };

        // The offset counts from the instruction after the jump.
        let distance = (to as isize) - (from as isize) - 1;
        if distance < 0 {
            return Err(Error::msg(
                "classic BPF cannot jump backwards, which is what keeps a filter finite"
                    .to_string(),
            ));
        }
        u8::try_from(distance).map_err(|_| {
            Error::msg(format!(
                "a jump of {distance} instructions does not fit in a byte; \
                 the filter needs breaking up"
            ))
        })
    }
}

/// The x86-64 syscall table, from `asm/unistd_64.h`.
///
/// Names the kernel does not have on this architecture are not an error: a
/// profile written for several architectures lists all their names, and 79 of
/// the 432 podman sends are 32-bit or x32 spellings like `chown32`. Those are
/// refused by the architecture check regardless.
const SYSCALLS: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("open", 2),
    ("close", 3),
    ("stat", 4),
    ("fstat", 5),
    ("lstat", 6),
    ("poll", 7),
    ("lseek", 8),
    ("mmap", 9),
    ("mprotect", 10),
    ("munmap", 11),
    ("brk", 12),
    ("rt_sigaction", 13),
    ("rt_sigprocmask", 14),
    ("rt_sigreturn", 15),
    ("ioctl", 16),
    ("pread64", 17),
    ("pwrite64", 18),
    ("readv", 19),
    ("writev", 20),
    ("access", 21),
    ("pipe", 22),
    ("select", 23),
    ("sched_yield", 24),
    ("mremap", 25),
    ("msync", 26),
    ("mincore", 27),
    ("madvise", 28),
    ("shmget", 29),
    ("shmat", 30),
    ("shmctl", 31),
    ("dup", 32),
    ("dup2", 33),
    ("pause", 34),
    ("nanosleep", 35),
    ("getitimer", 36),
    ("alarm", 37),
    ("setitimer", 38),
    ("getpid", 39),
    ("sendfile", 40),
    ("socket", 41),
    ("connect", 42),
    ("accept", 43),
    ("sendto", 44),
    ("recvfrom", 45),
    ("sendmsg", 46),
    ("recvmsg", 47),
    ("shutdown", 48),
    ("bind", 49),
    ("listen", 50),
    ("getsockname", 51),
    ("getpeername", 52),
    ("socketpair", 53),
    ("setsockopt", 54),
    ("getsockopt", 55),
    ("clone", 56),
    ("fork", 57),
    ("vfork", 58),
    ("execve", 59),
    ("exit", 60),
    ("wait4", 61),
    ("kill", 62),
    ("uname", 63),
    ("semget", 64),
    ("semop", 65),
    ("semctl", 66),
    ("shmdt", 67),
    ("msgget", 68),
    ("msgsnd", 69),
    ("msgrcv", 70),
    ("msgctl", 71),
    ("fcntl", 72),
    ("flock", 73),
    ("fsync", 74),
    ("fdatasync", 75),
    ("truncate", 76),
    ("ftruncate", 77),
    ("getdents", 78),
    ("getcwd", 79),
    ("chdir", 80),
    ("fchdir", 81),
    ("rename", 82),
    ("mkdir", 83),
    ("rmdir", 84),
    ("creat", 85),
    ("link", 86),
    ("unlink", 87),
    ("symlink", 88),
    ("readlink", 89),
    ("chmod", 90),
    ("fchmod", 91),
    ("chown", 92),
    ("fchown", 93),
    ("lchown", 94),
    ("umask", 95),
    ("gettimeofday", 96),
    ("getrlimit", 97),
    ("getrusage", 98),
    ("sysinfo", 99),
    ("times", 100),
    ("ptrace", 101),
    ("getuid", 102),
    ("syslog", 103),
    ("getgid", 104),
    ("setuid", 105),
    ("setgid", 106),
    ("geteuid", 107),
    ("getegid", 108),
    ("setpgid", 109),
    ("getppid", 110),
    ("getpgrp", 111),
    ("setsid", 112),
    ("setreuid", 113),
    ("setregid", 114),
    ("getgroups", 115),
    ("setgroups", 116),
    ("setresuid", 117),
    ("getresuid", 118),
    ("setresgid", 119),
    ("getresgid", 120),
    ("getpgid", 121),
    ("setfsuid", 122),
    ("setfsgid", 123),
    ("getsid", 124),
    ("capget", 125),
    ("capset", 126),
    ("rt_sigpending", 127),
    ("rt_sigtimedwait", 128),
    ("rt_sigqueueinfo", 129),
    ("rt_sigsuspend", 130),
    ("sigaltstack", 131),
    ("utime", 132),
    ("mknod", 133),
    ("uselib", 134),
    ("personality", 135),
    ("ustat", 136),
    ("statfs", 137),
    ("fstatfs", 138),
    ("sysfs", 139),
    ("getpriority", 140),
    ("setpriority", 141),
    ("sched_setparam", 142),
    ("sched_getparam", 143),
    ("sched_setscheduler", 144),
    ("sched_getscheduler", 145),
    ("sched_get_priority_max", 146),
    ("sched_get_priority_min", 147),
    ("sched_rr_get_interval", 148),
    ("mlock", 149),
    ("munlock", 150),
    ("mlockall", 151),
    ("munlockall", 152),
    ("vhangup", 153),
    ("modify_ldt", 154),
    ("pivot_root", 155),
    ("_sysctl", 156),
    ("prctl", 157),
    ("arch_prctl", 158),
    ("adjtimex", 159),
    ("setrlimit", 160),
    ("chroot", 161),
    ("sync", 162),
    ("acct", 163),
    ("settimeofday", 164),
    ("mount", 165),
    ("umount2", 166),
    ("swapon", 167),
    ("swapoff", 168),
    ("reboot", 169),
    ("sethostname", 170),
    ("setdomainname", 171),
    ("iopl", 172),
    ("ioperm", 173),
    ("create_module", 174),
    ("init_module", 175),
    ("delete_module", 176),
    ("get_kernel_syms", 177),
    ("query_module", 178),
    ("quotactl", 179),
    ("nfsservctl", 180),
    ("getpmsg", 181),
    ("putpmsg", 182),
    ("afs_syscall", 183),
    ("tuxcall", 184),
    ("security", 185),
    ("gettid", 186),
    ("readahead", 187),
    ("setxattr", 188),
    ("lsetxattr", 189),
    ("fsetxattr", 190),
    ("getxattr", 191),
    ("lgetxattr", 192),
    ("fgetxattr", 193),
    ("listxattr", 194),
    ("llistxattr", 195),
    ("flistxattr", 196),
    ("removexattr", 197),
    ("lremovexattr", 198),
    ("fremovexattr", 199),
    ("tkill", 200),
    ("time", 201),
    ("futex", 202),
    ("sched_setaffinity", 203),
    ("sched_getaffinity", 204),
    ("set_thread_area", 205),
    ("io_setup", 206),
    ("io_destroy", 207),
    ("io_getevents", 208),
    ("io_submit", 209),
    ("io_cancel", 210),
    ("get_thread_area", 211),
    ("lookup_dcookie", 212),
    ("epoll_create", 213),
    ("epoll_ctl_old", 214),
    ("epoll_wait_old", 215),
    ("remap_file_pages", 216),
    ("getdents64", 217),
    ("set_tid_address", 218),
    ("restart_syscall", 219),
    ("semtimedop", 220),
    ("fadvise64", 221),
    ("timer_create", 222),
    ("timer_settime", 223),
    ("timer_gettime", 224),
    ("timer_getoverrun", 225),
    ("timer_delete", 226),
    ("clock_settime", 227),
    ("clock_gettime", 228),
    ("clock_getres", 229),
    ("clock_nanosleep", 230),
    ("exit_group", 231),
    ("epoll_wait", 232),
    ("epoll_ctl", 233),
    ("tgkill", 234),
    ("utimes", 235),
    ("vserver", 236),
    ("mbind", 237),
    ("set_mempolicy", 238),
    ("get_mempolicy", 239),
    ("mq_open", 240),
    ("mq_unlink", 241),
    ("mq_timedsend", 242),
    ("mq_timedreceive", 243),
    ("mq_notify", 244),
    ("mq_getsetattr", 245),
    ("kexec_load", 246),
    ("waitid", 247),
    ("add_key", 248),
    ("request_key", 249),
    ("keyctl", 250),
    ("ioprio_set", 251),
    ("ioprio_get", 252),
    ("inotify_init", 253),
    ("inotify_add_watch", 254),
    ("inotify_rm_watch", 255),
    ("migrate_pages", 256),
    ("openat", 257),
    ("mkdirat", 258),
    ("mknodat", 259),
    ("fchownat", 260),
    ("futimesat", 261),
    ("newfstatat", 262),
    ("unlinkat", 263),
    ("renameat", 264),
    ("linkat", 265),
    ("symlinkat", 266),
    ("readlinkat", 267),
    ("fchmodat", 268),
    ("faccessat", 269),
    ("pselect6", 270),
    ("ppoll", 271),
    ("unshare", 272),
    ("set_robust_list", 273),
    ("get_robust_list", 274),
    ("splice", 275),
    ("tee", 276),
    ("sync_file_range", 277),
    ("vmsplice", 278),
    ("move_pages", 279),
    ("utimensat", 280),
    ("epoll_pwait", 281),
    ("signalfd", 282),
    ("timerfd_create", 283),
    ("eventfd", 284),
    ("fallocate", 285),
    ("timerfd_settime", 286),
    ("timerfd_gettime", 287),
    ("accept4", 288),
    ("signalfd4", 289),
    ("eventfd2", 290),
    ("epoll_create1", 291),
    ("dup3", 292),
    ("pipe2", 293),
    ("inotify_init1", 294),
    ("preadv", 295),
    ("pwritev", 296),
    ("rt_tgsigqueueinfo", 297),
    ("perf_event_open", 298),
    ("recvmmsg", 299),
    ("fanotify_init", 300),
    ("fanotify_mark", 301),
    ("prlimit64", 302),
    ("name_to_handle_at", 303),
    ("open_by_handle_at", 304),
    ("clock_adjtime", 305),
    ("syncfs", 306),
    ("sendmmsg", 307),
    ("setns", 308),
    ("getcpu", 309),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("kcmp", 312),
    ("finit_module", 313),
    ("sched_setattr", 314),
    ("sched_getattr", 315),
    ("renameat2", 316),
    ("seccomp", 317),
    ("getrandom", 318),
    ("memfd_create", 319),
    ("kexec_file_load", 320),
    ("bpf", 321),
    ("execveat", 322),
    ("userfaultfd", 323),
    ("membarrier", 324),
    ("mlock2", 325),
    ("copy_file_range", 326),
    ("preadv2", 327),
    ("pwritev2", 328),
    ("pkey_mprotect", 329),
    ("pkey_alloc", 330),
    ("pkey_free", 331),
    ("statx", 332),
    ("io_pgetevents", 333),
    ("rseq", 334),
    ("uretprobe", 335),
    ("uprobe", 336),
    ("pidfd_send_signal", 424),
    ("io_uring_setup", 425),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("open_tree", 428),
    ("move_mount", 429),
    ("fsopen", 430),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fspick", 433),
    ("pidfd_open", 434),
    ("clone3", 435),
    ("close_range", 436),
    ("openat2", 437),
    ("pidfd_getfd", 438),
    ("faccessat2", 439),
    ("process_madvise", 440),
    ("epoll_pwait2", 441),
    ("mount_setattr", 442),
    ("quotactl_fd", 443),
    ("landlock_create_ruleset", 444),
    ("landlock_add_rule", 445),
    ("landlock_restrict_self", 446),
    ("memfd_secret", 447),
    ("process_mrelease", 448),
    ("futex_waitv", 449),
    ("set_mempolicy_home_node", 450),
    ("cachestat", 451),
    ("fchmodat2", 452),
    ("map_shadow_stack", 453),
    ("futex_wake", 454),
    ("futex_wait", 455),
    ("futex_requeue", 456),
    ("statmount", 457),
    ("listmount", 458),
    ("lsm_get_self_attr", 459),
    ("lsm_set_self_attr", 460),
    ("lsm_list_modules", 461),
    ("mseal", 462),
    ("setxattrat", 463),
    ("getxattrat", 464),
    ("listxattrat", 465),
    ("removexattrat", 466),
    ("open_tree_attr", 467),
    ("file_getattr", 468),
    ("file_setattr", 469),
    ("listns", 470),
];

/// The syscall number for a name, if this architecture has one.
pub fn syscall_number(name: &str) -> Option<u32> {
    SYSCALLS.iter().find(|(known, _)| *known == name).map(|(_, number)| *number)
}

/// Runs a program the way the kernel would, for testing.
///
/// A filter that is subtly wrong still loads, so the only way to know what one
/// decides is to ask it. This is the interpreter that asks.
#[cfg(test)]
pub fn simulate(program: &[Instruction], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let word = |offset: u32| -> u32 {
        match offset {
            DATA_NR => nr,
            DATA_ARCH => arch,
            _ if offset >= DATA_ARGS => {
                let index = ((offset - DATA_ARGS) / 8) as usize;
                let value = args.get(index).copied().unwrap_or(0);
                if (offset - DATA_ARGS) % 8 == 0 {
                    value as u32
                } else {
                    (value >> 32) as u32
                }
            }
            _ => 0,
        }
    };

    let mut accumulator = 0u32;
    let mut pc = 0usize;

    loop {
        let instruction = program.get(pc).expect("a program must end in a return");
        pc += 1;

        match instruction.code {
            LD_W_ABS => accumulator = word(instruction.k),
            JMP_JEQ_K => {
                let taken =
                    if accumulator == instruction.k { instruction.jt } else { instruction.jf };
                pc += taken as usize;
            }
            JMP_JGE_K => {
                let taken =
                    if accumulator >= instruction.k { instruction.jt } else { instruction.jf };
                pc += taken as usize;
            }
            RET_K => return instruction.k,
            other => panic!("the interpreter does not know opcode {other:#x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Compiling a `linux.seccomp` profile into a filter.
// ---------------------------------------------------------------------------

/// The kernel's return value for one of the spec's action names.
fn action_for(name: &str, errno: Option<u32>) -> Result<u32> {
    Ok(match name {
        "SCMP_ACT_ALLOW" => SECCOMP_RET_ALLOW,
        "SCMP_ACT_LOG" => SECCOMP_RET_LOG,
        "SCMP_ACT_TRAP" => SECCOMP_RET_TRAP,
        // Both spellings mean the thread, not the process. The distinction
        // matters: killing one thread of a multi-threaded workload leaves the
        // rest running.
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => SECCOMP_RET_KILL_THREAD,
        "SCMP_ACT_KILL_PROCESS" => SECCOMP_RET_KILL_PROCESS,
        // EPERM by default. The spec's own advice is to prefer an errno over a
        // kill, because a denied syscall surfaces deep inside a program nobody
        // here wrote and a corpse says nothing about which one it was.
        "SCMP_ACT_ERRNO" => SECCOMP_RET_ERRNO | (errno.unwrap_or(1) & SECCOMP_RET_DATA),
        "SCMP_ACT_TRACE" => SECCOMP_RET_TRACE | (errno.unwrap_or(0) & SECCOMP_RET_DATA),
        "SCMP_ACT_NOTIFY" => {
            return Err(Error::msg(
                "config.json asks for SCMP_ACT_NOTIFY, which hands syscalls to a user-space \
                 agent over a descriptor quilt has nobody to send"
                    .to_string(),
            ));
        }
        other => return Err(Error::msg(format!("config.json names an unknown action: {other}"))),
    })
}

/// A comparison the filter can make against one syscall argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Compare {
    Equal,
    NotEqual,
}

fn compare_for(op: &str) -> Result<Compare> {
    Ok(match op {
        "SCMP_CMP_EQ" => Compare::Equal,
        "SCMP_CMP_NE" => Compare::NotEqual,
        // The ordering and masked comparisons need more than the two-word
        // equality test below, and no profile quilt has been given uses them.
        // Refusing names the one that is missing rather than quietly matching
        // nothing, which would turn a deny rule into a no-op.
        other => {
            return Err(Error::msg(format!(
                "config.json uses the argument comparison {other}, which quilt does not build"
            )));
        }
    })
}

/// Assembles a filter for the bundle's profile.
///
/// The architecture check comes first and is not negotiable. `seccomp_data.nr`
/// means nothing without knowing which table it indexes, so a filter that reads
/// the number first is one a caller from another architecture walks straight
/// through — its numbers land on whatever this architecture happens to call
/// them.
pub fn compile(profile: &crate::spec::Seccomp) -> Result<Vec<Instruction>> {
    if !profile.architectures.is_empty()
        && !profile.architectures.iter().any(|a| a == "SCMP_ARCH_X86_64")
    {
        return Err(Error::msg(format!(
            "config.json's seccomp profile covers {:?} but not SCMP_ARCH_X86_64, which is the \
             architecture this container will run on",
            profile.architectures
        )));
    }
    if !profile.flags.is_empty() {
        // SECCOMP_FILTER_FLAG_* changes how the filter is loaded. quilt sets
        // one of them itself, behind --seccomp-log; honouring a bundle's list
        // would mean deciding what each does, and dropping it silently would
        // mean loading a filter that behaves differently from the one asked for.
        return Err(Error::msg(format!(
            "config.json sets the seccomp flags {:?}, which quilt does not pass on",
            profile.flags
        )));
    }
    if profile.listener_metadata.is_some() {
        return Err(Error::msg(
            "config.json sets seccomp listener metadata, which goes with a listener quilt does              not connect to"
                .to_string(),
        ));
    }
    if let Some(path) = &profile.listener_path {
        return Err(Error::msg(format!(
            "config.json points seccomp at the listener {path}, which quilt does not connect to"
        )));
    }

    let default = action_for(&profile.default_action, profile.default_errno_ret)?;

    let mut assembler = Assembler::new();

    // Each check carries its own kill rather than jumping to a shared one at
    // the end. A single exit would be several hundred instructions away by the
    // time the rules are laid out, and a classic-BPF jump offset is one byte —
    // so the tidier arrangement is the one that will not assemble.
    let supported = assembler.label();
    assembler.load_arch();
    assembler.if_eq(AUDIT_ARCH_X86_64, Target::Label(supported), Target::Next);
    assembler.ret(SECCOMP_RET_KILL_PROCESS);
    assembler.place(supported);

    // Same architecture token, different syscall table: x32 numbers carry this
    // bit and would otherwise be compared against x86-64 numbers.
    let native = assembler.label();
    assembler.load_nr();
    assembler.if_ge(X32_SYSCALL_BIT, Target::Next, Target::Label(native));
    assembler.ret(SECCOMP_RET_KILL_PROCESS);
    assembler.place(native);

    for rule in &profile.syscalls {
        let action = action_for(&rule.action, rule.errno_ret)?;
        let comparisons = rule
            .args
            .iter()
            .map(|arg| Ok((arg.index, arg.value, compare_for(&arg.op)?)))
            .collect::<Result<Vec<_>>>()?;

        for name in &rule.names {
            // A name this architecture does not have cannot be called here, and
            // a caller from the architecture that does have it is killed above,
            // so there is nothing to emit and nothing lost by not emitting it.
            let Some(number) = syscall_number(name) else { continue };
            emit_rule(&mut assembler, number, &comparisons, action);
        }
    }

    assembler.ret(default);
    assembler.assemble()
}

/// One syscall's rule: take `action` when the number matches and every argument
/// comparison holds.
fn emit_rule(
    assembler: &mut Assembler,
    number: u32,
    comparisons: &[(u32, u64, Compare)],
    action: u32,
) {
    let done = assembler.label();
    assembler.if_eq(number, Target::Next, Target::Label(done));

    for (index, value, compare) in comparisons {
        let (low, high) = (*value as u32, (*value >> 32) as u32);

        match compare {
            Compare::Equal => {
                assembler.load_arg_half(*index, true);
                assembler.if_eq(high, Target::Next, Target::Label(done));
                assembler.load_arg_half(*index, false);
                assembler.if_eq(low, Target::Next, Target::Label(done));
            }
            Compare::NotEqual => {
                // Unequal in either half is enough, so a difference up top skips
                // the second test rather than failing the rule.
                let differs = assembler.label();
                assembler.load_arg_half(*index, true);
                assembler.if_eq(high, Target::Next, Target::Label(differs));
                assembler.load_arg_half(*index, false);
                assembler.if_eq(low, Target::Label(done), Target::Label(differs));
                assembler.place(differs);
            }
        }
    }

    assembler.ret(action);
    assembler.place(done);

    // Reading an argument leaves it in the accumulator, and every rule after
    // this one expects to find the syscall number there.
    if !comparisons.is_empty() {
        assembler.load_nr();
    }
}

/// `struct sock_fprog`, the handle the kernel is given to the program.
#[repr(C)]
struct Program {
    len: u16,
    filter: *const Instruction,
}

const SECCOMP_SET_MODE_FILTER: u64 = 1;
/// Logs every non-allow decision to the audit log. The spec's own note about
/// this phase is that seccomp debugging is miserable — a denied syscall shows
/// up as an unexplained failure deep inside a program nobody here wrote — and
/// this is what turns it into a line saying which syscall it was.
const SECCOMP_FILTER_FLAG_LOG: u64 = 2;

/// The kernel's ceiling on filter length.
const MAX_INSTRUCTIONS: usize = 4096;

/// Loads the filter into the current process, for good.
///
/// A filter cannot be removed, and it is inherited across `execve`, which is
/// what makes it worth installing immediately before one: everything quilt does
/// to set the container up needs syscalls the container itself must not have.
pub fn install(program: &[Instruction], log: bool) -> Result<()> {
    if program.is_empty() {
        return Err(Error::msg("a seccomp filter cannot be empty".to_string()));
    }
    if program.len() > MAX_INSTRUCTIONS {
        return Err(Error::msg(format!(
            "the filter is {} instructions and the kernel takes at most {MAX_INSTRUCTIONS}",
            program.len()
        )));
    }

    // Without no_new_privs the kernel wants CAP_SYS_ADMIN, and by this point the
    // bundle's capability set has usually taken that away. It is also the right
    // thing on its own: a filter that a setuid binary can escape is not one.
    rustix::thread::set_no_new_privs(true)
        .map_err(|e| Error::from_errno("setting no_new_privs before the seccomp filter", e))?;

    let handle = Program { len: program.len() as u16, filter: program.as_ptr() };
    let flags = if log { SECCOMP_FILTER_FLAG_LOG } else { 0 };

    // SAFETY: `handle` describes `program`, which outlives this call.
    let ret = unsafe {
        crate::syscall::syscall3(
            crate::syscall::SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &handle as *const Program as u64,
        )
    };
    crate::syscall::result(ret)
        .map(|_| ())
        .map_err(|e| Error::from_errno("loading the seccomp filter", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec;

    fn profile(json: &str) -> spec::Seccomp {
        serde_json::from_str(json).expect("a seccomp profile")
    }

    fn podman_profile() -> spec::Seccomp {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/podman-default.json");
        let json = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} is a committed capture: {e}", path.display()));
        spec::Config::parse(&json).unwrap().linux.seccomp.expect("podman sends a profile")
    }

    fn verdict(program: &[Instruction], nr: u32) -> u32 {
        simulate(program, AUDIT_ARCH_X86_64, nr, [0; 6])
    }

    #[test]
    fn the_whole_profile_stays_inside_the_one_byte_jump_range() {
        // Every rule is laid out so that no jump has to reach past the rule it
        // belongs to. Assembling podman's 432-name profile is the test: a
        // shared exit at the end of the program does not fit.
        let program = compile(&podman_profile()).unwrap();
        assert!(program.iter().all(|i| i.jt <= 255 && i.jf <= 255));
        assert!(program.len() > 700, "the profile should assemble to a real filter");
    }

    #[test]
    fn the_kernels_handle_is_a_length_and_a_pointer() {
        assert_eq!(size_of::<Program>(), 16);
        assert_eq!(align_of::<Program>(), 8);
    }

    #[test]
    fn an_empty_or_oversized_filter_is_refused_before_the_kernel_sees_it() {
        assert!(install(&[], false).is_err());
        let huge = vec![Instruction { code: RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW }; 4097];
        assert!(install(&huge, false).is_err());
    }

    #[test]
    fn an_instruction_is_the_kernels_eight_bytes() {
        assert_eq!(size_of::<Instruction>(), 8);
    }

    #[test]
    fn a_jump_offset_counts_from_the_following_instruction() {
        let mut assembler = Assembler::new();
        let target = assembler.label();
        assembler.if_eq(1, Target::Next, Target::Label(target));
        assembler.ret(SECCOMP_RET_ALLOW);
        assembler.place(target);
        assembler.ret(SECCOMP_RET_KILL_PROCESS);

        let program = assembler.assemble().unwrap();
        assert_eq!(program[0].jt, 0, "Next is the instruction straight after");
        assert_eq!(program[0].jf, 1, "one instruction is skipped to reach the label");
    }

    #[test]
    fn a_label_that_was_never_placed_is_an_error() {
        let mut assembler = Assembler::new();
        let nowhere = assembler.label();
        assembler.if_eq(1, Target::Next, Target::Label(nowhere));
        assembler.ret(SECCOMP_RET_ALLOW);
        assert!(assembler.assemble().is_err());
    }

    #[test]
    fn a_backward_jump_is_refused() {
        // Classic BPF only jumps forward, which is what bounds the program.
        let mut assembler = Assembler::new();
        let behind = assembler.label();
        assembler.place(behind);
        assembler.ret(SECCOMP_RET_ALLOW);
        assembler.if_eq(1, Target::Label(behind), Target::Next);
        assembler.ret(SECCOMP_RET_ALLOW);
        assert!(assembler.assemble().is_err());
    }

    #[test]
    fn a_jump_too_far_to_fit_in_a_byte_is_refused() {
        let mut assembler = Assembler::new();
        let far = assembler.label();
        assembler.if_eq(1, Target::Next, Target::Label(far));
        for _ in 0..300 {
            assembler.ret(SECCOMP_RET_ALLOW);
        }
        assembler.place(far);
        assembler.ret(SECCOMP_RET_ALLOW);

        let error = assembler.assemble().unwrap_err().to_string();
        assert!(error.contains("does not fit in a byte"), "{error}");
    }

    #[test]
    fn the_architecture_is_checked_before_the_syscall_number_is_read() {
        // The whole filter rests on this: a syscall number means nothing until
        // you know which table it indexes.
        let program = compile(&profile(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_X86_64"]}"#,
        ))
        .unwrap();

        assert_eq!(program[0].code, LD_W_ABS);
        assert_eq!(program[0].k, DATA_ARCH, "the first load is the architecture");
        assert_eq!(program[1].code, JMP_JEQ_K);
        assert_eq!(program[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(program[2].code, RET_K, "a mismatch is refused before anything else");
        assert_eq!(program[2].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn a_caller_from_another_architecture_is_killed_whatever_the_default_says() {
        let program = compile(&profile(r#"{"defaultAction": "SCMP_ACT_ALLOW"}"#)).unwrap();

        // i386 is AUDIT_ARCH_I386. Its syscall numbers mean other things.
        assert_eq!(simulate(&program, 0x4000_0003, 1, [0; 6]), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(simulate(&program, AUDIT_ARCH_X86_64, 1, [0; 6]), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn an_x32_caller_is_killed_despite_sharing_the_architecture_token() {
        let program = compile(&profile(r#"{"defaultAction": "SCMP_ACT_ALLOW"}"#)).unwrap();
        let write = syscall_number("write").unwrap();

        assert_eq!(verdict(&program, write), SECCOMP_RET_ALLOW);
        assert_eq!(
            simulate(&program, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | write, [0; 6]),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn an_allowlist_allows_what_it_names_and_refuses_the_rest() {
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 38,
                "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]
            }"#,
        ))
        .unwrap();

        assert_eq!(verdict(&program, syscall_number("read").unwrap()), SECCOMP_RET_ALLOW);
        assert_eq!(verdict(&program, syscall_number("write").unwrap()), SECCOMP_RET_ALLOW);
        assert_eq!(
            verdict(&program, syscall_number("ptrace").unwrap()),
            SECCOMP_RET_ERRNO | 38
        );
    }

    #[test]
    fn an_errno_action_defaults_to_eperm() {
        assert_eq!(action_for("SCMP_ACT_ERRNO", None).unwrap(), SECCOMP_RET_ERRNO | 1);
        assert_eq!(action_for("SCMP_ACT_ERRNO", Some(38)).unwrap(), SECCOMP_RET_ERRNO | 38);
    }

    #[test]
    fn an_argument_equality_test_compares_both_halves_of_the_value() {
        // A filter that only compared the low word would let 0x1_0000_0000
        // through as if it were zero. That is exactly the subtly-wrong filter
        // that still loads.
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 38,
                "syscalls": [{
                    "names": ["personality"], "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]
                }]
            }"#,
        ))
        .unwrap();
        let personality = syscall_number("personality").unwrap();

        let with = |value: u64| {
            simulate(&program, AUDIT_ARCH_X86_64, personality, [value, 0, 0, 0, 0, 0])
        };
        assert_eq!(with(0), SECCOMP_RET_ALLOW);
        assert_eq!(with(8), SECCOMP_RET_ERRNO | 38);
        assert_eq!(with(1 << 32), SECCOMP_RET_ERRNO | 38, "the high word was ignored");
    }

    #[test]
    fn a_high_argument_value_is_matched_exactly() {
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{
                    "names": ["personality"], "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 4294967295, "op": "SCMP_CMP_EQ"}]
                }]
            }"#,
        ))
        .unwrap();
        let personality = syscall_number("personality").unwrap();
        let with = |value: u64| {
            simulate(&program, AUDIT_ARCH_X86_64, personality, [value, 0, 0, 0, 0, 0])
        };

        assert_eq!(with(0xffff_ffff), SECCOMP_RET_ALLOW);
        assert_eq!(with(0xffff_ffff_ffff_ffff), SECCOMP_RET_ERRNO | 1);
    }

    #[test]
    fn an_argument_inequality_test_matches_when_either_half_differs() {
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{
                    "names": ["clone"], "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 16, "op": "SCMP_CMP_NE"}]
                }]
            }"#,
        ))
        .unwrap();
        let clone = syscall_number("clone").unwrap();
        let with =
            |value: u64| simulate(&program, AUDIT_ARCH_X86_64, clone, [value, 0, 0, 0, 0, 0]);

        assert_eq!(with(0), SECCOMP_RET_ALLOW);
        assert_eq!(with(16), SECCOMP_RET_ERRNO | 1, "equal, so the rule must not match");
        assert_eq!(with(16 | (1 << 32)), SECCOMP_RET_ALLOW, "differs in the high word");
    }

    #[test]
    fn several_argument_tests_all_have_to_hold() {
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{
                    "names": ["socket"], "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 16, "op": "SCMP_CMP_EQ"},
                             {"index": 2, "value": 9, "op": "SCMP_CMP_EQ"}]
                }]
            }"#,
        ))
        .unwrap();
        let socket = syscall_number("socket").unwrap();
        let with = |a: u64, c: u64| {
            simulate(&program, AUDIT_ARCH_X86_64, socket, [a, 0, c, 0, 0, 0])
        };

        assert_eq!(with(16, 9), SECCOMP_RET_ALLOW);
        assert_eq!(with(16, 0), SECCOMP_RET_ERRNO | 1);
        assert_eq!(with(2, 9), SECCOMP_RET_ERRNO | 1);
    }

    #[test]
    fn a_rule_that_reads_an_argument_leaves_the_number_where_the_next_rule_expects_it() {
        // The accumulator holds the syscall number for every comparison. A rule
        // with arguments overwrites it, and forgetting to put it back makes
        // every later rule test an argument value against a syscall number —
        // which loads, and is wrong.
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    {"names": ["personality"], "action": "SCMP_ACT_ALLOW",
                     "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]},
                    {"names": ["write"], "action": "SCMP_ACT_ALLOW"}
                ]
            }"#,
        ))
        .unwrap();

        assert_eq!(verdict(&program, syscall_number("write").unwrap()), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn names_this_architecture_does_not_have_are_skipped() {
        let program = compile(&profile(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{"names": ["chown32", "write"], "action": "SCMP_ACT_ALLOW"}]
            }"#,
        ))
        .unwrap();
        assert_eq!(verdict(&program, syscall_number("write").unwrap()), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn an_action_or_comparison_quilt_cannot_build_is_refused() {
        assert!(action_for("SCMP_ACT_NOTIFY", None).is_err());
        assert!(action_for("SCMP_ACT_INVENTED", None).is_err());
        assert!(compare_for("SCMP_CMP_MASKED_EQ").is_err());
        assert!(compare_for("SCMP_CMP_LT").is_err());
    }

    #[test]
    fn seccomp_load_flags_are_refused_rather_than_dropped() {
        let error = compile(&profile(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "flags": ["SECCOMP_FILTER_FLAG_TSYNC"]}"#,
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("SECCOMP_FILTER_FLAG_TSYNC"), "{error}");
    }

    #[test]
    fn a_profile_that_does_not_cover_this_architecture_is_refused() {
        let error = compile(&profile(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_AARCH64"]}"#,
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCMP_ARCH_X86_64"), "{error}");
    }

    #[test]
    fn the_profile_podman_sends_compiles_and_fits_the_kernels_limit() {
        let program = compile(&podman_profile()).unwrap();
        assert!(
            program.len() <= 4096,
            "a filter may hold at most 4096 instructions, this one has {}",
            program.len()
        );
    }

    #[test]
    fn every_plain_rule_in_podmans_profile_decides_the_way_it_says() {
        // The point of the interpreter: a filter that is subtly wrong still
        // loads, so the only way to know what it decides is to run it. Names
        // that appear more than once, or alongside argument tests, are left out
        // because the first matching rule wins and the answer depends on order.
        let profile = podman_profile();
        let program = compile(&profile).unwrap();

        let mut seen: std::collections::BTreeMap<&str, usize> = Default::default();
        for rule in &profile.syscalls {
            for name in &rule.names {
                *seen.entry(name.as_str()).or_default() += 1;
            }
        }

        let mut checked = 0;
        for rule in &profile.syscalls {
            if !rule.args.is_empty() {
                continue;
            }
            let expected = action_for(&rule.action, rule.errno_ret).unwrap();
            for name in &rule.names {
                if seen[name.as_str()] > 1 {
                    continue;
                }
                let Some(number) = syscall_number(name) else { continue };
                assert_eq!(
                    verdict(&program, number),
                    expected,
                    "{name} was decided differently from the profile"
                );
                checked += 1;
            }
        }
        assert!(checked > 300, "only {checked} syscalls were covered");
    }
}
