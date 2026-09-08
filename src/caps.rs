//! Capability sets and `no_new_privs`.
//!
//! Applied in the init process immediately before `execve`, for the same reason
//! seccomp is: the setup itself needs capabilities the container must not keep.

use rustix::thread::{CapabilitySet, CapabilitySets};

use crate::error::{Context, Error, Result};
use crate::spec;
use crate::syscall;

/// The OCI spec names capabilities; the kernel numbers them.
const CAPABILITIES: &[(&str, u32)] = &[
    ("CAP_CHOWN", 0),
    ("CAP_DAC_OVERRIDE", 1),
    ("CAP_DAC_READ_SEARCH", 2),
    ("CAP_FOWNER", 3),
    ("CAP_FSETID", 4),
    ("CAP_KILL", 5),
    ("CAP_SETGID", 6),
    ("CAP_SETUID", 7),
    ("CAP_SETPCAP", 8),
    ("CAP_LINUX_IMMUTABLE", 9),
    ("CAP_NET_BIND_SERVICE", 10),
    ("CAP_NET_BROADCAST", 11),
    ("CAP_NET_ADMIN", 12),
    ("CAP_NET_RAW", 13),
    ("CAP_IPC_LOCK", 14),
    ("CAP_IPC_OWNER", 15),
    ("CAP_SYS_MODULE", 16),
    ("CAP_SYS_RAWIO", 17),
    ("CAP_SYS_CHROOT", 18),
    ("CAP_SYS_PTRACE", 19),
    ("CAP_SYS_PACCT", 20),
    ("CAP_SYS_ADMIN", 21),
    ("CAP_SYS_BOOT", 22),
    ("CAP_SYS_NICE", 23),
    ("CAP_SYS_RESOURCE", 24),
    ("CAP_SYS_TIME", 25),
    ("CAP_SYS_TTY_CONFIG", 26),
    ("CAP_MKNOD", 27),
    ("CAP_LEASE", 28),
    ("CAP_AUDIT_WRITE", 29),
    ("CAP_AUDIT_CONTROL", 30),
    ("CAP_SETFCAP", 31),
    ("CAP_MAC_OVERRIDE", 32),
    ("CAP_MAC_ADMIN", 33),
    ("CAP_SYSLOG", 34),
    ("CAP_WAKE_ALARM", 35),
    ("CAP_BLOCK_SUSPEND", 36),
    ("CAP_AUDIT_READ", 37),
    ("CAP_PERFMON", 38),
    ("CAP_BPF", 39),
    ("CAP_CHECKPOINT_RESTORE", 40),
];

/// The highest capability this kernel could know about. Dropping past the end
/// of what it supports is harmless, and is how the bounding set is swept.
const MAX_CAPABILITY: u32 = 63;

fn capability_number(name: &str) -> Result<u32> {
    CAPABILITIES.iter().find(|(known, _)| *known == name).map(|(_, number)| *number).ok_or_else(
        || {
            // A capability quilt does not recognise is one it cannot withhold,
            // so granting the rest would be a silent over-grant.
            Error::msg(format!("config.json names a capability quilt does not know: {name}"))
        },
    )
}

/// Turns a list of OCI capability names into a bitmask.
fn mask(names: &[String]) -> Result<u64> {
    let mut bits = 0u64;
    for name in names {
        bits |= 1u64 << capability_number(name)?;
    }
    Ok(bits)
}

/// Checks the names without changing anything, so `create` can refuse a bundle
/// it could not carry out before telling the caller the container exists.
pub fn validate(capabilities: &spec::Capabilities) -> Result<()> {
    if !capabilities.ambient.is_empty() {
        return Err(Error::msg(
            "config.json asks for ambient capabilities, which quilt does not raise".to_string(),
        ));
    }
    for names in [
        &capabilities.bounding,
        &capabilities.effective,
        &capabilities.permitted,
        &capabilities.inheritable,
    ] {
        mask(names)?;
    }
    Ok(())
}

/// Narrows the bounding set to what the bundle asked for.
///
/// Runs *before* the process changes user, and must. `PR_CAPBSET_DROP` needs
/// `CAP_SETPCAP` in the effective set, and any move off uid 0 empties effective
/// outright — `PR_SET_KEEPCAPS` preserves permitted, not effective
/// (capabilities(7)) — so doing it after fails every drop with EPERM.
///
/// It does not disturb the user change either: the bounding set only caps what
/// can be gained, so dropping `CAP_SETGID` from it leaves the copy in effective
/// alone and `setgroups` still works.
pub fn narrow_bounding(capabilities: &spec::Capabilities) -> Result<()> {
    // The first of the two passes, so refuse before anything has changed.
    validate(capabilities)?;

    let bounding = mask(&capabilities.bounding)?;
    for number in 0..=MAX_CAPABILITY {
        if bounding & (1u64 << number) != 0 {
            continue;
        }
        match syscall::prctl_2(syscall::PR_CAPBSET_DROP, u64::from(number)) {
            Ok(()) => {}
            // Past the end of what this kernel defines.
            Err(rustix::io::Errno::INVAL) => {}
            Err(e) => {
                return Err(Error::from_errno(
                    format!("dropping capability {number} from the bounding set"),
                    e,
                ));
            }
        }
    }

    Ok(())
}

/// Applies the effective, permitted and inheritable sets.
///
/// Runs *after* the user change, so these are the sets the workload keeps.
/// Raising effective out of permitted needs no privilege, which is why this
/// half survives a transition the other could not.
pub fn apply_sets(capabilities: &spec::Capabilities) -> Result<()> {
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: CapabilitySet::from_bits_retain(mask(&capabilities.effective)?),
            permitted: CapabilitySet::from_bits_retain(mask(&capabilities.permitted)?),
            inheritable: CapabilitySet::from_bits_retain(mask(&capabilities.inheritable)?),
        },
    )
    .context(|| "setting the capability sets".to_string())
}

/// Stops the workload gaining privilege through a setuid binary.
pub fn set_no_new_privs() -> Result<()> {
    rustix::thread::set_no_new_privs(true).context(|| "setting no_new_privs".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn capability_names_map_to_their_kernel_numbers() {
        assert_eq!(capability_number("CAP_CHOWN").unwrap(), 0);
        assert_eq!(capability_number("CAP_SYS_ADMIN").unwrap(), 21);
        assert_eq!(capability_number("CAP_CHECKPOINT_RESTORE").unwrap(), 40);
    }

    #[test]
    fn an_unknown_capability_is_refused_rather_than_ignored() {
        // Skipping it would grant everything else and look like it worked.
        assert!(capability_number("CAP_INVENTED").is_err());
        assert!(mask(&names(&["CAP_CHOWN", "CAP_INVENTED"])).is_err());
    }

    #[test]
    fn a_mask_sets_one_bit_per_capability() {
        assert_eq!(mask(&names(&["CAP_CHOWN"])).unwrap(), 1);
        assert_eq!(mask(&names(&["CAP_DAC_OVERRIDE"])).unwrap(), 2);
        assert_eq!(mask(&names(&["CAP_CHOWN", "CAP_DAC_OVERRIDE"])).unwrap(), 3);
        assert_eq!(mask(&[]).unwrap(), 0);
    }

    #[test]
    fn the_table_has_no_duplicate_names_or_numbers() {
        let mut names: Vec<&str> = CAPABILITIES.iter().map(|(n, _)| *n).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "a duplicated name would shadow a capability");

        let mut numbers: Vec<u32> = CAPABILITIES.iter().map(|(_, n)| *n).collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), count, "a duplicated number would drop the wrong capability");
    }

    #[test]
    fn the_set_podman_sends_is_fully_recognised() {
        let podman = names(&[
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ]);
        let bits = mask(&podman).unwrap();

        // CAP_SETPCAP has to survive into the bounding-set pass.
        assert_ne!(bits & (1 << 8), 0);
        assert_eq!(bits.count_ones(), 11);
    }

    #[test]
    fn ambient_capabilities_are_refused_before_anything_changes() {
        let capabilities = spec::Capabilities {
            ambient: names(&["CAP_NET_RAW"]),
            ..spec::Capabilities::default()
        };
        assert!(narrow_bounding(&capabilities).is_err());
    }
}
