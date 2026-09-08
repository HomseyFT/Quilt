//! Rootless connectivity, handed to `pasta`.
//!
//! The veth and bridge in `veth.rs` need CAP_NET_ADMIN on the host, which
//! user-namespace root does not buy. `pasta` works from the other end: it joins
//! the container's network namespace, puts a tap interface in it, and runs a
//! TCP/IP stack in user space over ordinary sockets owned by the invoking user.
//!
//! Shelling out is the same bargain as `newuidmap` — the sanctioned way an
//! unprivileged process gets this.

use rustix::process::Pid;

use crate::error::{Context, Error, Result};

/// Configures the container's network namespace and leaves pasta serving it.
///
/// pasta puts itself in the background once the namespace is set up, so this
/// returns as soon as the container has an address. It exits by itself when the
/// namespace goes away, which is why there is nothing to tear down here.
pub fn connect(pid: Pid) -> Result<()> {
    let pid = pid.as_raw_nonzero().get();

    // Both namespaces, not just the network one: the netns is owned by the
    // user namespace the clone made, and joining a netns needs CAP_SYS_ADMIN in
    // its owner. Given a bare pid, pasta joins the netns alone and is refused.
    let output = std::process::Command::new("pasta")
        .arg("--config-net")
        // That watch is for a namespace bound into /run/netns. The container's
        // belongs to a live process, so there is nothing to watch and the
        // attempt fails on a directory owned by root.
        .arg("--no-netns-quit")
        .arg("--userns")
        .arg(format!("/proc/{pid}/ns/user"))
        .arg("--netns")
        .arg(format!("/proc/{pid}/ns/net"))
        .output()
        .context(|| "running pasta".to_string())?;

    if !output.status.success() {
        return Err(Error::msg(format!(
            "pasta could not connect the container ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
