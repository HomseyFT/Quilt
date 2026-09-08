//! Rootless connectivity, handed to `pasta`.
//!
//! The veth and bridge in `veth.rs` need CAP_NET_ADMIN on the host: creating a
//! link, attaching it to a bridge and adding a NAT rule are all privileged, and
//! no amount of user-namespace root buys them. `pasta` solves it from the other
//! end — it joins the container's network namespace, puts a tap interface in
//! it, and runs a TCP/IP stack in user space that forwards through ordinary
//! sockets owned by the invoking user.
//!
//! Shelling out is the same bargain phase 6 makes with `newuidmap`: pasta is
//! the sanctioned way an unprivileged process gets this, and reimplementing a
//! user-space network stack is a different project.

use rustix::process::Pid;

use crate::error::{Context, Error, Result};

/// Configures the container's network namespace and leaves pasta serving it.
///
/// pasta puts itself in the background once the namespace is set up, so this
/// returns as soon as the container has an address. It exits by itself when the
/// namespace goes away, which is why there is nothing to tear down here.
pub fn connect(pid: Pid) -> Result<()> {
    let pid = pid.as_raw_nonzero().get();

    // Both namespaces, not just the network one. The container's netns is owned
    // by the user namespace the clone made, and joining a netns needs
    // CAP_SYS_ADMIN in its owner — which pasta only has once it is inside. Given
    // a bare pid it joins the netns alone and is refused.
    let output = std::process::Command::new("pasta")
        .arg("--config-net")
        // That watch is for a namespace bound into /run/netns, which pasta
        // polls to know when to exit. The container's is a live process's
        // namespace instead, so there is nothing there to watch and the attempt
        // fails on a directory that belongs to root.
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
