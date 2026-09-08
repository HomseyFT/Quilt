//! Container networking.
//!
//! Out of the OCI path on purpose: the runtime spec does not cover networking.
//! `runc` and `crun` create or join a network namespace and stop there, and
//! podman wires it up with netavark afterwards. This hangs off `run` only.

pub mod netlink;
pub mod veth;

/// What `--net` asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkMode {
    /// An empty network namespace with nothing but loopback.
    #[default]
    None,
    /// A veth pair onto a host bridge, with NAT for egress. Needs privilege.
    Bridge,
    /// A user-space network stack joined to the container's namespace, which is
    /// how an unprivileged container gets out.
    Pasta,
}

pub mod pasta;
