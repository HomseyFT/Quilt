//! Container networking.
//!
//! Out of the OCI path on purpose. The runtime spec does not cover networking:
//! `runc` and `crun` create or join a network namespace and stop there, and
//! podman wires it up with netavark afterwards. So this hangs off the bespoke
//! `run` CLI only, and phase 4 leaves it alone.

pub mod netlink;
pub mod veth;

/// What `--net` asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum NetworkMode {
    /// An empty network namespace with nothing but loopback.
    #[default]
    None,
    /// A veth pair onto a host bridge, with NAT for egress.
    Bridge,
}
