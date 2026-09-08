//! veth pairs, a host bridge, addresses and routes — all over rtnetlink.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use rustix::process::Pid;

use crate::error::{Context, Error, Result};
use crate::net::netlink::{self, Message, Socket};

/// The host bridge every container attaches to.
pub const BRIDGE: &str = "quilt0";
/// The subnet handed out on it.
pub const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
pub const PREFIX_LEN: u8 = 16;
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);

/// The name of the container's interface, once it is in the netns.
pub const CONTAINER_LINK: &str = "eth0";
/// The nftables table quilt owns outright, so it can be replaced wholesale.
const NFT_TABLE: &str = "quilt";

/// Everything the init process needs to configure its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
}

/// What one container's networking will look like, decided before the clone so
/// that the init process can be told about it on its command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    seed: u32,
    pub endpoint: Endpoint,
}

impl Plan {
    /// `seed` must be unique among the containers running at one time; the
    /// runtime's own pid is.
    pub fn new(seed: u32) -> Self {
        Self {
            seed,
            endpoint: Endpoint {
                address: address_for(seed),
                prefix_len: PREFIX_LEN,
                gateway: GATEWAY,
            },
        }
    }
}

impl Endpoint {
    /// Parses the form `run` puts on init's command line.
    pub fn parse(address: &str, gateway: &str) -> Result<Self> {
        let (address, prefix_len) = address
            .split_once('/')
            .ok_or_else(|| Error::msg(format!("{address:?} is not ADDRESS/PREFIX")))?;
        Ok(Self {
            address: address
                .parse()
                .map_err(|_| Error::msg(format!("{address:?} is not an IPv4 address")))?,
            prefix_len: prefix_len
                .parse()
                .map_err(|_| Error::msg(format!("{prefix_len:?} is not a prefix length")))?,
            gateway: gateway
                .parse()
                .map_err(|_| Error::msg(format!("{gateway:?} is not an IPv4 address")))?,
        })
    }
}

/// The host side of one container's connection. Deleting the host end of a veth
/// takes the peer with it, so this is the whole teardown.
pub struct HostLink {
    name: String,
}

impl Drop for HostLink {
    fn drop(&mut self) {
        if let Err(e) = delete_link(&self.name) {
            eprintln!("quilt: {e}");
        }
    }
}

/// The interface name for the host end of a container's veth.
///
/// `IFNAMSIZ` leaves 15 usable characters, and the seed is the runtime's own
/// pid, which is unique among the containers running at any one time.
pub fn host_link_name(seed: u32) -> String {
    format!("qv{seed}")
}

/// Picks a host address inside the subnet.
///
/// `.1` is the gateway and `.0`/`.255.255` are the network and broadcast, so
/// the host part is folded into the range that is left. Two containers running
/// at once get different seeds, so they get different addresses; this is not
/// real IPAM, and does not try to be — allocation is podman's job in the OCI
/// path, and this exists to give the bespoke CLI something to route.
pub fn address_for(seed: u32) -> Ipv4Addr {
    let host_part = 2 + (seed % 65_532);
    let [a, b, _, _] = SUBNET.octets();
    Ipv4Addr::new(a, b, (host_part >> 8) as u8, (host_part & 0xff) as u8)
}

/// Reads an interface's index out of sysfs.
///
/// The alternative is an `RTM_GETLINK` round trip and a second parser for the
/// reply; the index is right here, and the encoder is what this phase is about.
fn link_index(netns_sysfs: &Path, name: &str) -> Result<u32> {
    let path = netns_sysfs.join(name).join("ifindex");
    let raw = std::fs::read_to_string(&path).context(|| format!("reading {}", path.display()))?;
    raw.trim()
        .parse()
        .map_err(|_| Error::msg(format!("{} does not hold an interface index", path.display())))
}

const SYSFS_LINKS: &str = "/sys/class/net";

fn index_of(name: &str) -> Result<u32> {
    link_index(Path::new(SYSFS_LINKS), name)
}

/// Creates the bridge if it is not already there, addresses it, and brings it
/// up. Shared by every container, so all three steps tolerate "already done".
fn ensure_bridge(socket: &mut Socket) -> Result<()> {
    socket.request_tolerating(
        create_bridge_message(),
        "creating the bridge",
        rustix::io::Errno::EXIST,
    )?;

    let index = index_of(BRIDGE)?;
    add_address(socket, index, GATEWAY, PREFIX_LEN, true)?;
    set_up(socket, BRIDGE)
}

/// `ip link add quilt0 type bridge`.
fn create_bridge_message() -> Message {
    let mut message = Message::new(
        netlink::RTM_NEWLINK,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
    );
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, 0, 0));
    message.attr_nul_str(netlink::IFLA_IFNAME, BRIDGE);
    let link_info = message.nest(netlink::IFLA_LINKINFO);
    message.attr_str(netlink::IFLA_INFO_KIND, "bridge");
    message.end(link_info);
    message
}

fn add_address(
    socket: &mut Socket,
    index: u32,
    address: Ipv4Addr,
    prefix_len: u8,
    tolerate_existing: bool,
) -> Result<()> {
    let message = address_message(index, address, prefix_len);
    let what = format!("adding {address}/{prefix_len}");
    if tolerate_existing {
        socket.request_tolerating(message, &what, rustix::io::Errno::EXIST)
    } else {
        socket.request(message, &what)
    }
}

/// `ip addr add <address>/<prefix> dev <index>`.
fn address_message(index: u32, address: Ipv4Addr, prefix_len: u8) -> Message {
    let mut message = Message::new(
        netlink::RTM_NEWADDR,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
    );
    message.payload(&netlink::ifaddrmsg(netlink::AF_INET, prefix_len, 0, index));
    // IFA_LOCAL is the address itself; IFA_ADDRESS is the peer on a
    // point-to-point link and the same value on a broadcast one.
    message.attr(netlink::IFA_LOCAL, &address.octets());
    message.attr(netlink::IFA_ADDRESS, &address.octets());
    message
}

fn set_up(socket: &mut Socket, name: &str) -> Result<()> {
    socket.request(set_up_message(name), &format!("bringing {name} up"))
}

/// `ip link set <name> up`.
fn set_up_message(name: &str) -> Message {
    let mut message =
        Message::new(netlink::RTM_SETLINK, netlink::NLM_F_REQUEST | netlink::NLM_F_ACK);
    // ifi_change says which flag bits ifi_flags is authoritative for.
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, netlink::IFF_UP, netlink::IFF_UP));
    message.attr_str(netlink::IFLA_IFNAME, name);
    message
}

fn delete_link(name: &str) -> Result<()> {
    let mut socket = Socket::open()?;
    let mut message =
        Message::new(netlink::RTM_DELLINK, netlink::NLM_F_REQUEST | netlink::NLM_F_ACK);
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, 0, 0));
    message.attr_nul_str(netlink::IFLA_IFNAME, name);
    // Already gone is the desired state: the peer dying takes this end with it.
    socket.request_tolerating(message, &format!("deleting {name}"), rustix::io::Errno::NODEV)
}

/// Builds the host side: bridge, veth pair with the peer born straight into the
/// container's netns, and the host end enslaved to the bridge and brought up.
pub fn connect(plan: &Plan, pid: Pid) -> Result<HostLink> {
    let mut socket = Socket::open()?;
    ensure_bridge(&mut socket)?;
    enable_egress()?;

    let name = host_link_name(plan.seed);
    create_veth(&mut socket, &name, pid)?;
    // From here on the pair exists, so any later failure must tear it down.
    let link = HostLink { name: name.clone() };

    let bridge = index_of(BRIDGE)?;
    enslave(&mut socket, &name, bridge)?;
    set_up(&mut socket, &name)?;

    Ok(link)
}

/// Lets the container's traffic leave the host.
///
/// The nftables rule goes in through `nft` rather than hand-assembled
/// nf_tables netlink. That is a second encoder as large as this whole phase and
/// it teaches the same lesson twice; the phase 3 bar is the rtnetlink encoder's
/// bytes. Same bargain phase 6 makes with `newuidmap`.
fn enable_egress() -> Result<()> {
    enable_forwarding()?;

    let mut nft = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context(|| "running nft".to_string())?;
    nft.stdin
        .take()
        .expect("stdin was piped")
        .write_all(masquerade_ruleset().as_bytes())
        .context(|| "writing the nft ruleset".to_string())?;

    let status = nft.wait().context(|| "waiting for nft".to_string())?;
    if !status.success() {
        return Err(Error::msg(format!("nft rejected the masquerade ruleset ({status})")));
    }
    Ok(())
}

/// Turns on IPv4 forwarding, which is host-wide and outlives the container.
///
/// quilt is a one-shot process changing a setting that belongs to the whole
/// machine, so it says when it is the one doing it rather than flipping it
/// silently. It is not restored afterwards: another container, or anything else
/// on the host, may be relying on it by then.
fn enable_forwarding() -> Result<()> {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";

    let current = std::fs::read_to_string(PATH).context(|| format!("reading {PATH}"))?;
    if current.trim() == "1" {
        return Ok(());
    }

    std::fs::write(PATH, "1").context(|| format!("writing {PATH}"))?;
    eprintln!("quilt: enabled ipv4 forwarding host-wide ({PATH}); it is not turned back off");
    Ok(())
}

/// `add` then `delete` makes replacement idempotent: the add creates the table
/// if it is missing so the delete always has something to remove, and the
/// definition that follows is then the table's only content. Without it a
/// second run appends a duplicate rule.
fn masquerade_ruleset() -> String {
    format!(
        "add table ip {NFT_TABLE}\n\
         delete table ip {NFT_TABLE}\n\
         table ip {NFT_TABLE} {{\n\
         chain postrouting {{\n\
         type nat hook postrouting priority srcnat;\n\
         ip saddr {SUBNET}/{PREFIX_LEN} oifname != \"{BRIDGE}\" masquerade\n\
         }}\n\
         }}\n"
    )
}

/// One `RTM_NEWLINK` that creates both ends and places the far one.
///
/// This is the deepest nest the encoder has to build: `IFLA_LINKINFO` holds
/// `IFLA_INFO_KIND` and `IFLA_INFO_DATA`, and for a veth `IFLA_INFO_DATA` holds
/// `VETH_INFO_PEER`, which is a whole second `ifinfomsg` with its own
/// attributes. `IFLA_NET_NS_PID` in there is what moves the peer into the
/// container's netns, so it is never visible on the host and cannot collide
/// with a host interface already called eth0.
fn create_veth(socket: &mut Socket, host_name: &str, pid: Pid) -> Result<()> {
    let message = create_veth_message(host_name, Some(pid.as_raw_nonzero().get() as u32));
    socket.request(message, "creating the veth pair")
}

/// `peer_pid` of `None` leaves both ends on the host. Nothing in the runtime
/// wants that, but it is the shape `ip link add ... type veth peer name ...`
/// produces, which is what the golden capture can be compared against:
/// `ip`'s `netns` argument resolves to an open descriptor and goes out as
/// `IFLA_NET_NS_FD`, and quilt has a pid rather than a descriptor.
fn create_veth_message(host_name: &str, peer_pid: Option<u32>) -> Message {
    let mut message = Message::new(
        netlink::RTM_NEWLINK,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
    );
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, 0, 0));
    message.attr_nul_str(netlink::IFLA_IFNAME, host_name);

    let link_info = message.nest(netlink::IFLA_LINKINFO);
    message.attr_str(netlink::IFLA_INFO_KIND, "veth");
    let info_data = message.nest(netlink::IFLA_INFO_DATA);
    let peer = message.nest(netlink::VETH_INFO_PEER);
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, 0, 0));
    // The namespace attribute goes before the name, which is the order `ip`
    // uses. The kernel parses attributes into a table and does not care, but
    // matching it keeps the capture comparison about substance.
    if let Some(pid) = peer_pid {
        message.attr_u32(netlink::IFLA_NET_NS_PID, pid);
    }
    message.attr_nul_str(netlink::IFLA_IFNAME, CONTAINER_LINK);
    message.end(peer);
    message.end(info_data);
    message.end(link_info);
    message
}

fn enslave(socket: &mut Socket, name: &str, bridge: u32) -> Result<()> {
    socket.request(enslave_message(name, bridge), &format!("attaching {name} to {BRIDGE}"))
}

/// `ip link set <name> master quilt0`.
fn enslave_message(name: &str, bridge: u32) -> Message {
    let mut message =
        Message::new(netlink::RTM_SETLINK, netlink::NLM_F_REQUEST | netlink::NLM_F_ACK);
    message.payload(&netlink::ifinfomsg(netlink::AF_UNSPEC, 0, 0, 0));
    message.attr_nul_str(netlink::IFLA_IFNAME, name);
    message.attr_u32(netlink::IFLA_MASTER, bridge);
    message
}

/// Configures the container's end. Runs inside the netns, in the init process,
/// after the mount plan so that sysfs is there to read the interface index
/// from.
pub fn configure(endpoint: &Endpoint) -> Result<()> {
    let mut socket = Socket::open()?;

    set_up(&mut socket, "lo")?;

    let index = index_of(CONTAINER_LINK)?;
    add_address(&mut socket, index, endpoint.address, endpoint.prefix_len, false)?;
    // The route below needs the connected prefix, which only appears once the
    // link is up, so the ordering here is load-bearing.
    set_up(&mut socket, CONTAINER_LINK)?;
    add_default_route(&mut socket, index, endpoint.gateway)
}

fn add_default_route(socket: &mut Socket, index: u32, gateway: Ipv4Addr) -> Result<()> {
    socket.request(
        default_route_message(index, gateway),
        &format!("adding a default route via {gateway}"),
    )
}

/// `ip route add default via <gateway> dev <index>`.
fn default_route_message(index: u32, gateway: Ipv4Addr) -> Message {
    let mut message = Message::new(
        netlink::RTM_NEWROUTE,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | netlink::NLM_F_CREATE,
    );
    // A destination prefix length of zero is what makes this the default route.
    message.payload(&netlink::rtmsg(
        netlink::AF_INET,
        0,
        netlink::RT_TABLE_MAIN,
        netlink::RTPROT_BOOT,
        netlink::RT_SCOPE_UNIVERSE,
        netlink::RTN_UNICAST,
    ));
    message.attr(netlink::RTA_GATEWAY, &gateway.octets());
    message.attr_u32(netlink::RTA_OIF, index);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn a_host_link_name_fits_in_ifnamsiz() {
        // IFNAMSIZ is 16, leaving 15 usable characters.
        assert!(host_link_name(u32::MAX).len() <= 15);
        assert_eq!(host_link_name(1234), "qv1234");
    }

    #[test]
    fn an_address_never_lands_on_the_gateway_or_the_network() {
        for seed in [0, 1, 2, 65_531, 65_532, 65_535, u32::MAX] {
            let address = address_for(seed);
            assert_ne!(address, GATEWAY);
            assert_ne!(address, SUBNET);
            assert!(address.octets()[0..2] == SUBNET.octets()[0..2], "{address} left the subnet");
        }
    }

    #[test]
    fn different_seeds_give_different_addresses() {
        assert_ne!(address_for(10), address_for(11));
        assert_eq!(address_for(2), Ipv4Addr::new(10, 88, 0, 4));
    }

    /// Reads a message captured from `ip` with `scripts/capture-netlink.sh`.
    ///
    /// The captures are committed artifacts, so a missing one is a broken
    /// checkout, not a reason to skip. Nothing else in the suite compares these
    /// bytes; if this returns without looking, the phase 3 acceptance criterion
    /// is unverified and says otherwise.
    fn golden(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name);
        let hex = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "tests/golden/{name} is missing ({e}). It is a committed capture of what ip puts \
                 on the wire; regenerate the set with: sudo scripts/capture-netlink.sh"
            )
        });
        hex.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).expect("golden files hold hex bytes"))
            .collect()
    }

    /// Compares against `ip`'s bytes with the sequence number and port id
    /// zeroed, which is how the capture script stores them: those two fields
    /// are per-socket bookkeeping, not part of the request.
    fn assert_matches_ip(name: &str, message: Message) {
        assert_eq!(message.finish(0), golden(name), "{name} diverges from what ip sends");
    }

    /// The veth request is the deepest nest in the project and the place an
    /// encoder bug would actually live, so it is held to byte equality.
    #[test]
    fn the_veth_message_is_byte_identical_to_what_ip_sends() {
        // Must match the invocation in scripts/capture-netlink.sh, which
        // creates the pair without a netns for the reason on
        // `create_veth_message`.
        assert_matches_ip("veth-add.hex", create_veth_message("qvgolden", None));
    }

    /// The netns move is the one part of the veth request no capture can cover,
    /// so its bytes are pinned directly.
    #[test]
    fn moving_the_peer_adds_exactly_the_net_ns_pid_attribute() {
        let without = create_veth_message("qvgolden", None).finish(0);
        let with = create_veth_message("qvgolden", Some(4242)).finish(0);

        assert_eq!(with.len(), without.len() + 8);

        let mut expected = Vec::new();
        expected.extend_from_slice(&8u16.to_ne_bytes());
        expected.extend_from_slice(&netlink::IFLA_NET_NS_PID.to_ne_bytes());
        expected.extend_from_slice(&4242u32.to_ne_bytes());
        assert!(
            with.windows(8).any(|w| w == expected),
            "the IFLA_NET_NS_PID attribute is not on the wire"
        );
        assert!(!without.windows(8).any(|w| w == expected));
    }

    /// Everything else is compared for what the kernel reads rather than
    /// byte-for-byte, so iproute2's stylistic choices do not end up pinned in
    /// this suite.
    #[test]
    fn the_bridge_message_asks_for_the_same_thing_ip_asks_for() {
        let theirs =
            netlink::parse(&golden("bridge-add.hex"), 16, &[netlink::IFLA_LINKINFO]).unwrap();
        let ours =
            netlink::parse(&create_bridge_message().finish(0), 16, &[netlink::IFLA_LINKINFO])
                .unwrap();

        assert_eq!(ours.kind, theirs.kind);
        assert_eq!(ours.flags, theirs.flags);
        assert_eq!(ours.payload, theirs.payload);
        assert_eq!(attribute_set(&ours.attrs), attribute_set(&theirs.attrs));
    }

    #[test]
    fn the_set_up_message_asks_for_the_same_thing_ip_asks_for() {
        let theirs = netlink::parse(&golden("link-up.hex"), 16, &[]).unwrap();
        let ours = netlink::parse(&set_up_message("qvgolden").finish(0), 16, &[]).unwrap();

        // iproute2 modifies an existing link with RTM_NEWLINK minus
        // NLM_F_CREATE; quilt uses RTM_SETLINK, which is the message named for
        // the job. The kernel registers a handler for both and they end up in
        // the same place, so the capture accepts either and this records which.
        assert!(
            matches!(theirs.kind, netlink::RTM_NEWLINK | netlink::RTM_SETLINK),
            "ip sent an unexpected message type {}",
            theirs.kind
        );
        assert_eq!(ours.kind, netlink::RTM_SETLINK);

        // ifi_flags and ifi_change, the last two words of ifinfomsg: which bits
        // are being set, and which of them this message is authoritative for.
        // This is the part that actually has to agree.
        assert_eq!(ours.payload[8..16], theirs.payload[8..16]);

        // The accepted divergence, asserted rather than glossed over: iproute2
        // resolves the name to an index before sending and identifies the link
        // by ifi_index, while quilt sends ifi_index 0 and IFLA_IFNAME. The
        // kernel takes either.
        assert_ne!(theirs.payload[4..8], [0, 0, 0, 0], "ip identifies by index");
        assert_eq!(ours.payload[4..8], [0, 0, 0, 0]);
        assert!(
            ours.attrs
                .iter()
                .any(|a| matches!(a, netlink::Attr::Value { kind: netlink::IFLA_IFNAME, .. })),
            "quilt identifies by name"
        );
    }

    /// Attributes as a set, with the trailing NUL stripped off the string ones.
    /// Order is not meaningful — the kernel parses them into a table — and the
    /// NUL is stripped by `nla_strcmp` before anything compares it.
    fn attribute_set(attrs: &[netlink::Attr]) -> BTreeSet<netlink::Attr> {
        const STRINGS: &[u16] = &[netlink::IFLA_IFNAME, netlink::IFLA_INFO_KIND];

        attrs
            .iter()
            .map(|attr| match attr {
                netlink::Attr::Value { kind, value } if STRINGS.contains(kind) => {
                    netlink::Attr::Value {
                        kind: *kind,
                        value: value.strip_suffix(b"\0").unwrap_or(value).to_vec(),
                    }
                }
                netlink::Attr::Nest { kind, attrs } => netlink::Attr::Nest {
                    kind: *kind,
                    attrs: attribute_set(attrs).into_iter().collect(),
                },
                other => other.clone(),
            })
            .collect()
    }

    #[test]
    fn the_masquerade_ruleset_replaces_rather_than_appends() {
        let ruleset = masquerade_ruleset();
        let add = ruleset.find("add table").unwrap();
        let delete = ruleset.find("delete table").unwrap();
        assert!(add < delete, "the delete must follow the add or it can fail");
        assert!(ruleset.contains("ip saddr 10.88.0.0/16"));
        assert!(ruleset.contains("oifname != \"quilt0\""));
        assert!(ruleset.contains("masquerade"));
    }

    #[test]
    fn an_endpoint_round_trips_through_its_command_line_form() {
        let plan = Plan::new(7);
        let text = format!("{}/{}", plan.endpoint.address, plan.endpoint.prefix_len);
        let parsed = Endpoint::parse(&text, &plan.endpoint.gateway.to_string()).unwrap();
        assert_eq!(parsed, plan.endpoint);
    }

    #[test]
    fn a_malformed_endpoint_is_rejected() {
        assert!(Endpoint::parse("10.88.0.2", "10.88.0.1").is_err());
        assert!(Endpoint::parse("not-an-address/16", "10.88.0.1").is_err());
        assert!(Endpoint::parse("10.88.0.2/16", "nonsense").is_err());
    }

    #[test]
    fn an_interface_index_is_read_out_of_sysfs() {
        let dir = std::env::temp_dir().join("quilt-ifindex-test/eth0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ifindex"), "42\n").unwrap();

        let index = link_index(dir.parent().unwrap(), "eth0");
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();

        assert_eq!(index.unwrap(), 42);
    }

    #[test]
    fn a_missing_interface_index_is_an_error_not_a_zero() {
        assert!(link_index(Path::new("/nonexistent"), "eth0").is_err());
    }
}
