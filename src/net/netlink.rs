//! A hand-assembled rtnetlink encoder.
//!
//! `rustix` provides the socket; every byte on the wire is built here. Netlink
//! is a stream of `nlmsghdr`-prefixed messages, each carrying a fixed struct
//! followed by a list of `rtattr` type-length-value attributes, and attributes
//! nest: `IFLA_LINKINFO` contains `IFLA_INFO_KIND` and `IFLA_INFO_DATA`, and for
//! a veth the latter contains `VETH_INFO_PEER`, which contains a whole second
//! `ifinfomsg` and its own attributes.
//!
//! Everything is in host byte order except addresses, which are on the wire as
//! they are on the network.

use std::os::fd::OwnedFd;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

use crate::error::{Context, Error, Result};

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_NEWROUTE: u16 = 24;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

const NLMSG_ERROR: u16 = 2;

pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;

pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const VETH_INFO_PEER: u16 = 1;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;

pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const IFF_UP: u32 = 0x1;

/// `RT_TABLE_MAIN`, `RTPROT_BOOT`, `RT_SCOPE_UNIVERSE`, `RTN_UNICAST`.
pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_BOOT: u8 = 3;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RTN_UNICAST: u8 = 1;

const NLMSGHDR_LEN: usize = 16;
const RTATTR_LEN: usize = 4;

/// Netlink pads every header and attribute up to a 4-byte boundary.
const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// An open nested attribute. Its length is only known once it is closed, so the
/// offset of its header is held until then.
#[must_use = "a nest must be closed with Message::end"]
pub struct Nest(usize);

/// One netlink request under construction.
pub struct Message {
    buf: Vec<u8>,
}

impl Message {
    pub fn new(kind: u16, flags: u16) -> Self {
        // nlmsg_len, nlmsg_seq and nlmsg_pid are filled in by `finish`.
        let mut buf = vec![0u8; NLMSGHDR_LEN];
        buf[4..6].copy_from_slice(&kind.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        Self { buf }
    }

    /// The fixed struct that follows the header: `ifinfomsg`, `ifaddrmsg` or
    /// `rtmsg`.
    pub fn payload(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    pub fn attr(&mut self, kind: u16, value: &[u8]) -> &mut Self {
        // rta_len counts the header and the value, but not the padding.
        let len = (RTATTR_LEN + value.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(value);
        self.pad();
        self
    }

    /// A string attribute, without a terminator.
    ///
    /// Termination is decided per attribute, not once for netlink: the
    /// kernel's `nla_strcmp` strips a trailing NUL, so both forms work but are
    /// different bytes. Captures of `ip` show `IFLA_INFO_KIND` bare and
    /// `IFLA_IFNAME` terminated. See [`Message::attr_nul_str`].
    pub fn attr_str(&mut self, kind: u16, value: &str) -> &mut Self {
        self.attr(kind, value.as_bytes())
    }

    /// A string attribute with the trailing NUL, as interface names go.
    pub fn attr_nul_str(&mut self, kind: u16, value: &str) -> &mut Self {
        let mut bytes = Vec::with_capacity(value.len() + 1);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        self.attr(kind, &bytes)
    }

    pub fn attr_u32(&mut self, kind: u16, value: u32) -> &mut Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    pub fn nest(&mut self, kind: u16) -> Nest {
        let at = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        Nest(at)
    }

    /// Backfills a nest's length, which spans everything written since it was
    /// opened, padding included.
    pub fn end(&mut self, nest: Nest) -> &mut Self {
        let len = (self.buf.len() - nest.0) as u16;
        self.buf[nest.0..nest.0 + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    /// Writes `nlmsg_len` and `nlmsg_seq`, and hands over the bytes.
    ///
    /// `nlmsg_pid` stays zero: it is the sender's port id, and the kernel fills
    /// it in for us rather than trusting what we claim.
    pub fn finish(mut self, seq: u32) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }

    fn pad(&mut self) {
        self.buf.resize(align(self.buf.len()), 0);
    }
}

/// `struct ifinfomsg`.
pub fn ifinfomsg(family: u8, index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = family;
    // out[1] is __ifi_pad, out[2..4] is ifi_type, both left zero.
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out[8..12].copy_from_slice(&flags.to_ne_bytes());
    out[12..16].copy_from_slice(&change.to_ne_bytes());
    out
}

/// `struct ifaddrmsg`.
pub fn ifaddrmsg(family: u8, prefix_len: u8, scope: u8, index: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = family;
    out[1] = prefix_len;
    // out[2] is ifa_flags.
    out[3] = scope;
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out
}

/// `struct rtmsg`.
pub fn rtmsg(family: u8, dst_len: u8, table: u8, protocol: u8, scope: u8, kind: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = family;
    out[1] = dst_len;
    // out[2] is rtm_src_len, out[3] is rtm_tos.
    out[4] = table;
    out[5] = protocol;
    out[6] = scope;
    out[7] = kind;
    // out[8..12] is rtm_flags.
    out
}

/// What a response buffer says about a request.
#[derive(Debug, PartialEq, Eq)]
enum Ack {
    Ok,
    Failed(i32),
    /// The acknowledgement is not in this buffer; read again.
    Absent,
}

/// Walks a buffer of netlink messages looking for the acknowledgement of `seq`.
///
/// An `NLMSG_ERROR` with a zero error code is the success acknowledgement, not
/// a failure.
fn find_ack(buf: &[u8], seq: u32) -> Ack {
    let mut offset = 0;
    while offset + NLMSGHDR_LEN <= buf.len() {
        let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        if len < NLMSGHDR_LEN || offset + len > buf.len() {
            return Ack::Absent;
        }
        let kind = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
        let msg_seq = u32::from_ne_bytes(buf[offset + 8..offset + 12].try_into().unwrap());

        if kind == NLMSG_ERROR && msg_seq == seq && len >= NLMSGHDR_LEN + 4 {
            let code = i32::from_ne_bytes(
                buf[offset + NLMSGHDR_LEN..offset + NLMSGHDR_LEN + 4].try_into().unwrap(),
            );
            return if code == 0 { Ack::Ok } else { Ack::Failed(-code) };
        }
        offset += align(len);
    }
    Ack::Absent
}

/// One attribute, decoded.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attr {
    Value { kind: u16, value: Vec<u8> },
    Nest { kind: u16, attrs: Vec<Attr> },
}

/// A decoded request.
///
/// Compares two encodings of the same intent where they may differ in style:
/// attribute order, or a NUL the kernel strips anyway.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub kind: u16,
    pub flags: u16,
    /// The fixed struct after the header, still as bytes.
    pub payload: Vec<u8>,
    pub attrs: Vec<Attr>,
}

/// Decodes a request. `payload_len` is the size of the fixed struct for this
/// message type, and `nested` names the attribute types whose values are
/// themselves attribute lists.
#[cfg(test)]
pub fn parse(bytes: &[u8], payload_len: usize, nested: &[u16]) -> Result<Parsed> {
    if bytes.len() < NLMSGHDR_LEN + payload_len {
        return Err(Error::msg("netlink message is shorter than its fixed payload".to_string()));
    }
    let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if len < NLMSGHDR_LEN + payload_len || len > bytes.len() {
        return Err(Error::msg(format!("nlmsg_len {len} does not fit {} bytes", bytes.len())));
    }

    Ok(Parsed {
        kind: u16::from_ne_bytes(bytes[4..6].try_into().unwrap()),
        flags: u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
        payload: bytes[NLMSGHDR_LEN..NLMSGHDR_LEN + payload_len].to_vec(),
        attrs: parse_attrs(&bytes[NLMSGHDR_LEN + payload_len..len], nested)?,
    })
}

#[cfg(test)]
fn parse_attrs(bytes: &[u8], nested: &[u16]) -> Result<Vec<Attr>> {
    let mut out = Vec::new();
    let mut offset = 0;

    while offset + RTATTR_LEN <= bytes.len() {
        let len = u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into().unwrap());
        if len < RTATTR_LEN || offset + len > bytes.len() {
            return Err(Error::msg(format!(
                "attribute {kind} claims {len} bytes it does not have"
            )));
        }

        let value = &bytes[offset + RTATTR_LEN..offset + len];
        out.push(if nested.contains(&kind) {
            Attr::Nest { kind, attrs: parse_attrs(value, nested)? }
        } else {
            Attr::Value { kind, value: value.to_vec() }
        });
        offset += align(len);
    }
    Ok(out)
}

/// A `NETLINK_ROUTE` socket, bound to whichever netns the caller is in.
pub struct Socket {
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    pub fn open() -> Result<Self> {
        // Protocol `None` is 0, which for AF_NETLINK is NETLINK_ROUTE.
        let fd = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)
            .context(|| "opening a NETLINK_ROUTE socket".to_string())?;
        // Port id 0 asks the kernel to allocate one.
        rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0))
            .context(|| "binding the netlink socket".to_string())?;
        Ok(Self { fd, seq: 0 })
    }

    /// Sends a request and waits for the kernel to acknowledge it.
    pub fn request(&mut self, message: Message, what: &str) -> Result<()> {
        self.try_request(message, what)
    }

    /// As [`Socket::request`], but treats `errno` as success. Used where the
    /// object may already exist and that is the desired state.
    pub fn request_tolerating(
        &mut self,
        message: Message,
        what: &str,
        tolerated: rustix::io::Errno,
    ) -> Result<()> {
        match self.try_request(message, what) {
            Err(e) if e.errno() == Some(tolerated) => Ok(()),
            other => other,
        }
    }

    fn try_request(&mut self, message: Message, what: &str) -> Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let bytes = message.finish(seq);

        rustix::net::send(&self.fd, &bytes, SendFlags::empty())
            .context(|| format!("sending the {what} request"))?;

        let mut buf = vec![0u8; 8192];
        loop {
            let received = rustix::net::recv(&self.fd, &mut buf[..], RecvFlags::empty())
                .context(|| format!("reading the {what} response"))?;
            match find_ack(&buf[..received.0], seq) {
                Ack::Ok => return Ok(()),
                Ack::Failed(code) => {
                    return Err(Error::from_errno(
                        format!("{what} was refused by the kernel"),
                        rustix::io::Errno::from_raw_os_error(code),
                    ));
                }
                Ack::Absent => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_string_attribute_carries_no_terminator() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST);
        message.attr_str(IFLA_INFO_KIND, "veth");
        let bytes = message.finish(1);

        // 4 header bytes plus "veth" is 8, which needs no padding.
        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 8);
        assert_eq!(&bytes[20..24], b"veth");
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn parsing_round_trips_what_the_encoder_built() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        message.payload(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        message.attr_nul_str(IFLA_IFNAME, "quilt0");
        let link_info = message.nest(IFLA_LINKINFO);
        message.attr_str(IFLA_INFO_KIND, "bridge");
        message.end(link_info);

        let parsed = parse(&message.finish(1), 16, &[IFLA_LINKINFO]).unwrap();

        assert_eq!(parsed.kind, RTM_NEWLINK);
        assert_eq!(parsed.flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(parsed.payload, vec![0u8; 16]);
        assert_eq!(
            parsed.attrs,
            vec![
                Attr::Value { kind: IFLA_IFNAME, value: b"quilt0\0".to_vec() },
                Attr::Nest {
                    kind: IFLA_LINKINFO,
                    attrs: vec![Attr::Value { kind: IFLA_INFO_KIND, value: b"bridge".to_vec() }],
                },
            ]
        );
    }

    #[test]
    fn parsing_rejects_an_attribute_that_overruns_the_message() {
        let mut bytes = Message::new(RTM_NEWLINK, NLM_F_REQUEST).finish(1);
        bytes.extend_from_slice(&[0xff, 0xff, 0x03, 0x00]);
        let len = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&len.to_ne_bytes());
        assert!(parse(&bytes, 0, &[]).is_err());
    }

    #[test]
    fn alignment_rounds_up_to_four() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
        assert_eq!(align(16), 16);
    }

    #[test]
    fn an_empty_message_is_just_a_header() {
        let bytes = Message::new(RTM_NEWLINK, NLM_F_REQUEST).finish(1);
        assert_eq!(bytes.len(), NLMSGHDR_LEN);
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 16);
        assert_eq!(u16::from_ne_bytes(bytes[4..6].try_into().unwrap()), RTM_NEWLINK);
        assert_eq!(u16::from_ne_bytes(bytes[6..8].try_into().unwrap()), NLM_F_REQUEST);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 1);
        // nlmsg_pid is left for the kernel to fill in.
        assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn a_string_attribute_is_nul_terminated_and_padded() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST);
        message.attr_nul_str(IFLA_IFNAME, "eth0");
        let bytes = message.finish(1);

        let attr = &bytes[NLMSGHDR_LEN..];
        // 4 header bytes + "eth0\0" is 9, padded to 12.
        assert_eq!(attr.len(), 12);
        assert_eq!(u16::from_ne_bytes(attr[0..2].try_into().unwrap()), 9);
        assert_eq!(u16::from_ne_bytes(attr[2..4].try_into().unwrap()), IFLA_IFNAME);
        assert_eq!(&attr[4..9], b"eth0\0");
        assert_eq!(&attr[9..12], &[0, 0, 0], "padding must be zeroed");
    }

    #[test]
    fn the_declared_length_excludes_padding_but_the_buffer_includes_it() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST);
        message.attr(IFLA_IFNAME, b"a");
        let bytes = message.finish(1);

        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 5);
        assert_eq!(bytes.len(), 24, "the attribute occupies 8 bytes once padded");
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 24);
    }

    #[test]
    fn a_nest_spans_everything_written_inside_it() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST);
        let link_info = message.nest(IFLA_LINKINFO);
        message.attr_str(IFLA_INFO_KIND, "veth");
        message.end(link_info);
        let bytes = message.finish(1);

        let nest = &bytes[NLMSGHDR_LEN..];
        // 4 nest header + (4 + "veth" = 8, already aligned) = 12.
        assert_eq!(u16::from_ne_bytes(nest[0..2].try_into().unwrap()), 12);
        assert_eq!(u16::from_ne_bytes(nest[2..4].try_into().unwrap()), IFLA_LINKINFO);
        assert_eq!(u16::from_ne_bytes(nest[4..6].try_into().unwrap()), 8);
        assert_eq!(&nest[8..12], b"veth");
    }

    #[test]
    fn nests_inside_nests_each_get_their_own_length() {
        let mut message = Message::new(RTM_NEWLINK, NLM_F_REQUEST);
        let link_info = message.nest(IFLA_LINKINFO);
        message.attr_str(IFLA_INFO_KIND, "veth");
        let info_data = message.nest(IFLA_INFO_DATA);
        let peer = message.nest(VETH_INFO_PEER);
        message.payload(&ifinfomsg(AF_UNSPEC, 0, 0, 0));
        message.attr_nul_str(IFLA_IFNAME, "eth0");
        message.end(peer);
        message.end(info_data);
        message.end(link_info);
        let bytes = message.finish(1);

        let outer = &bytes[NLMSGHDR_LEN..];
        let outer_len = u16::from_ne_bytes(outer[0..2].try_into().unwrap()) as usize;
        assert_eq!(outer_len, outer.len(), "the outer nest spans the rest of the message");

        // IFLA_INFO_KIND takes 8 bytes after the 4-byte outer header.
        let data = &outer[12..];
        let data_len = u16::from_ne_bytes(data[0..2].try_into().unwrap()) as usize;
        assert_eq!(u16::from_ne_bytes(data[2..4].try_into().unwrap()), IFLA_INFO_DATA);

        let peer = &data[4..data_len];
        assert_eq!(u16::from_ne_bytes(peer[2..4].try_into().unwrap()), VETH_INFO_PEER);
        // 4 peer header + 16 ifinfomsg + 12 for the NUL-terminated name.
        assert_eq!(u16::from_ne_bytes(peer[0..2].try_into().unwrap()), 32);
    }

    #[test]
    fn ifinfomsg_places_index_flags_and_change() {
        let bytes = ifinfomsg(AF_UNSPEC, 7, IFF_UP, IFF_UP);
        assert_eq!(bytes.len(), 16);
        assert_eq!(i32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), IFF_UP);
        assert_eq!(u32::from_ne_bytes(bytes[12..16].try_into().unwrap()), IFF_UP);
    }

    #[test]
    fn ifaddrmsg_and_rtmsg_are_their_documented_sizes() {
        assert_eq!(ifaddrmsg(AF_INET, 16, 0, 3).len(), 8);
        assert_eq!(
            rtmsg(AF_INET, 0, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST).len(),
            12
        );
    }

    #[test]
    fn ifaddrmsg_carries_the_prefix_length_and_index() {
        let bytes = ifaddrmsg(AF_INET, 16, 0, 3);
        assert_eq!(bytes[0], AF_INET);
        assert_eq!(bytes[1], 16);
        assert_eq!(u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 3);
    }

    /// Builds an NLMSG_ERROR the way the kernel does: the code, then a copy of
    /// the request header it is answering.
    fn ack(seq: u32, code: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(36u32).to_ne_bytes());
        out.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&code.to_ne_bytes());
        out.resize(36, 0);
        out
    }

    #[test]
    fn a_zero_error_code_is_the_success_acknowledgement() {
        assert_eq!(find_ack(&ack(4, 0), 4), Ack::Ok);
    }

    #[test]
    fn a_negative_error_code_becomes_a_positive_errno() {
        // The kernel reports -EEXIST; EEXIST is 17.
        assert_eq!(find_ack(&ack(4, -17), 4), Ack::Failed(17));
    }

    #[test]
    fn an_acknowledgement_for_another_request_is_not_ours() {
        assert_eq!(find_ack(&ack(9, 0), 4), Ack::Absent);
    }

    #[test]
    fn our_acknowledgement_is_found_after_someone_elses() {
        let mut buf = ack(9, 0);
        buf.extend_from_slice(&ack(4, -17));
        assert_eq!(find_ack(&buf, 4), Ack::Failed(17));
    }

    #[test]
    fn a_truncated_message_does_not_loop_or_panic() {
        assert_eq!(find_ack(&[0u8; 8], 1), Ack::Absent);
        // A zero length would otherwise leave the cursor where it was.
        assert_eq!(find_ack(&[0u8; 32], 1), Ack::Absent);
        assert_eq!(find_ack(&ack(4, 0)[..20], 4), Ack::Absent);
    }
}
