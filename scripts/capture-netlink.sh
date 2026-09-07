#!/bin/sh
# Capture what `ip` puts on the netlink wire, for the golden byte tests.
#
# An nlmon interface taps netlink itself — but it taps ALL of it, not just ours.
# NetworkManager, firewalld and podman are all talking on the same bus, so the
# extractor below filters on the interface name inside the message rather than
# taking the first thing that structurally resembles a request. Without that,
# an unrelated nftables message can contain a byte offset whose length/type
# fields happen to look plausible, and it gets written out as truth.
#
# Needs root. Re-run whenever the message builders change; commit tests/golden/.
set -eu

cd "$(dirname "$0")/.."
mkdir -p tests/golden

if [ "$(id -u)" -ne 0 ]; then
    echo "capture-netlink.sh needs root: nlmon and tcpdump both do" >&2
    exit 1
fi

# The peer name has to be the one quilt uses, so it must be free on the host.
if [ -e /sys/class/net/eth0 ]; then
    echo "this host has an interface called eth0; the veth capture needs that name" >&2
    exit 1
fi

cleanup() {
    ip link del qvgolden 2>/dev/null || true
    ip link del quilt0 2>/dev/null || true
    ip link del nlmon0 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip link add nlmon0 type nlmon
ip link set nlmon0 up

# capture <output> <nlmsg_type> <ifname the message must name> <command...>
capture() {
    out="tests/golden/$1"
    want_type=$2
    want_name=$3
    shift 3

    # Remove it first, so a failed capture leaves no stale golden behind.
    rm -f "$out"

    pcap=$(mktemp /tmp/quilt-nl-XXXXXX.pcap)
    tcpdump -i nlmon0 -w "$pcap" -U -Q inout >/dev/null 2>&1 &
    tcpdump_pid=$!
    sleep 1

    "$@" >/dev/null 2>&1 || true
    sleep 1
    kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true

    python3 - "$pcap" "$want_type" "$want_name" "$out" <<'PY'
import struct, sys

pcap_path, want_type, want_name, out_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

NLM_F_REQUEST = 0x1
IFLA_IFNAME = 3
IFINFOMSG_LEN = 16
NLMSGHDR_LEN = 16

with open(pcap_path, "rb") as fh:
    blob = fh.read()

magic = blob[:4]
if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    endian = "<"
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    endian = ">"
else:
    sys.exit(f"{pcap_path}: not a pcap file")

offset, packets = 24, []
while offset + 16 <= len(blob):
    _, _, incl, _ = struct.unpack(endian + "IIII", blob[offset:offset + 16])
    offset += 16
    packets.append(blob[offset:offset + incl])
    offset += incl


def names(message):
    """Every IFLA_IFNAME in the message's top-level attribute list."""
    at = NLMSGHDR_LEN + IFINFOMSG_LEN
    found = []
    while at + 4 <= len(message):
        length, kind = struct.unpack_from("=HH", message, at)
        if length < 4 or at + length > len(message):
            break
        if kind == IFLA_IFNAME:
            found.append(message[at + 4:at + length].rstrip(b"\x00").decode("ascii", "replace"))
        at += (length + 3) & ~3
    return found


def find(packet):
    # The link-layer header nlmon puts in front is not worth assuming, so every
    # offset is tried -- but a candidate only counts if it is a whole message
    # that names the interface we are capturing for.
    for at in range(0, len(packet) - NLMSGHDR_LEN):
        length, kind, flags = struct.unpack_from("=IHH", packet, at)
        if kind != want_type or not flags & NLM_F_REQUEST:
            continue
        if length < NLMSGHDR_LEN + IFINFOMSG_LEN:
            continue
        # The message must end where the packet does, give or take padding.
        trailing = len(packet) - (at + length)
        if not 0 <= trailing < 4:
            continue
        message = bytearray(packet[at:at + length])
        if want_name not in names(message):
            continue
        return message
    return None


for packet in packets:
    message = find(packet)
    if message is None:
        continue
    # nlmsg_seq and nlmsg_pid are per-socket bookkeeping; zero them so the
    # comparison is about the request itself.
    message[8:16] = b"\x00" * 8
    with open(out_path, "w") as fh:
        fh.write(" ".join(f"{b:02x}" for b in message) + "\n")
    print(f"{out_path}: {len(message)} bytes, names {want_name}")
    sys.exit(0)

sys.exit(f"no type-{want_type} request naming {want_name} was captured")
PY
    rm -f "$pcap"
}

# RTM_NEWLINK is 16, RTM_SETLINK is 19. The names must be the ones the message
# builders in src/net/veth.rs use, or the comparison can never match.
capture bridge-add.hex 16 quilt0 \
    ip link add quilt0 type bridge
ip link del quilt0 2>/dev/null || true

# Deliberately without `netns`: iproute2 resolves that argument to an open
# descriptor and sends IFLA_NET_NS_FD, while quilt has the child's pid and
# sends IFLA_NET_NS_PID. There is no invocation of `ip` that produces quilt's
# shape, so the netns attribute is pinned by a unit test instead and the
# capture covers the rest of the nest.
capture veth-add.hex 16 qvgolden \
    ip link add qvgolden type veth peer name eth0

capture link-up.hex 19 qvgolden \
    ip link set qvgolden up

# The script runs under sudo, so without this the captures land root-owned and
# cannot be rewritten or removed by the user who has to commit them.
if [ -n "${SUDO_UID:-}" ]; then
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" tests/golden/*.hex
fi

echo
echo "Captured into tests/golden/. Re-run cargo test to compare."
