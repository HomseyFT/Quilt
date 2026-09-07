#!/bin/sh
# Capture what `ip` puts on the netlink wire, for the golden byte tests.
#
# An nlmon interface is a tap on netlink itself: every message the kernel sees
# shows up on it. We run `ip` alongside a capture, pull the request back out,
# and store it as hex for src/net/veth.rs to compare against.
#
# Needs root. Run once; commit what lands in tests/golden/.
set -eu

cd "$(dirname "$0")/.."
mkdir -p tests/golden

if [ "$(id -u)" -ne 0 ]; then
    echo "capture-netlink.sh needs root: nlmon and tcpdump both do" >&2
    exit 1
fi

PEER_NS=""

cleanup() {
    ip link del qvgolden 2>/dev/null || true
    ip link del quilt-golden-br 2>/dev/null || true
    ip link del nlmon0 2>/dev/null || true
    [ -n "$PEER_NS" ] && kill "$PEER_NS" 2>/dev/null || true
}
trap cleanup EXIT

ip link del nlmon0 2>/dev/null || true
ip link add nlmon0 type nlmon
ip link set nlmon0 up

# A process to own the netns the veth peer is moved into, so the capture sees
# the same IFLA_NET_NS_PID shape quilt sends.
capture() {
    name=$1
    want_type=$2
    shift 2

    pcap=$(mktemp /tmp/quilt-nl-XXXXXX.pcap)
    tcpdump -i nlmon0 -w "$pcap" -U -Q inout >/dev/null 2>&1 &
    tcpdump_pid=$!
    sleep 1

    "$@" >/dev/null 2>&1 || true
    sleep 1
    kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true

    python3 - "$pcap" "$want_type" "tests/golden/$name" <<'PY'
import struct, sys

pcap_path, want_type, out_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
NLM_F_REQUEST = 0x1

with open(pcap_path, "rb") as fh:
    blob = fh.read()

magic = blob[:4]
if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    endian = "<"
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    endian = ">"
else:
    sys.exit(f"{pcap_path}: not a pcap file")

offset = 24
packets = []
while offset + 16 <= len(blob):
    _, _, incl, _ = struct.unpack(endian + "IIII", blob[offset:offset + 16])
    offset += 16
    packets.append(blob[offset:offset + incl])
    offset += incl

# The link-layer header nlmon puts in front of the message is not worth
# assuming: scan for a well-formed nlmsghdr of the type we asked for instead.
def find(packet):
    for at in range(0, len(packet) - 16):
        length, kind, flags = struct.unpack_from("=IHH", packet, at)
        if kind != want_type or not flags & NLM_F_REQUEST:
            continue
        if not 16 <= length <= len(packet) - at:
            continue
        return bytearray(packet[at:at + length])
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
    print(f"{out_path}: {len(message)} bytes")
    sys.exit(0)

sys.exit(f"no request of type {want_type} was captured")
PY
    rm -f "$pcap"
}

# RTM_NEWLINK is 16, RTM_SETLINK is 19.
capture bridge-add.hex 16 ip link add quilt-golden-br type bridge
ip link del quilt-golden-br 2>/dev/null || true

# Hold a netns open so `netns 1` has the same shape as quilt's peer move.
capture veth-add.hex 16 ip link add qvgolden type veth peer name eth0 netns 1

ip link add qvgolden type veth peer name qvgoldenp 2>/dev/null || true
capture link-up.hex 19 ip link set qvgolden up

echo
echo "Captured into tests/golden/. Re-run cargo test to compare."
