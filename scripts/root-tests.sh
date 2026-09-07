#!/bin/sh
# Build as the invoking user, then run the root-gated integration tests as root.
# Building under sudo would leave target/ owned by root.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d rootfs ]; then
    echo "rootfs/ is missing; run scripts/make-rootfs.sh first" >&2
    exit 1
fi

binary="$(cargo test --test root --no-run --message-format=json \
    | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "root":
        print(m["executable"])' | tail -1)"

if [ -z "$binary" ]; then
    echo "could not locate the built test binary" >&2
    exit 1
fi

# A killed or panicking run leaves root-owned state behind: cgroup scopes, veth
# ends, and bundles under /tmp that the invoking user cannot then remove. None
# of it is load-bearing, and leaving it lying around makes the next run fail for
# reasons that have nothing to do with the code.
purge() {
    sudo sh -c '
        for scope in /sys/fs/cgroup/quilt/*/; do
            [ -d "$scope" ] || continue
            [ -f "$scope/cgroup.kill" ] && echo 1 > "$scope/cgroup.kill" 2>/dev/null
            rmdir "$scope" 2>/dev/null
        done
        rmdir /sys/fs/cgroup/quilt 2>/dev/null

        rm -rf /tmp/quilt-oci-* /tmp/quilt-seccomp-* /tmp/quilt-ro-* \
               /tmp/quilt-ifindex-test /tmp/quilt-nl-*.pcap /run/quilt

        for link in /sys/class/net/qv*; do
            [ -e "$link" ] || continue
            ip link del "$(basename "$link")" 2>/dev/null
        done
        ip link del nlmon0 2>/dev/null
        exit 0
    '
}

purge
trap purge EXIT

# One at a time: the mount-propagation test compares global state.
# Not exec: the purge on the way out has to run.
sudo QUILT_TEST_ROOT=1 QUILT_TEST_PODMAN=1 QUILT_TEST_ROOTFS="$PWD/rootfs" \
    "$binary" --test-threads=1 "$@"
