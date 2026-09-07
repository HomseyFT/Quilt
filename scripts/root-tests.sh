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

# One at a time: the mount-propagation test compares global state.
exec sudo QUILT_TEST_ROOT=1 QUILT_TEST_PODMAN=1 QUILT_TEST_ROOTFS="$PWD/rootfs" \
    "$binary" --test-threads=1 "$@"
