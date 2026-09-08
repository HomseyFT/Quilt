#!/bin/sh
# Phase 6: the same runtime as an ordinary user. No sudo anywhere, which is the
# whole point — running these as root would exercise the privileged half of
# every seam instead.
set -eu

cd "$(dirname "$0")/.."

if [ "$(id -u)" -eq 0 ]; then
    echo "rootless-tests.sh must not be run as root" >&2
    exit 1
fi

if [ ! -d rootfs ]; then
    echo "rootfs/ is missing; run scripts/make-rootfs.sh first" >&2
    exit 1
fi

purge() {
    for scope in "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/quilt/"*/; do
        [ -d "$scope" ] || continue
        [ -f "$scope/cgroup.kill" ] && echo 1 > "$scope/cgroup.kill" 2>/dev/null
        rmdir "$scope" 2>/dev/null || true
    done
    rm -rf "/run/user/$(id -u)/quilt"
}

purge
trap purge EXIT

binary="$(cargo test --test rootless --no-run --message-format=json \
    | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "rootless":
        print(m["executable"])' | tail -1)"

if [ -z "$binary" ]; then
    echo "could not locate the built test binary" >&2
    exit 1
fi

QUILT_TEST_ROOTLESS=1 QUILT_TEST_ROOTFS="$PWD/rootfs" "$binary" --test-threads=1 "$@"
