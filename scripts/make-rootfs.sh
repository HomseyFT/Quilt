#!/bin/sh
# Export an image's root filesystem into ./rootfs for the phase 1 demo.
# Pulling is podman's job, not quilt's: see the non-goals in SPEC.md.
set -eu

image="${1:-docker.io/library/alpine:latest}"
cd "$(dirname "$0")/.."

podman pull -q "$image"
container="$(podman create "$image" true)"
trap 'podman rm -f "$container" >/dev/null 2>&1 || true' EXIT

rm -rf rootfs
mkdir rootfs
podman export "$container" | tar -x -C rootfs

echo "rootfs/ populated from $image"
