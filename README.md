# quilt

A Linux container runtime in Rust. See [SPEC.md](SPEC.md) for what it is and
where it is going.

Phases 1 and 2 are done: namespaces, mount setup, `pivot_root`, and cgroup v2
limits.

## Build

```sh
cargo build --release
```

## Run

`quilt` does not pull images — that is podman's job. Export one first:

```sh
scripts/make-rootfs.sh                 # populates ./rootfs from alpine
sudo ./target/release/quilt run ./rootfs /bin/sh
```

Root is required until phase 6: the identity id-map needs `CAP_SETUID` in the
parent user namespace.

```
quilt run [--hostname NAME] [--ro SRC[:DST]]...
          [--memory SIZE] [--cpus N] [--pids N]
          <ROOTFS> <COMMAND>...
```

`--memory` covers swap as well as memory, so the ceiling cannot be escaped by
swapping. The OCI spec separates the two, and phase 4 honours that split.

## Test

```sh
cargo test              # unit tests; no root, safe to run on every save
scripts/root-tests.sh   # phase 1 acceptance; builds as you, runs as root
```

`scripts/root-tests.sh` will ask for your sudo password.
