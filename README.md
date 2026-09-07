# quilt

A Linux container runtime in Rust. See [SPEC.md](SPEC.md) for what it is and
where it is going.

Phase 1 is done: namespaces, mount setup and `pivot_root`.

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
quilt run [--hostname NAME] [--ro SRC[:DST]]... <ROOTFS> <COMMAND>...
```

## Test

```sh
cargo test              # unit tests; no root, safe to run on every save
scripts/root-tests.sh   # phase 1 acceptance; builds as you, runs as root
```

`scripts/root-tests.sh` will ask for your sudo password.
