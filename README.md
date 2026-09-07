# quilt

A Linux container runtime in Rust. See [SPEC.md](SPEC.md) for what it is and
where it is going.

Phases 1 to 5 are done: namespaces, mount setup, `pivot_root`, cgroup v2 limits,
hand-assembled rtnetlink for veth networking, the OCI runtime interface, and a
hand-assembled classic-BPF seccomp filter.

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
          [--net none|bridge]
          <ROOTFS> <COMMAND>...
```

`--memory` covers swap as well as memory, so the ceiling cannot be escaped by
swapping. The OCI spec separates the two, and phase 4 honours that split.

`--net bridge` puts the container on a shared `quilt0` bridge with NAT for
egress. It is deliberately outside the OCI path — the runtime spec does not
cover networking — so it exists on this CLI only.

It changes host state that outlives the container: `quilt0`, an nftables table
called `quilt`, and `net.ipv4.ip_forward`, which it sets to 1 and does not set
back. Forwarding is host-wide, and by the time a container exits something else
may be relying on it. quilt says on stderr when it is the one turning it on.
The veth pair is the only part torn down per container.

## As an OCI runtime

```sh
sudo podman --cgroup-manager=cgroupfs --runtime $(pwd)/target/release/quilt run --rm \
    --security-opt label=disable alpine ls /
```

Two flags more than you would like. Each is the alternative to silently ignoring
a security field in the bundle, which quilt refuses to do; both are non-goals,
see SPEC.md. The container's own seccomp profile is applied.

`--seccomp-log` puts every denial in the audit log, which is the difference
between debugging a filter and guessing at it.

The verbs work on their own too:

```
quilt [--root DIR] create --bundle DIR [--pid-file PATH] <ID>
quilt [--root DIR] start|state|delete [--force] <ID>
quilt [--root DIR] kill <ID> [SIGNAL]
```

## Test

```sh
cargo test              # unit tests; no root, safe to run on every save
scripts/root-tests.sh   # phase 1 acceptance; builds as you, runs as root
```

`scripts/root-tests.sh` will ask for your sudo password.

The netlink golden tests compare against captures of what `ip` puts on the wire.
They skip until those exist; `sudo scripts/capture-netlink.sh` records them into
`tests/golden/`, and they are meant to be committed.
