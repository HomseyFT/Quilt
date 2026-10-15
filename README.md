# quilt

A Linux container runtime in Rust.

All six phases are done: namespaces, mount setup, `pivot_root`, cgroup v2
limits, hand-assembled rtnetlink for veth networking, the OCI runtime interface,
a hand-assembled classic-BPF seccomp assembler for the profiles a bundle sends,
and rootless operation.

## Build

```sh
cargo build --release
```

## Run

`quilt` does not pull images — that is podman's job. Export one first:

```sh
scripts/make-rootfs.sh                 # populates ./rootfs from alpine
./target/release/quilt run ./rootfs /bin/sh
```

As root the id map is the identity; as an ordinary user it comes from
`/etc/subuid` through `newuidmap`, and the container's root is you.

```
quilt run [--hostname NAME] [--ro SRC[:DST]]...
          [--memory SIZE] [--cpus N] [--pids N]
          [--net none|bridge|pasta]
          <ROOTFS> <COMMAND>...
```

`run` is a demo of namespaces, mounts and cgroups, not a sandbox. It installs
no seccomp filter and drops no capabilities: quilt writes no policy of its own,
and the only filters and capability sets it applies are the ones a bundle asks
for, on the OCI path below.

`--memory` covers swap as well as memory, so the ceiling cannot be escaped by
swapping. The OCI spec separates the two, and phase 4 honours that split.

`--net bridge` puts the container on a shared `quilt0` bridge with NAT for
egress, and needs root: creating a link and adding a NAT rule are privileged
however the id map is written. `--net pasta` does the same job from user space
and is what an unprivileged container uses. Both are deliberately outside the
OCI path — the runtime spec does not cover networking — so they exist on this
CLI only.

It changes host state that outlives the container: `quilt0`, an nftables table
called `quilt`, and `net.ipv4.ip_forward`, which it sets to 1 and does not set
back. Forwarding is host-wide, and by the time a container exits something else
may be relying on it. quilt says on stderr when it is the one turning it on.
The veth pair is the only part torn down per container.

## As an OCI runtime

```sh
podman --cgroup-manager=cgroupfs --runtime $(pwd)/target/release/quilt run --rm \
    --security-opt label=disable alpine ls /
```

No `sudo`: rootless works, and the container is root inside while the process is
yours outside. As root the same command runs through the privileged half of each
seam instead.

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
cargo test                  # unit tests; no root, safe to run on every save
scripts/rootless-tests.sh   # the unprivileged path; must not be run as root
scripts/root-tests.sh       # the privileged path; builds as you, runs as root
```

`scripts/root-tests.sh` will ask for your sudo password.

The netlink golden tests compare against captures of what `ip` puts on the
wire, committed under `tests/golden/`. A missing capture fails the test rather
than skipping it — it means a broken checkout, not an absent option.
`sudo scripts/capture-netlink.sh` re-records them when the message builders
change.
