# quilt — a container runtime from scratch

A Linux container runtime in Rust, built to learn the kernel interfaces that
containers are actually made of. Ends as a drop-in replacement for `crun` under
podman.

## Why this project

Every substantial thing in this tree is Python. The stated interest is low-level
systems. A container runtime is almost entirely kernel interface work —
namespaces, cgroups, mount propagation, seccomp, netlink — with no language
design in it, and there is already a 12-service Docker homelab here to give the
work a context and a test bed.

## Goals

- Run an unmodified container image with real isolation: PID, mount, network,
  UTS, IPC and user namespaces.
- Enforce resource limits through cgroups v2.
- Apply a syscall policy written as hand-assembled classic-BPF.
- Satisfy enough of the OCI runtime spec that `podman --runtime` drives it.
- Do the above as an unprivileged user (phase 6).

## Non-goals

These are deliberately excluded. Each is real work, none of it teaches kernel
interfaces.

| Excluded | Why |
|---|---|
| Registry client / `pull` | HTTP, OAuth token dance, manifest lists. Podman already does it; `podman export` produces a rootfs in one command. |
| Networking in the OCI path | The OCI runtime spec does not cover networking. `runc` and `crun` create or join a netns and stop. Podman wires it up with netavark. Building it there would fight the caller. |
| `libseccomp` | It would hide the single most on-theme piece of work in the project. |
| A daemon, an API, a UI | Runtimes are one-shot processes. Podman is the thing with a lifecycle. |
| SELinux and AppArmor labelling | `setexeccon` and a policy toolchain, not a kernel interface worth learning twice. `linux.mountLabel` is honoured because it is a `context=` string passed to `mount(2)`; the process label is refused rather than ignored. |
| systemd cgroup scopes | The systemd form of `cgroupsPath` means asking systemd for a transient scope over dbus. Writing the files by hand underneath it fights the manager, the same mistake as building networking into the OCI path. |

## Language and dependencies

Rust 1.95, edition 2024.

| Crate | Role |
|---|---|
| `rustix` | Typed syscall wrappers. Provides the syscall; all policy and sequencing is hand-written. |
| `serde` + `serde_json` | `config.json` deserialization (phase 4 only). |
| `clap` | Argument parsing. |

No `libseccomp`, no `netlink-*` crate, no `nix`. The seccomp filter and the
netlink messages are assembled byte by byte — that is the point.

`rustix` does not cover everything either. `clone3`, `close_range` and
`mount_setattr` are all on its `not_implemented!` list, so those are issued from
`syscall.rs` as hand-written x86-64 syscalls. That is the same bargain as the
rest of the table: the syscall is ours, the sequencing is ours.

## Architecture

```
src/
  main.rs           CLI dispatch
  error.rs          error type carrying the errno
  syscall.rs        raw x86-64 syscalls rustix does not wrap
  spec.rs           OCI config.json types                    (phase 4)
  container.rs      lifecycle state machine, state on disk
  init.rs           the re-exec'd child: the "quilt init" process
  ns.rs             clone3 flags, namespace entry ordering
  idmap.rs          IdMapper trait — Identity | SubUid
  cgroup.rs         CgroupDriver trait — RootCgroup | Delegated
  mount.rs          MountPlan: pivot_root, procfs, sysfs, /dev, ro binds
  seccomp.rs        classic-BPF assembler + default policy
  caps.rs           bounding set, no_new_privs
  net/
    mod.rs          the --net modes
    netlink.rs      hand-rolled rtnetlink message encoder    (phase 3)
    veth.rs         veth pair, bridge, address assignment    (phase 3)
```

### The three seams

Rootless is phase 6, but three decisions would be a rewrite if hardcoded now.
Each is a trait from the first commit, with the root implementation written
first and the rootless one added later behind it.

```rust
trait IdMapper     { fn write_maps(&self, pid: Pid) -> Result<()>; }
trait CgroupDriver { fn scope(&self, controllers: &[&str]) -> Result<PathBuf>; }
trait MountStrategy{ fn prepare(&self, rootfs: &Path) -> Result<MountPlan>; }
```

`Identity` writes `0 0 4294967295`. `SubUid` shells out to `newuidmap`, which
is setuid and is the only sanctioned way an unprivileged process gets a range.
`RootCgroup` uses `/sys/fs/cgroup/quilt/<id>`; `Delegated` resolves
`/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/quilt/<id>`,
which systemd is already delegating on this machine.

### The init-process dance

`create` and `start` are separate verbs in the OCI spec, so something must exist
between them holding the namespaces open with the workload not yet running.
The standard shape, which quilt copies:

1. `quilt create` clones a child with the namespace flags.
2. The child re-execs `/proc/self/exe init` — a fresh image, so no parent state
   leaks and the mount setup runs in a process that is already in the new
   namespaces.
3. The init process completes the mount plan, then blocks reading an exec fifo.
4. `quilt start` opens the fifo for writing, which unblocks the read.
5. Init applies seccomp and caps **last**, then `execve`s the workload.

Seccomp goes on immediately before `execve` because the setup itself needs
`mount`, `pivot_root` and `write` to cgroup files — syscalls the policy denies.

## Phases

Each phase has a demo you can run and an acceptance test.

### Phase 1 — namespaces and a shell

`quilt run ./rootfs /bin/sh` gives a shell that cannot see the host.

- `clone3` with `CLONE_NEWNS|NEWPID|NEWNET|NEWUTS|NEWIPC|NEWUSER`
- Recursive `MS_PRIVATE` on `/` so nothing propagates back to the host
- `pivot_root` with the `put_old` detach, not `chroot`
- `/proc`, `/sys`, a minimal `/dev` (bind `null`, `zero`, `random`, `urandom`,
  `tty`), `tmpfs` on `/dev/shm`
- Read-only bind mounts via `mount_setattr` with `AT_RECURSIVE`. The classic
  mount-then-remount two-step covers only the top mount, and inside a user
  namespace it must also carry forward every flag the kernel locked on the way
  in or it fails with a bare EPERM. `mount_setattr` sets and clears nothing
  else, so no locked flag is at stake, and it reaches submounts in one call
- Hostname set in the new UTS namespace

**Accepts when:** `ps aux` inside shows the shell as PID 1; `ip addr` shows only
`lo`; `mount` output is the container's; `hostname` differs from the host; and
no mount created inside is visible in the host's `/proc/self/mountinfo`.

### Phase 2 — cgroups v2 and limits

`quilt run --memory 64M --cpus 0.5 ./rootfs stress`

- Create the scope, enable controllers via `cgroup.subtree_control`. Two
  structural rules shape the layout and both surface as a bare ENOENT or EBUSY:
  a controller's files only exist in a cgroup if its parent enabled it, and a
  cgroup holding children cannot hold processes. So `quilt/` is a pure parent
  and `quilt/<id>` is the leaf that holds the limits and the workload
- Enable only the controllers this container's limits are written with, not a
  fixed set of all three. Root can enable anything, so the difference is
  invisible until phase 6: a delegated subtree offers whatever systemd handed
  the user session, and `cpu` delegation to `user@.service` only became the
  default in systemd v252. Demanding `cpu` for a container that sets no CPU
  limit refuses to run on an older machine for the sake of a file nothing was
  going to write
- Write `memory.max`, `memory.swap.max`, `cpu.max`, `pids.max`. The swap ceiling
  is not optional: without it the kernel swaps anonymous pages out to stay under
  `memory.max` rather than OOM-killing, and on a machine with zram the memory
  limit is then not a limit. OCI splits memory from swap, and phase 4 honours
  that split; the bespoke `--memory` covers both
- Birth the container inside the scope with `CLONE_INTO_CGROUP`, rather than
  writing its pid to `cgroup.procs` afterwards. The second leaves a window in
  which the workload runs under no limits at all, which is not hypothetical for
  a fork bomb or a large allocation in the first milliseconds
- Read `memory.events` to prove the limit fired
- Tear the scope down with `cgroup.kill`, waiting for `cgroup.events:populated`
  to reach zero before the rmdir, on the failure paths too. `waitpid` returns
  when pid 1 is reaped, but the rest of that pid namespace is killed and
  reparented asynchronously, so an rmdir straight after the wait races it
- Give each scope an id unique to the invocation. Pids recycle, and a scope left
  behind by an earlier run would otherwise be reused by a run that asked for
  different limits, silently inheriting the ones it did not set

**Accepts when:** a process allocating past `memory.max` is OOM-killed and
`memory.events:oom_kill` increments; `pids.max` blocks a fork bomb; the scope
directory is gone after the container exits, including when a child outlives
pid 1 and when the container never started.

### Phase 3 — networking, by hand

`quilt run --net bridge ./rootfs ping 1.1.1.1`

Out of the OCI path on purpose — this hangs off the bespoke CLI only.

- A rtnetlink message encoder written against `RTM_NEWLINK` etc., with nested
  attribute support. The veth request is the deepest nest and the reason the
  encoder has to be general: `IFLA_LINKINFO` holds `IFLA_INFO_KIND` and
  `IFLA_INFO_DATA`, and `IFLA_INFO_DATA` holds `VETH_INFO_PEER`, which is a
  whole second `ifinfomsg` with its own attributes
- veth pair, the peer moved into the container netns by pid. `IFLA_NET_NS_PID`
  goes inside `VETH_INFO_PEER`, so the far end is born in the container's netns
  rather than created on the host and moved afterwards. It is therefore never
  visible on the host and cannot collide with a host interface already called
  `eth0`
- Host bridge, address assignment, default route. The address ordering is
  load-bearing: the default route needs the connected prefix, which only appears
  once the link is up
- Interface indices come from `/sys/class/net/<name>/ifindex` rather than an
  `RTM_GETLINK` round trip. The phase is about what goes out on the wire, and a
  reply parser is a second job
- Address allocation is seeded from the runtime's own pid, which is unique among
  the containers running at one time. That is all a bridge with a handful of
  containers needs; real IPAM belongs to podman, which is why networking is out
  of the OCI path in the first place
- Masquerade rule for egress, applied through `nft`. nf_tables netlink is a
  second encoder as large as this whole phase and it teaches the same lesson
  twice, so this takes the same bargain phase 6 takes with `newuidmap`: shell
  out to the tool that owns the interface

**Accepts when:** the container reaches the internet, and the encoder agrees
with what `ip` puts on the wire — captured with `nlmon` by
`scripts/capture-netlink.sh` and stored under `tests/golden/`.

The bar is split, because "byte-identical to `ip`" turns out to be the wrong
target for most messages. Several differences between two encodings are
semantically invisible: attribute order, which the kernel parses into a table;
a trailing NUL, which `nla_strcmp` strips before comparing; and identifying a
link by `ifi_index` rather than by `IFLA_IFNAME`. Pinning those would encode
iproute2's style into this suite and break on its next release, without ever
catching a bug.

- **Byte-identical** for the veth creation message. It is the deepest nest in
  the project and the place an encoding bug would actually live, so it is worth
  matching exactly. Two divergences found this way were real and are fixed:
  `IFLA_INFO_KIND` goes on the wire without a terminator while `IFLA_IFNAME`
  goes with one — the convention is per attribute, not per protocol — and the
  namespace attribute precedes the name inside `VETH_INFO_PEER`.
- **Structural** for the rest: decode both sides and compare message type,
  flags, the fixed struct, and the attribute tree as a set with string
  terminators normalised. That is what the kernel reads.
- **Directly pinned** for the one thing no capture can cover. `ip`'s `netns`
  argument resolves to an open descriptor and goes out as `IFLA_NET_NS_FD`;
  quilt holds the child's pid and sends `IFLA_NET_NS_PID`. No invocation of
  `ip` produces quilt's shape, so a unit test asserts those eight bytes instead
  and the capture is taken without a netns.

Sequence number and port id are zeroed on both sides throughout: they are
per-socket bookkeeping rather than part of the request.

Capturing is not as simple as it sounds, and the trap is worth recording: an
`nlmon` interface taps every netlink conversation on the machine, not just this
one. Scanning a captured packet for a plausible `nlmsghdr` will happily find a
false positive inside an unrelated nftables message and write it out as truth.
The extractor filters on the interface name carried inside the message.

The bridge and the nftables table outlive containers on purpose — they are
shared fabric, and tearing them down would cut off whatever else is still
attached. So does `net.ipv4.ip_forward`, which is host-wide: by the time a
container exits, something else may be relying on it. A one-shot runtime should
not change a machine-wide kernel setting silently, so quilt says on stderr when
it is the one turning it on. The veth is the only part torn down per container:
deleting the host end takes the peer with it, on every path out.

### Phase 4 — OCI runtime spec

```
sudo podman --cgroup-manager=cgroupfs --runtime $(pwd)/target/release/quilt run --rm \
    --security-opt label=disable alpine ls /
```

Two flags more than you would like, and each one is the alternative to silently
ignoring a security field, which is the outcome this phase exists to avoid. Both
are permanent, for the reasons in the non-goals table. A third,
`--security-opt seccomp=unconfined`, was needed until phase 5 applied the
profile rather than refusing it.

- `create` / `start` / `state` / `kill` / `delete`
- `config.json` deserialization, honouring the subset that matters
- State persisted where the spec says, in the format it says
- Exit codes and error messages the caller expects

What "the subset that matters" is should come from podman rather than from the
spec document: a shim runtime that logs its argv and copies the bundle, then
hands off to `crun`, says exactly what a real `podman run` asks for. Doing that
first changed four decisions:

- The network namespace arrives as a **path** to join, not a request to create.
  This is what `setns` and the namespace entry ordering in `ns.rs` were for
- There is **no user namespace** in the config. Podman has already made one
  outside, so the `IdMapper` seam goes unused in the OCI path
- A **cgroup namespace** is requested, so `CLONE_NEWCGROUP` turns on
- `devpts` is in the mount list, which settles the `/dev/pts` question phase 1
  deferred — podman states the options, so there is nothing to guess

The capability work straddles the user change, and the order is forced. The
bounding-set sweep needs `CAP_SETPCAP` in the *effective* set, and any move off
uid 0 empties effective outright — `PR_SET_KEEPCAPS` preserves the permitted set
and nothing else. So the bounding set is narrowed first, while still root, and
the effective/permitted/inheritable sets are applied afterwards, where raising
effective out of permitted needs no privilege of its own. Dropping `CAP_SETUID`
and `CAP_SETGID` from the bounding set does not disturb the copies in effective,
so becoming the container's user still works in between. None of this is visible
at uid 0, which is what every default bundle asks for, so the acceptance tests
include a `--user` case on purpose.

`create` must not report success for a container that cannot run. Init reports
it survived setup *before* it parks on the exec fifo, so anything checked after
that point is discovered at `start` — by which time the caller has been told the
container exists. Everything decidable from the bundle alone is therefore
decided during `create`: the seccomp profile is assembled and thrown away, and
the capability and rlimit names are resolved. A profile using an action quilt
cannot build is the case that shows why, since the container would otherwise be
created, started, and only then refuse to run.

Two things a bundle does not say, which the runtime owes it anyway:

- **The default devices.** `linux.devices` is empty and the mount list stops at
  putting a tmpfs on `/dev`, because the spec makes `/dev/null`, `zero`, `full`,
  `random`, `urandom` and `tty` the runtime's job. This is not a missing
  convenience: masking a path binds `/dev/null` over it, so a container with
  `maskedPaths` and an empty `/dev` cannot be created at all
- **`/dev/ptmx`**, as a symlink into the devpts instance, when one is mounted

And one the bundle says that cannot be taken literally: `linux.mountLabel`
survives `--security-opt label=disable`, and it is honoured by passing
`context=` to `mount(2)` — but only for tmpfs and devpts. mqueue answers EINVAL,
which arrives as an unexplained mount failure several steps into the plan.

`process` and `linux` deserialize with `deny_unknown_fields`. They are where the
security-bearing settings live, and a field quilt has never heard of is exactly
the one it must not skip past. The price is that a future podman adding a field
makes quilt complain rather than quietly ignore it, which is the right way round.
The captured configs are committed under `tests/fixtures/` and parsed by the unit
tests, so "every field podman sends is named by a struct" stays a checked claim.

Root-only at this phase, hence `sudo podman`.

**Accepts when:** podman runs a container end to end through quilt, and the
`opencontainers/runtime-tools` validation suite passes its namespace, cgroup
and mount groups.

### Phase 5 — seccomp

A hand-assembled classic-BPF filter, no library.

- A small assembler with labels and jump-offset resolution. The offsets are the
  point: they count from the *following* instruction, only go forward, and live
  in a single byte. That last limit is not theoretical — the first layout here
  used one shared kill return at the end of the program, and podman's profile
  put it 780 instructions away. Each architecture check now carries its own
  return, which costs eight bytes and assembles
- Architecture check first — validate `AUDIT_ARCH_X86_64` before reading the
  syscall number, or a 32-bit caller walks straight through the filter
- Default-deny with an allowlist, `SECCOMP_RET_ERRNO` over `KILL` so failures
  are debuggable, and `--seccomp-log` to put every denial in the audit log
- Syscall names the architecture does not have are skipped rather than refused.
  79 of the 432 podman sends are 32-bit or x32 spellings like `chown32`; they
  cannot be called here, and a caller from the architecture that has them is
  killed by the check above
- Honour the `linux.seccomp` section of `config.json`, which is what removes
  `--security-opt seccomp=unconfined` from the phase 4 demo

**Accepts when:** a denied syscall returns an errno rather than killing the
process, podman's real profile compiles and decides every rule the way it is
written, and the phase 4 demo drops `--security-opt seccomp=unconfined`.

Byte-identity with libseccomp was the original bar and is the wrong one.
libseccomp sorts the syscall set and emits a binary-search jump tree; quilt
emits rules in profile order. Both are correct and they share no bytes, so
matching would mean reimplementing another project's optimiser to reproduce its
layout — pinning its style rather than catching anything.

What the tier was actually for still holds: "catches a filter that is subtly
wrong but still loads". So the filter is run rather than read. `simulate` is a
classic-BPF interpreter, and the tests assemble podman's 432-name profile and
assert what it decides for each of 300-odd syscalls. That catches the failures
that matter and byte comparison would not:

- an argument test that only compares the low 32 bits, so `0x1_0000_0000`
  passes a test for zero
- a rule that reads an argument and leaves it in the accumulator, so every
  later rule compares an argument value against a syscall number
- an x32 caller reaching the allowlist under the x86-64 architecture token

### Phase 6 — rootless

Plain `podman --runtime quilt`, no sudo anywhere.

- `SubUid` mapper via `newuidmap` / `newgidmap`
- `Delegated` cgroup driver under `user@1000.service`, found by reading this
  process's own cgroup rather than by constructing the path: `user@<uid>.service`
  is where systemd hands the subtree over, and everything above it is not ours
- Connectivity via `pasta`. It has to be told to join the *user* namespace as
  well as the network one — the netns is owned by the userns the clone made, and
  joining a netns needs CAP_SYS_ADMIN in its owner. It also needs
  `--no-netns-quit`: that watch is for a namespace bound into `/run/netns`, and
  the container's is a live process's namespace instead
- **Not** idmapped mounts. `MOUNT_ATTR_IDMAP` needs CAP_SYS_ADMIN in the user
  namespace that owns the filesystem's superblock, so an unprivileged process
  cannot idmap a host filesystem: the call returns EPERM, and idmapping a tmpfs
  made inside the namespace with that same namespace returns EINVAL. Both were
  measured rather than assumed.

  The outcome the bullet wanted arrives anyway, from the mapping instead of the
  mount. `SubUid` maps container uid 0 to the invoking user, so a rootfs
  unpacked by that user is already owned by root inside, with no chown pass. A
  bundle that asks for a per-mount id mapping is refused rather than ignored.

Telling privilege apart is its own problem, and getting it wrong is silent.
`geteuid()` returns 0 inside a user namespace, so a rootless runtime believes it
is root while every write lands as the real user; and the identity id-map is not
enough either, because an ordinary user's shell has one. Privilege over the host
is both together. The id a rootless runtime needs for `/run/user/<uid>`,
`user@<uid>.service` and the owner of a subordinate range is its id *outside*
the namespace, which comes from translating the inside id back out through
`/proc/self/uid_map` — and the same for the gid through `gid_map`, since
`newgidmap` checks the request against the outside gid.

**Accepts when:** the phase-4 podman demo runs as your normal user, and
`ps -o user` shows `nathan` outside while `id` inside shows uid 0.

These run as an ordinary user by construction, so they are their own tier —
`scripts/rootless-tests.sh`, which refuses to run under sudo. Running them as
root would exercise the privileged half of every seam and prove nothing about
this phase.

## Testing

Four tiers, mirroring how QuinLang and Finance are already tested.

**Pure unit.** Config parsing, cgroup value formatting, mount ordering,
capability set arithmetic, jump-offset resolution in the BPF assembler. No root,
runs on every save.

**Golden bytes.** The two encoders emit bytes, so they get pinned against a
reference implementation:

- seccomp: diff against libseccomp's output for the same policy (as a dev-only
  comparison, not a dependency)
- config.json: the bundles podman really produces, committed under
  `tests/fixtures/` and parsed by the unit tests. `deny_unknown_fields` turns
  that into a completeness check rather than a smoke test
- netlink: capture what `ip` sends using an `nlmon` interface, store as golden.
  `scripts/capture-netlink.sh` does the capture; the comparison lives in
  `src/net/veth.rs` beside the message builders, which are split from the
  senders so a message can be built and inspected without a socket

This is the tier that catches a filter that is subtly wrong but still loads —
the failure mode that manual testing never finds.

**Rootless integration.** Gated behind `QUILT_TEST_ROOTLESS=1`, and refuses to
run as root. Every seam picks its second implementation precisely because the
caller is unprivileged, so this is the only tier that exercises those halves.

**Root integration.** Gated behind `QUILT_TEST_ROOT=1` so a plain `cargo test`
stays safe. Asserts on observable behaviour: PID 1 inside, OOM kill fires, mount
namespace does not leak.

**External validation.** `oci-runtime-tool validate` from phase 4 onward, and
the podman demo itself as the end-to-end check.

## Risks

**Mount propagation is subtle and fails quietly.** A missing `MS_PRIVATE` means
container mounts appear on the host and survive the container. Mitigate by
asserting on host `/proc/self/mountinfo` before and after in phase 1's tests,
from the very first commit.

**Seccomp debugging is miserable.** A denied syscall surfaces as an
unexplained failure deep inside a program you did not write. Using
`SECCOMP_RET_ERRNO` rather than `SECCOMP_RET_KILL_PROCESS` during development,
and keeping `SECCOMP_RET_LOG` available behind a flag, is what makes phase 5
tractable.

**Phase 4 can turn into JSON plumbing.** The OCI spec is large and most of it
does not matter here. Implement only the fields podman actually sends for a
default `podman run`, and return a clear error for anything else rather than
silently ignoring it — silently ignoring a security field is the bad outcome.

**Scope creep toward a mini-docker.** The pull/layer/registry direction is
always tempting and always the wrong layer. The overlayfs layer store is the one
piece of that worth building, and only after phase 4.

## Reference material

- `man 7 namespaces`, `man 2 clone3`, `man 2 pivot_root`, `man 7 mount_namespaces`
- `man 2 seccomp`, `Documentation/userspace-api/seccomp_filter.rst` in the kernel tree
- `Documentation/admin-guide/cgroup-v2.rst`
- The OCI runtime spec, `opencontainers/runtime-spec`
- `crun` source — small enough to read, C, and it is the thing you are replacing
