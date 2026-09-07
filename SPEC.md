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
trait CgroupDriver { fn scope(&self) -> Result<PathBuf>; }
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

**Accepts when:** the encoder's output is byte-identical to what `ip link add`
puts on the wire (captured with `nlmon` by `scripts/capture-netlink.sh`, stored
under `tests/golden/`, compared with the sequence number and port id zeroed
since those are per-socket bookkeeping rather than part of the request), and the
container reaches the internet.

The bridge and the nftables table outlive containers on purpose — they are
shared fabric, and tearing them down would cut off whatever else is still
attached. So does `net.ipv4.ip_forward`, which is host-wide: by the time a
container exits, something else may be relying on it. A one-shot runtime should
not change a machine-wide kernel setting silently, so quilt says on stderr when
it is the one turning it on. The veth is the only part torn down per container:
deleting the host end takes the peer with it, on every path out.

### Phase 4 — OCI runtime spec

`sudo podman --runtime $(pwd)/target/release/quilt run --rm alpine ls /`

- `create` / `start` / `state` / `kill` / `delete`
- `config.json` deserialization, honouring the subset that matters
- State persisted where the spec says, in the format it says
- Exit codes and error messages the caller expects

Root-only at this phase, hence `sudo podman`.

**Accepts when:** podman runs a container end to end through quilt, and the
`opencontainers/runtime-tools` validation suite passes its namespace, cgroup
and mount groups.

### Phase 5 — seccomp

A hand-assembled classic-BPF filter, no library.

- A small assembler: `bpf_stmt`, `bpf_jump`, jump-offset resolution
- Architecture check first — validate `AUDIT_ARCH_X86_64` before reading the
  syscall number, or a 32-bit caller walks straight through the filter
- Default-deny with an allowlist, `SECCOMP_RET_ERRNO` over `KILL` so failures
  are debuggable
- Honour the `linux.seccomp` section of `config.json`

**Accepts when:** the emitted program is byte-identical to libseccomp's output
for the same policy, and a denied syscall returns `EPERM` rather than killing
the process.

### Phase 6 — rootless

Plain `podman --runtime quilt`, no sudo anywhere.

- `SubUid` mapper via `newuidmap` / `newgidmap`
- `Delegated` cgroup driver under `user@1000.service`
- Idmapped mounts (`MOUNT_ATTR_IDMAP` via `mount_setattr`, kernel 6.19 has it)
  so image files owned by uid 0 are usable without a chown pass. The
  `mount_setattr` wrapper and its `struct mount_attr` already exist from
  phase 1, with `userns_fd` waiting to be filled in
- Connectivity via `pasta`, which is already installed

**Accepts when:** the phase-4 podman demo runs as your normal user, and
`ps -o user` shows `nathan` outside while `id` inside shows uid 0.

## Testing

Four tiers, mirroring how QuinLang and Finance are already tested.

**Pure unit.** Config parsing, cgroup value formatting, mount ordering,
capability set arithmetic, jump-offset resolution in the BPF assembler. No root,
runs on every save.

**Golden bytes.** The two encoders emit bytes, so they get pinned against a
reference implementation:

- seccomp: diff against libseccomp's output for the same policy (as a dev-only
  comparison, not a dependency)
- netlink: capture what `ip` sends using an `nlmon` interface, store as golden.
  `scripts/capture-netlink.sh` does the capture; the comparison lives in
  `src/net/veth.rs` beside the message builders, which are split from the
  senders so a message can be built and inspected without a socket

This is the tier that catches a filter that is subtly wrong but still loads —
the failure mode that manual testing never finds.

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
