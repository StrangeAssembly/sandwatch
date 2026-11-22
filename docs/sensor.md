# The Sandwatch live sensor

`sandwatch run` and `sandwatch watch` monitor a workload in real time with eBPF. They record
it to a `.swrec.gz`, run Catena on every event as it arrives, and can freeze the workload
when a chosen rule fires.

```
sandwatch run   [--freeze-on chain] [-o out.swrec.gz] -- python my_agent.py
sandwatch watch --container <id>  [--freeze-on chain,escape-probe] [--duration 600]
sandwatch thaw  --container <id>
```

Requirements: Linux ≥ 5.15 with BTF (`/sys/kernel/btf/vmlinux`), cgroup v2, and root (or
CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN). Tested on Docker Desktop's WSL2 kernel 6.18.

## Architecture

```
 agent container (unprivileged)          sensor container (privileged, --pid=host)
 ┌──────────────────────────┐            ┌─────────────────────────────────────────────┐
 │ agent process tree       │  syscalls  │ kernel: 101 tracepoint programs             │
 │  bash → curl, cat, tar … │ ─────────► │  · filter: task's cgroup ∈ watched set      │
 └──────────────────────────┘            │  · capture paths, argv, sockaddr, ppid      │
                                         │  · ring buffer (16 MB)                      │
                                         │ user space (Rust):                          │
                                         │  · normalize → OCSF events                  │
                                         │  · Catena rules + chain correlation         │
                                         │  · hash-chained .swrec.gz                   │
                                         │  · response: cgroup.freeze                  │
                                         └─────────────────────────────────────────────┘
```

The sensor sits **outside** the monitored container. The workload can't see the sensor's
processes, can't read its memory, and can't stop it without first escaping, which is exactly
what the sensor is watching for.

## Kernel side (`crates/sensor/bpf/sensor.bpf.c`)

- **Syscall tracepoints**, not kprobes. Their argument layout is a stable kernel ABI, so the
  programs use no kernel-version-specific structs for arguments. Syscalls that don't exist on
  an architecture (for example `open` on arm64) are skipped at attach time.
- **In-kernel cgroup filter.** Events from unwatched cgroups are discarded before any copying
  happens. Descendant cgroups (up to 10 levels) count as watched.
- **CO-RE for task context.** Parent PID, process start time and exit code are read from
  `task_struct`, relocated against the running kernel's BTF when the programs load.
- **Enter/exit pairing.** Arguments are captured on entry and parked per thread. The exit
  adds the return value and submits the record.
- **Calls that never return.** If a process dies mid-call (for example a `connect` killed by
  `timeout`), `sched_process_exit` flushes the call as `UNFINISHED`.
- **Calls rejected before entry.** Seccomp rejects blocked syscalls *before* the entry
  tracepoint runs, so they would be invisible. When an exit arrives with no matching entry
  and an error result, the sensor recovers the arguments from the task's saved user
  registers (x86-64) and records the event with `unmapped.denied_before_entry: true`. This
  is how Sandwatch sees a blocked `unshare(CLONE_NEWUSER)` inside Docker. (strace sees these
  calls only because ptrace runs before seccomp.)
- **Loss accounting.** Ring-buffer and pending-map overflows are counted in kernel and
  reported in the recording's footer (`sensor_stats`). A recording never silently claims
  completeness.

## User side (`crates/sensor/src`)

- `normalize.rs` turns raw records into the same event schema the lab converter produces,
  so rules behave the same on live and recorded data:
  - **Stable process identity:** a hash of session, PID and kernel start time.
  - **Parent links:** from `real_parent`.
  - **Command lines:** from the exec's argv.
  - **Absolute paths:** relative names are resolved against a tracked cwd and directory-fd
    table, with `/proc` as a fallback.
- **Container-runtime plumbing is ignored.** `runc init` joins namespaces inside the
  container's cgroup for every `docker exec`. Those events are dropped and counted, but its
  final exec, which is the workload starting, is kept.
- `session.rs` runs the loop: drain the ring buffer, normalize, write, evaluate, respond.

## Response

`--freeze-on <rule ids>` writes `1` to the watched cgroup's `cgroup.freeze` when a listed
rule fires. Every process in it stops immediately. Nothing is killed or deleted, so the
evidence and process state stay intact.
- In `watch` mode the workload stays frozen. Inspect it, then run `sandwatch thaw` or
  remove the container.
- In `run` mode the frozen workload is killed when the session ends.

## Known limitations (v0.3)

- **x86-64 only** for recovering arguments of seccomp-denied calls. On other architectures
  those events arrive without paths or flags.
- **Path resolution is best-effort.** It covers relative paths through cwd and directory
  fds; `dup`/`fcntl` fd tricks are not tracked.
- **One session per sensor process.** Fleet mode (many containers, one daemon) is planned.
- **Capture limits.** argv is captured up to 6 arguments × 64 bytes, and paths up to 256 bytes.
- **Seccomp-denied calls the sensor doesn't trace** (for example `keyctl`) are not seen.
- **Long-running sessions.** The normalizer keeps per-process state in memory and the writer
  streams to disk. There are no rotation or retention limits yet.
