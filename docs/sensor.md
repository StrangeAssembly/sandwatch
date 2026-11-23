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
- **Namespace creation through `clone`/`clone3`.** `clone` passes its flags in a register.
  `clone3` passes a pointer to `struct clone_args`, so the sensor copies `clone_args.flags`
  out of user memory. A clone with any `CLONE_NEW*` flag is reported as a
  `Namespace Change` event (with the child pid when it succeeded); other clones stay `Fork`.
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

## Sensor health

Once a second the sensor checks its loss counters. When events were dropped since the last
check, it does three things:
- prints a live warning;
- emits an `Event Loss` event (class 9001, see `recording-format.md`) into the event
  stream, so the gap is on the recording's timeline and rules can react to it;
- puts the final totals in the footer's `sensor_stats`.

The `sensor-blinding` rule alerts when one report lost 10,000 or more events. A syscall
flood is a way to blind the sensor (MITRE T1562.006), so the rule's stage is
*defense-evasion*: on its own it is a medium alert, and together with two other attack
stages it completes a chain. Counting *repeated* reports would be a weaker signal: under a
flood the sensor gets little CPU, and its once-a-second checks merge into one.

## Response

`--freeze-on <rule ids>` writes `1` to the watched cgroup's `cgroup.freeze` when a listed
rule fires. Every process in it stops immediately. Nothing is killed or deleted, so the
evidence and process state stay intact.
- In `watch` mode the workload stays frozen. Inspect it, then run `sandwatch thaw` or
  remove the container.
- In `run` mode the session owns the workload. When the session ends, everything still in
  its cgroup is terminated, including descendants left behind by the launched command, and
  the cgroup is removed. This also happens if the session fails partway through.
  - Session stopped by `--duration` or Ctrl+C: the workload gets SIGTERM, `--grace`
    seconds to exit (default 2), then `cgroup.kill`.
  - Frozen workload: killed straight away, because frozen processes cannot handle SIGTERM.

## Known limitations (v0.3)

- **x86-64 only** for recovering arguments of seccomp-denied calls. On other architectures
  those events arrive without paths or flags, so a denied `unshare`/`setns`/`clone` there
  carries no namespace flags and the namespace rule cannot match it.
- **`clone3` flags are read from user memory at syscall entry.** In theory another thread
  could change them before the kernel copies them in.
- **Path resolution is best-effort.** It covers relative paths through cwd and directory
  fds; `dup`/`fcntl` fd tricks are not tracked.
- **Event loss under extreme load.** A real session (Claude Code, pip and node all busy at
  once) once lost about 23% of its events with the original 16 MB buffer and single-threaded
  consumer. Since then:
  - records are sized to the fields they use (~360 bytes instead of 1000);
  - the ring buffer is 64 MB;
  - the producer skips per-event wakeups;
  - recording (canonical JSON, hashing, gzip at the fast level) runs on its own thread;
  - a reader thread drains the kernel buffer into a 256 MB in-memory burst buffer, so
    spikes wait in memory while detection catches up.

  `lab/stress/syscall_storm.py` on a 4-vCPU VM. Loss depends on the syscall rate:

  | syscalls/s | lost (original sensor) | lost now |
  |---|---|---|
  | ~260k | 74% | 0% |
  | 310k–440k | 87–91% | 0% |
  | ~510k | — | 33% |
  | 845k–915k | 91% | 61–68% |

  For scale, the busiest 100 ms of the three recorded real agent sessions peaked at 121k
  events/s (31k–33k in the other two); the median was 20–30/s. Above roughly 500k/s the
  limit is contention inside the single shared kernel ring buffer: four CPUs reserving
  records in it at once. Giving the reader more CPU, even real-time priority, does not help.
  Next steps:
  - one ring buffer per CPU;
  - kernel-side filtering of high-volume, low-value calls (e.g. repeated successful `stat`
    of the same non-sensitive path).

  Loss is counted in the footer (`sensor_stats`: ring buffer, pending map, burst buffer)
  and warned about live. Detection is blind while it lasts. A workload can **deliberately**
  flood syscalls to cause this, so sustained loss should itself be treated as suspicious. A
  rule for it is planned.
- **One session per sensor process.** Fleet mode (many containers, one daemon) is planned.
- **Capture limits.** argv is captured up to 6 arguments × 64 bytes, and paths up to 256 bytes.
- **Seccomp-denied calls the sensor doesn't trace** (for example `keyctl`) are not seen.
- **Long-running sessions.** The normalizer keeps per-process state in memory and the writer
  streams to disk. There are no rotation or retention limits yet.
