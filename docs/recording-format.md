# `.swrec` Recording Format — v0.1

An `.swrec` file is a **labeled, tamper-evident recording of one monitored session**: everything a
process tree did at the OS level, plus ground-truth labels saying what the session actually was.

Recordings are the test fixtures for Sandwatch detection rules. Every rule must fire on its
`must-fire` recordings and stay silent on its `must-not-fire` recordings.

## Design goals

1. **Sensor-independent.** The same format holds events from strace (v0.1 lab), eBPF, Tetragon,
   Falco, auditd, or Sysmon. Detection rules never see sensor-specific details.
2. **OCSF-aligned.** Events use [OCSF](https://schema.ocsf.io) class IDs, activity IDs and field
   names where they exist. Anything OCSF has no field for lives under `unmapped`.
3. **Replayable.** Events are in time order and carry microsecond timing, so tempo analysis works.
4. **Tamper-evident.** Every line is hash-chained to the previous one.
5. **Plain text.** One JSON object per line (JSONL), UTF-8. May be gzip-compressed as `.swrec.gz`.

## File layout

```
line 1        header   (record_type = "header")
line 2..N-1   events   (record_type = "event"), ordered by time
line N        footer   (record_type = "footer")
```

## Hash chain

For every line, in order:

```
canonical(obj) = JSON with sorted keys, separators (",", ":"), no ASCII escaping,
                 computed over the object WITHOUT its "hash" field
hash_n         = SHA-256( prev_hash_n  ||  canonical(obj_n) )      (hex, lowercase)
prev_hash_1    = "0" * 64
prev_hash_n    = hash_{n-1}
```

Each line stores both `prev_hash` and `hash`. The footer stores the final event hash and the
event count. `tools/swrec_verify.py` recomputes the chain.

This makes edits, deletions, insertions and reordering **detectable**. It does not make the file
immutable: whoever writes the file can also rewrite the whole chain. Tamper evidence becomes
meaningful once checkpoint hashes are stored somewhere the writer cannot alter (later versions).

## Header

```json
{
  "record_type": "header",
  "format": "sandwatch-recording",
  "format_version": "0.1",
  "session": {
    "id": "escape-probe-s1",
    "recorded_at": "2026-11-22T10:00:00Z",
    "start_time": 1795000000000,
    "duration_ms": 4210,
    "event_count": 1834
  },
  "sensor": {
    "name": "strace",
    "version": "strace -- version 6.1",
    "fidelity": "syscall-level via ptrace; file/process/network/creds syscalls; no read/write payloads"
  },
  "environment": {
    "kernel": "6.6.87.2-microsoft-standard-WSL2",
    "arch": "x86_64",
    "runtime": "docker",
    "container_user": "agent",
    "network": "isolated lab network, no internet"
  },
  "labels": {
    "class": "attack",
    "scenario": "escape-probe",
    "variant": 1,
    "pace": "machine",
    "description": "Container fingerprinting followed by escape-surface probing.",
    "attack_techniques": ["T1613", "T1082", "T1611"],
    "expected_detections": ["escape-probe", "sandbox-fingerprint"],
    "synthetic": true,
    "notes": "Scripted emulation. Probes only; nothing is exploited."
  },
  "ground_truth": {
    "phases": [
      {"name": "fingerprint", "time": 1795000000120},
      {"name": "escape-probe", "time": 1795000001400}
    ]
  },
  "schema": {"events": "ocsf-aligned-subset", "ocsf_version": "1.3.0"},
  "prev_hash": "000…000",
  "hash": "…"
}
```

### Label fields

| Field | Meaning |
|---|---|
| `class` | `attack` or `benign`. Ground truth for the whole session. |
| `scenario` | Scenario ID from the lab manifest. |
| `variant` | Seed used for ordering/jitter, so variants of a scenario differ. |
| `pace` | `machine` (agent-speed), `human` (deliberately slowed), or `natural` (whatever the workload does). |
| `attack_techniques` | MITRE ATT&CK technique IDs the session emulates. Empty for benign. |
| `expected_detections` | Sandwatch rule IDs that **should** fire. Empty for benign: **no** rule should fire. |
| `synthetic` | `true` for scripted emulation, `false` for a real agent session. |
| `hard_negative` | Optional. `true` for benign sessions that deliberately resemble attacks. |

### Ground-truth phases

Phase markers say when each stage of a scenario began. They come from the scenario itself
(in the lab, the script stats a path under `/.sandwatch-mark/<phase>`). Converters **remove** the
marker syscalls from the event stream, so detectors cannot cheat by seeing them.

## Events

```json
{
  "record_type": "event",
  "seq": 42,
  "time": 1795000001412,
  "class_uid": 1001,
  "class_name": "File System Activity",
  "activity_id": 14,
  "activity_name": "Open",
  "status": "Failure",
  "status_detail": "ENOENT",
  "actor": {
    "process": {
      "uid": "9c1f0a7b2e4d6a10",
      "pid": 57,
      "name": "ls",
      "path": "/usr/bin/ls",
      "cmd_line": "ls -la /var/run/docker.sock",
      "parent_uid": "1a2b3c4d5e6f7a8b"
    },
    "user": {"name": "agent"}
  },
  "file": {"path": "/var/run/docker.sock"},
  "unmapped": {"syscall": "openat", "flags": "O_RDONLY|O_CLOEXEC", "t_us": 1292011, "duration_us": 14},
  "prev_hash": "…",
  "hash": "…"
}
```

### Common fields

| Field | Meaning |
|---|---|
| `seq` | 1-based position in the event stream. |
| `time` | Epoch milliseconds (OCSF convention). |
| `unmapped.t_us` | Microseconds since session start. Use this for tempo analysis. |
| `class_uid` / `activity_id` | OCSF class and activity (tables below). |
| `status` | `Success`, `Failure`, or `Pending` (e.g. non-blocking connect). |
| `status_detail` | errno name on failure (`ENOENT`, `EACCES`, `ECONNREFUSED`, …). |
| `actor.process.uid` | **Stable process identity**: hash of session + pid + process start time. PIDs get reused; this does not. |
| `actor.process.parent_uid` | Stable identity of the parent, when known. |

### Classes and activities used in v0.1

**File System Activity (1001)**

| activity_id | activity_name | Typical syscalls |
|---|---|---|
| 1 | Create | mkdir, mkdirat, symlink, link, mknod |
| 4 | Delete | unlink, unlinkat, rmdir |
| 5 | Rename | rename, renameat, renameat2 |
| 6 | Set Attributes | utimensat, truncate, setxattr |
| 7 | Set Security | chmod, fchmodat, chown, fchownat |
| 8 | Get Attributes | stat, lstat, newfstatat, statx, readlink, statfs, chdir |
| 9 | Get Security | access, faccessat, faccessat2 |
| 12 | Mount | mount |
| 13 | Unmount | umount2 |
| 14 | Open | open, openat, openat2, creat |
| 99 | Other | other filename-taking syscalls |

Fields: `file.path`; `file.new_path` for renames/links; `unmapped.access` (`read` or `write`) for opens.

**Process Activity (1007)**

| activity_id | activity_name | Typical syscalls |
|---|---|---|
| 1 | Launch | execve, execveat (process loads a new image) |
| 2 | Terminate | process exit |
| 5 | Set User ID | setuid, setgid, setresuid, setreuid, … |
| 99 | Fork | clone, clone3, fork, vfork (`process` = the child) |
| 99 | Signal | kill, tkill, tgkill |
| 99 | Trace | ptrace |
| 99 | Capability Query / Capability Set | capget / capset |
| 99 | Namespace Change | unshare, setns |
| 99 | BPF | bpf |
| 99 | Process Control | prctl |

Fields: `process` (target/child process, same shape as `actor.process`), `unmapped.exit_code`.

**Network Activity (4001)**

| activity_id | activity_name | Typical syscalls |
|---|---|---|
| 1 | Open | connect |
| 6 | Traffic | sendto with an address |
| 7 | Listen | bind, listen |
| 99 | Accept | accept, accept4 |

Fields: `dst_endpoint.ip`, `dst_endpoint.port`, or `dst_endpoint.path` for Unix sockets;
`connection_info.protocol_name` (`tcp`, `udp`, `unix`) when known.

## Footer

```json
{"record_type": "footer", "event_count": 1834, "final_event_hash": "…", "prev_hash": "…", "hash": "…"}
```

## Versioning

`format_version` follows semver. Adding optional fields is a minor change; removing or renaming
fields is a major change. Readers must ignore fields they do not understand.
