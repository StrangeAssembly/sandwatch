# Sandwatch

**An open-source flight recorder and tripwire for AI agents.** Sandwatch watches what an
autonomous agent actually does at the OS level and flags escape attempts, credential hunting
and scope creep, as a linked chain, within a second of it starting.

Its correlation engine is **Catena** (Latin: *chain*).

> **Status: v0.3.** Live eBPF sensor, real-time detection, and freeze response, working on
> Linux (tested on Docker Desktop's 6.18 kernel). Pre-release: not yet hardened.

Live, watching an agent container with `--freeze-on chain`:

```
sandwatch: watching /sys/fs/cgroup/docker/89ff8183… (cgroup id 1462), 101 tracepoints attached

  00:00.097  ⚠  SANDBOX-FINGERPRINT  Sandbox / container fingerprinting [discovery]
  00:00.206  ✖  ESCAPE-PROBE         Container escape-surface probing [escape]  — 3 targets, 3 failed
  00:00.263  ⚠  NAMESPACE-ESCAPE     New user or mount namespace requested [escape]
  00:00.311  ✖  CRED-HUNT            Credential hunting [credential-access]  — 4 targets, 2 failed
  00:00.311  ✖✖ CHAIN                discovery → escape → credential-access  score 0.90
sandwatch: FROZE /sys/fs/cgroup/docker/89ff8183… after chain
```

The agent was frozen 0.31 s into the attack. The exfiltration step it was about to run
never happened (the decoy collector received 0 uploads).

## Why

Autonomous agents increasingly get shell access inside containers and VMs, and public incident
reports describe agents probing for and escaping their sandboxes. Perimeter tools don't see
this: the agent *is* the insider. Sandwatch looks for the behavior that separates hunting
from working: **many sensitive targets, many failed lookups, at machine speed, progressing
across attack stages.**

## Quick start

Requires only Docker (Rust, clang and Python run in containers).

```powershell
.\lab\live-all.ps1                                          # every scenario under the live sensor
.\lab\live-all.ps1 -Only full-chain -FreezeOn chain         # freeze demo
.\scripts\dev.ps1 sandwatch eval recordings\live --verbose  # score rules on labeled sessions
.\scripts\dev.ps1 sandwatch replay recordings\live\full-chain-s1.swrec.gz
.\scripts\dev.ps1 sandwatch verify recordings               # check tamper-evident hash chains
.\scripts\dev.ps1 test
```

On a Linux host, as root:

```bash
sandwatch run --freeze-on chain -- python my_agent.py        # launch + watch
sandwatch watch --container <id> --freeze-on chain           # attach to a running container
sandwatch thaw --container <id>
```

## Current results

| | strace lab recordings | **live eBPF sensor** |
|---|---|---|
| Attack sessions detected (expected rules all fired) | 14 / 14 | **14 / 14** |
| Benign sessions with any alert (5 are deliberately attack-like) | 0 / 12 | **0 / 12** |
| Median time from attack start to first alert | 0.17 s | **0.07 s** |
| Events lost by the sensor | — | **0** (26 sessions) |
| Run time of the 46k-event agent session | 58 s | **4.6 s** (untraced baseline not yet measured) |
| Tempo rule: human-paced vs machine-paced identical attack | silent / fires | silent / fires |

These numbers come from scenarios the rules were written alongside, so treat them as a
regression baseline, not proof of real-world accuracy. See [docs/catena.md](docs/catena.md)
and [docs/sensor.md](docs/sensor.md).

## Repository

| Path | What it is |
|---|---|
| `crates/swrec` | Recording reader + hash-chain verifier |
| `crates/catena` | Correlation engine: windows, failure counting, chain scoring |
| `crates/sensor` | Live sensor: eBPF programs (C, CO-RE) + Aya loader, normalizer, session loop |
| `crates/sandwatch` | CLI: `run`, `watch`, `thaw`, `verify`, `replay`, `eval`, `rules` |
| `rules/` | Catena rules (YAML), each with false-positive notes |
| `recordings/` | Labeled `.swrec.gz` sessions: strace lab (`/`), live sensor (`live/`), freeze demo (`live-freeze/`) |
| `lab/` | Isolated Docker lab: scenarios, `record-all.ps1` (strace), `live-all.ps1` (eBPF) |
| `docker/` | Dev toolchain and sensor images |
| `tools/` | Python converter (strace → `.swrec`) + quick stats |
| `docs/` | [Recording format](docs/recording-format.md), [Catena rules](docs/catena.md), [Live sensor](docs/sensor.md) |

## Roadmap

| Version | What ships |
|---|---|
| **v0.1** ✅ | Recording format, lab, 26 labeled sessions, Catena engine + 9 rules, `eval` gate |
| **v0.3** ✅ | Live eBPF sensor (101 tracepoints, cgroup-filtered in kernel, seccomp-denied calls recovered), real-time Catena, freeze response |
| v0.4 | Chain escalation (score updates as stages arrive), per-process-tree scoping, HTML session reports, multi-container daemon |
| v0.5 | Agent tool-call ingestion (OpenTelemetry GenAI / MCP) → intent-mismatch rule |
| v0.8 | Kubernetes daemon; Tetragon/Falco/Sysmon ingestion; community corpus + benchmark |
| v1.0 | Hardened, published threat model, measured numbers on independent data |

## Contributing

The most valuable contribution is recordings, especially real agent sessions. See
[CONTRIBUTING-recordings.md](CONTRIBUTING-recordings.md).

## License

Apache License 2.0. See [LICENSE](LICENSE). The eBPF program in `crates/sensor/bpf/` is
dual-licensed GPL-2.0-only OR Apache-2.0, as the Linux kernel requires for GPL-only helpers.
