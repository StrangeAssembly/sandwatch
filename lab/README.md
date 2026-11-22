# Sandwatch Recording Lab

Reproducible, isolated environment that produces labeled `.swrec` recordings: scripted attack
sessions and benign workloads, captured at the syscall level. These recordings are the test
fixtures for Sandwatch detection rules.

## Safety model

- **No internet at run time.** The lab network is Docker `internal`. Containers reach each
  other, not the internet or your LAN. (Internet is used only while *building* images.)
- **Unprivileged workload.** The agent container runs as a non-root user, with no added
  capabilities, Docker's default seccomp profile, and **no** `docker.sock` mount.
- **Probes, not exploits.** Attack scenarios check whether escape paths exist (sockets,
  tokens, writable kernel interfaces, namespaces). They never exploit anything.
- **Fake secrets only.** Every credential in the image contains `SANDWATCH-FAKE`.
- **Decoys are local.** The "metadata API", "collector" and "database" ports are one small
  Python container (`labsvc`) on the lab network.

## Requirements

- Docker with Compose v2 (Docker Desktop on Windows/macOS, Docker Engine on Linux)
- ~2 GB disk for images

## Run it

Windows (PowerShell, from the repo root):

```powershell
.\lab\record-all.ps1
```

Linux / macOS:

```bash
./lab/record-all.sh
```

Options: `-Only "escape*"` / `ONLY='escape*'` records matching scenarios only;
`-NoBuild` / `NO_BUILD=1` skips the image build.

Output: `recordings/<scenario>-s<seed>.swrec`, then a verification pass and a stats table.
Raw strace output stays in `lab/out/raw/` (git-ignored).

## What's recorded

| Scenario | Class | What it does |
|---|---|---|
| `escape-probe` | attack | Container fingerprinting, then escape-surface probing |
| `cred-hunt` | attack | Keys, tokens, `.env`, secret grep, other processes' environments |
| `egress-expand` | attack | Metadata API probing, DNS probing, TCP fan-out across the subnet |
| `recon-burst-machine` | attack | ~28 sensitive probes at agent speed, then one success used immediately |
| `recon-burst-human` | attack | Same actions at human pace (1–3 s gaps): isolates tempo |
| `full-chain` | attack | Fingerprint → escape probe → creds → metadata → fan-out → exfil |
| `py-dev` | benign | venv, offline pip install, pytest, edit, retest |
| `node-dev` | benign | offline `npm ci`, run, test |
| `git-work` | benign | commits, branch, merge, log, diff |
| `build-pkg` | benign | compile, checksum everything, tarball, verify |
| `env-check` | benign, hard negative | Environment checks that overlap with fingerprinting |
| `agent-session` | benign, hard negative | Legitimate coding-agent work at machine speed |

Each scenario runs with several seeds (variants change ordering and jitter). Labels, ATT&CK
technique IDs and the rules expected to fire are in `scenarios/manifest.json`.

## How recording works

1. `harness/record.sh` runs a scenario under `strace -f -ttt -T -yy` inside the agent container.
2. Scenarios mark phase boundaries by stat-ing `/.sandwatch-mark/<phase>`.
3. `tools/swrec_convert.py` parses strace output into OCSF-aligned events, assigns stable
   process identities, lifts phase markers into the header (and removes them from the event
   stream), attaches labels from the manifest, and hash-chains every line.
4. `tools/swrec_verify.py` checks every chain; `tools/swrec_stats.py` prints a summary.

## Known limitations (v0.1)

- **strace is not eBPF.** Tracing slows the workload (more for syscall-heavy installers), so
  absolute tempo numbers are inflated compared to an untraced run. Compare scenarios
  recorded the same way, and don't treat timings as ground truth for production thresholds.
- **No read/write payloads** and no `read`/`write` syscalls at all, by design.
- **Docker Desktop kernel.** Results reflect Docker's default seccomp profile; for example
  `unshare(CLONE_NEWUSER)` fails with `EPERM`. Other runtimes will differ, and that is useful data.
- **Synthetic attackers.** Scripted emulation, not real AI agents. Real-agent recordings are
  the main thing contributors can add; see `CONTRIBUTING-recordings.md`.

## Adding a scenario

1. Write `scenarios/attack/<name>.sh` or `scenarios/benign/<name>.sh`. Start with
   `source /lab/scenarios/_lib.sh`, and use `mark <phase>` and `pause`.
2. Add an entry to `scenarios/manifest.json` (id, script, class, seeds, techniques,
   expected detections).
3. Run `record-all` with `-Only <id>`.
