# Catena: the Sandwatch correlation engine

Catena reads a stream of OCSF-aligned events (from a `.swrec` recording today, from the live
sensor later) and raises two kinds of alert:

- **Detect alerts.** One rule saw enough distinct matching *targets* inside a sliding time
  window, optionally with enough of them *failing*.
- **Chain alerts.** Detect alerts from enough *different attack stages* landed in the same
  session within a window, and are linked into one incident with a score.

## The core idea: failed probes

Fast, broad activity is normal. Agents and build tools touch thousands of files a second. What
separates hunting from working is **looking for things that aren't there**. Legitimate code
knows where its one credential file lives. A hunter tries ten locations to see which exist.
Several rules therefore require a minimum number of *failed* lookups, and only real "it isn't
there / you can't have it" errors count (`ENOENT`, `EACCES`, `EPERM`, `ECONNREFUSED`,
`ENETUNREACH`, timeouts…). Noise errors such as `ENODATA` from extended-attribute reads do not.

## Writing a detect rule

```yaml
id: cred-hunt                     # unique, kebab-case
name: Credential hunting
severity: high                    # low | medium | high | critical
stage: credential-access          # attack stage; omit for modifiers like tempo-burst
attack: [T1552.001]               # MITRE ATT&CK ids
description: What it detects and why it matters.
false_positive_notes: Why normal work does not trigger it. (Required in review.)
match:                            # every listed condition must hold
  class: file                     # file | process | network
  activities: [Open, Get Attributes]
  path_any: ['/\.aws/(credentials|config)$', ...]   # regex, any match
  path_none: [...]                # regex, none may match
  access: read                    # opens only: read | write
  actor_name_any: [tar, zip]      # acting process basename
  flags_any: [CLONE_NEWUSER]      # substring of raw syscall flags
  dst_ip_any: ['169.254.169.254', '10.0.0.0/8']    # exact or CIDR
  dst_ip_none: ['127.0.0.0/8']
  dst_port_any: [80] / dst_port_none: [53]
  status: failure                 # any (default) | success | failure
aggregate:
  min_distinct: 4                 # distinct targets inside the window
  min_failures: 2                 # distinct targets that failed
  min_failure_ratio: 0.5          # failed / distinct
  window_s: 60
  distinct_by: target             # target (default) | basename
  failure_errnos: [ENOENT, ...]   # override what counts as a failure
```

A **target** is what the event touched: the file path, `ip:port`, `unix:/path`, or
`Activity(flags)` for process events. Each rule fires at most once per session (v0.1).

Rules are checked when they load, beyond YAML field names:
- `window_s` must be finite and > 0.
- `min_distinct` must be ≥ 1, and `min_failures` must not exceed it.
- `min_failure_ratio` must be within 0–1.
- `status` must be `any`, `success` or `failure`; `access` must be `read` or `write`.
- CIDR prefixes must fit the address family (`/0`–`/32` for IPv4, `/0`–`/128` for IPv6).
- A `match` must constrain something, so a rule cannot match every event by accident.
- Chains need `min_stages` ≥ 2. Rule ids must be unique.

### Event order

Events do not always arrive in timestamp order. The live sensor timestamps a syscall when
it starts and delivers it when it returns, so a slow call can arrive after faster, later
ones. Every window is anchored to the **newest timestamp seen so far** and covers
`[newest - window_s, newest]`:
- A late event that still falls inside a rule's window is counted at its true time, and
  later expires at the right moment.
- A late event older than the window is ignored by that rule. It stays in the recording
  and is counted in the footer's `catena_stats`.

So detection results do not depend on arrival order, except for events that are later than
the window itself.

## Writing a chain rule

```yaml
id: chain
kind: chain
severity: critical
chain:
  min_stages: 3       # distinct `stage` values among detect alerts
  window_s: 600
```

**Score** = 1 − Π(1 − wᵢ) over the highest-severity alert in each stage, with weights
low 0.2, medium 0.4, high 0.6, critical 0.8. Three high-severity stages score 0.94.

## Shipped rules (v0.1)

| Rule | Stage | Fires on |
|---|---|---|
| `sandbox-fingerprint` | discovery | ≥3 container-marker reads in 10 s (`/.dockerenv`, PID 1 cgroup/sched…) |
| `escape-probe` | escape | ≥3 escape-surface targets in 60 s (runtime sockets, SA tokens, core_pattern…) |
| `namespace-escape` | escape | a user or mount namespace request |
| `cred-hunt` | credential-access | ≥4 credential stores in 60 s, ≥2 of them failing |
| `metadata-access` | egress | any connection to a cloud metadata endpoint |
| `egress-expand` | egress | ≥8 destinations in 60 s, ≥3 failing (DNS/loopback excluded) |
| `cred-archive` | collection | an archiver reading ≥2 different credential files |
| `tempo-burst` | (modifier) | ≥10 sensitive targets in 2 s, ≥50% failing |
| `chain` | — | ≥3 distinct stages in 10 min |

## Testing rules

Every rule is scored against the labeled recordings:

```powershell
.\scripts\dev.ps1 sandwatch eval recordings --verbose
```

`eval` exits non-zero if any attack misses an expected rule, fires a forbidden one, or any
benign session alerts at all, so it can gate CI.

### Read this before trusting the numbers

The v0.1 thresholds were written by the same person who wrote the scenarios, with knowledge
of the lab data. A perfect score on that data is a **regression test**, not proof that the
rules generalize. Real validation needs recordings the rules were not designed against:
real agent sessions and other people's environments. See `CONTRIBUTING-recordings.md`.
