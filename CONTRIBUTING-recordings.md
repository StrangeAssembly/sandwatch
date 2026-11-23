# Contributing Recordings

The most valuable thing you can give Sandwatch is **recordings**: especially sessions of real AI
agents, both doing normal work and trying to get out of their sandbox. Detection rules are only
as good as the data they're tested against, and no single person can produce enough of it.

## What we want most

1. **Benign agent sessions (most needed).** A real coding/ops agent doing real tasks in a
   container. These keep false positives honest. Easy and safe to record.
2. **Real agents attempting escape or misuse.** For example, an agent inside an evaluation
   sandbox (CTF-style tasks, red-team evals) that probes its environment. Usually comes from
   eval or research teams that already run such setups.
3. **New attack scenarios.** Scripted emulations of techniques the lab does not cover yet.
4. **Different environments.** Same scenarios on other kernels, runtimes (Podman, containerd,
   gVisor, Kubernetes) or seccomp profiles.

## Recording real agent sessions

### Safety requirements (non-negotiable for escape-attempt recordings)

- Run in a disposable VM or container with **no credentials, API keys or personal data** inside
  (the agent's own model API key should live outside the sandbox, e.g. in a proxy).
- No network access except what the task needs. Use an internal network like the lab's.
- Never run escape-attempt sessions on a machine you care about.
- Only use agents and targets you are authorized to run.

### How to record

Simplest: put your agent in the lab's agent image, or any image with `strace`, and wrap it:

```bash
strace -f -ttt -T -yy -s 256 \
  -e trace=%file,%process,%network,%creds,capget,capset,ptrace,mount,umount2,unshare,setns,kill,tkill,tgkill,prctl,bpf \
  -o session.strace -- <your agent command>
```

Then add a manifest entry describing it and convert with `tools/swrec_convert.py`
(see `lab/README.md`). Set `"synthetic": false` in the labels. Phase markers are optional for
real sessions; describe what happened in `notes` instead.

### Labeling

- `class`: `attack` if the agent at any point attempted escape, credential access or
  out-of-scope egress, even if it failed; otherwise `benign`.
- `expected_detections`: rule IDs you believe should fire (best effort; maintainers review).
- `notes`: the task the agent was given, the agent/framework and model if you can share them,
  and what it actually did.

## Privacy checklist (before you submit)

Recordings contain file paths, command lines, hostnames and IP addresses. Before submitting:

- [ ] Recorded in a lab environment, not your personal machine or a production system
- [ ] No real usernames, hostnames, internal domains or IPs you aren't willing to publish
- [ ] No real secrets anywhere in command lines or paths (search for `key`, `token`, `secret`, `password`)
- [ ] Redacted: `python3 tools/swrec_redact.py raw.swrec.gz your.swrec.gz` replaces account
      and session ids (UUIDs), names synced to your agent account, real home directories,
      your user and host name, emails and credential-looking values, and re-seals the hash
      chain. Add `--term <text>` for anything else that identifies you.
- [ ] Checked: `lab/real-agents/scrub-check.sh your.swrec.gz` prints `clean` (run it on the
      machine you recorded on: it also looks for that machine's own user and host names)
- [ ] The recording verifies: `python3 tools/swrec_verify.py your.swrec`

Agent tools keep per-account state in the agent's home directory (for Claude Code,
`~/.claude/`). The sensor never records file contents, but the *paths* there carry account
ids, which is why redaction is required for real agent sessions.

If in doubt, don't submit: open an issue describing the session instead.

## Submitting

Open a pull request adding:

- `recordings/contrib/<your-handle>/<session-id>.swrec` (gzip with `.swrec.gz` if over 5 MB)
- the manifest entry (or a short `.json` sidecar with the same fields)

By submitting you agree the recording can be published under the project's data license.
