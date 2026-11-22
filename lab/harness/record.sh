#!/bin/bash
# Runs one scenario under strace inside the agent container.
#   record.sh <scenario-script relative to /lab/scenarios> <recording-id>
# Writes /out/raw/<id>.strace and /out/raw/<id>.env.json
set -u
script="$1"
rid="$2"
mkdir -p /out/raw
raw="/out/raw/$rid.strace"
rm -f "$raw"

# Syscall classes: filename-taking, process lifecycle, network, credentials, plus the
# individual syscalls that matter for escape attempts.
strace -f -ttt -T -yy -s 256 \
  -e trace=%file,%process,%network,%creds,capget,capset,ptrace,mount,umount2,unshare,setns,kill,tkill,tgkill,prctl,bpf \
  -o "$raw" -- bash "/lab/scenarios/$script" >/dev/null 2>&1
rc=$?

cat > "/out/raw/$rid.env.json" <<EOF
{
  "kernel": "$(uname -r)",
  "arch": "$(uname -m)",
  "strace_version": "$(strace -V | head -1)",
  "container_user": "$(id -un)",
  "recorded_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "scenario_exit_code": $rc,
  "pace": "${SANDWATCH_PACE:-default}",
  "seed": "${SANDWATCH_SEED:-1}"
}
EOF
lines=$(wc -l < "$raw")
echo "recorded $rid: $lines strace lines, scenario exit $rc"
