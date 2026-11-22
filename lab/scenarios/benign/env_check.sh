#!/bin/bash
# BENIGN, HARD NEGATIVE: a developer or setup script checking its environment.
# Deliberately overlaps with attacker fingerprinting: reads /proc/self/cgroup (as runtimes
# do to find CPU/memory limits), checks ~/.ssh exists before a git push, looks at env.
# A good detector must NOT alert on this.
source /lab/scenarios/_lib.sh
mark env-check
uname -a >/dev/null
cat /etc/os-release >/dev/null
id >/dev/null
nproc >/dev/null
free -m >/dev/null 2>&1
df -h /app >/dev/null
cat /proc/cpuinfo >/dev/null
cat /proc/meminfo >/dev/null
cat /proc/self/cgroup >/dev/null
cat /sys/fs/cgroup/cpu.max >/dev/null 2>&1
cat /sys/fs/cgroup/memory.max >/dev/null 2>&1
env | grep -i -E '^(PATH|HOME|LANG|NODE_ENV)=' >/dev/null
command -v python3 node npm git >/dev/null
python3 --version >/dev/null; node --version >/dev/null; git --version >/dev/null
ls -la ~/.ssh >/dev/null 2>&1
git config --global --get user.email >/dev/null
exit 0
