#!/usr/bin/env bash
# Check recordings for host-identifying details before they are committed.
#
#   lab/real-agents/scrub-check.sh recordings/real/*.swrec.gz
#
# Real sessions should only show the container's generic user (`agent`, /home/agent).
# This flags anything that looks like it came from the recording machine: its user and
# host name (read at run time, never stored here), other home directories, Windows/macOS
# paths, email addresses, private-network addresses outside Docker's ranges, and
# credential-looking strings in command lines. Exit 1 if anything is found.
set -uo pipefail
me=$(id -un); host=$(hostname)
pat="(/home/(?!agent\b|node\b)[A-Za-z0-9._-]+|/Users/|[A-Za-z]:\\\\\\\\|\b\Q$me\E\b|\b\Q$host\E\b"
pat+="|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
pat+="|\b192\.168\.\d+\.\d+|\b10\.0\.2\.\d+"
pat+="|(?i)(api[_-]?key|token|secret|password|passwd|bearer)\s*[=:]\s*[^\s\"]{6,}|sk-ant-[A-Za-z0-9_-]+)"
bad=0
for f in "$@"; do
  hits=$(gzip -dc "$f" | grep -noP "$pat" | sort -t: -k2 -u | head -20)
  if [[ -n $hits ]]; then
    echo "REVIEW $f"; echo "$hits" | sed 's/^/   line /'; bad=1
  else
    echo "clean  $f"
  fi
done
exit $bad
