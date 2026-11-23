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
# Home directories of real accounts on this machine (agents also probe /home/CLAUDE.md and
# similar parent-directory files, which are harmless, so only actual homes are flagged).
homes=$(getent passwd | awk -F: '$6 ~ "^/home/[^/]+$" {print $6}' | sed 's/[.]/\\./g' | paste -sd'|' -)
pat="(${homes:+(?:$homes)(?:/|\\b)|}/Users/|[A-Za-z]:\\\\\\\\|\b\Q$me\E\b|\b\Q$host\E\b"
pat+="|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
pat+="|\b192\.168\.\d+\.\d+|\b10\.0\.2\.\d+"
# account/session ids (UUIDs) and the names of items synced to an account
pat+="|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
pat+="|\.claude/(?:skills|plugins)/synced/[^/\"]+/(?!item-\d+|\.staging)[^/\"]+"
pat+="|(?i)(api[_-]?key|token|secret|password|passwd|bearer)\s*[=:]\s*(?!<redacted>)[^\s\"]{6,}|sk-ant-[A-Za-z0-9_-]+)"
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
