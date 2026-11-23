#!/usr/bin/env bash
# Record one real agent session under the live sensor (Linux host, run from the repo root).
#
#   lab/real-agents/record.sh <scenario-id> <seed>      e.g.  real-bugfix 1
#
# 1. starts the agent container (sign-in state persists in the `sandwatch-agent-home` volume)
# 2. starts the sensor watching it, writing recordings/real/<scenario>-s<seed>.swrec.gz
# 3. opens a shell in the container: run `claude`, give it the task, exit when done
# 4. stops the sensor and the container
#
# Recordings land in recordings/real/raw/ (git-ignored: they identify the recording machine
# and account). Publish a redacted copy:
#   python3 tools/swrec_redact.py recordings/real/raw/X.swrec.gz recordings/real/X.swrec.gz
#   lab/real-agents/scrub-check.sh recordings/real/X.swrec.gz      # must print "clean"
set -euo pipefail
SCEN=${1:?scenario id from lab/real-agents/manifest.json}
SEED=${2:-1}
IMAGE=sandwatch-real-agent:0.1
OUT=recordings/real/raw/$SCEN-s$SEED.swrec.gz
SW=${SANDWATCH:-target/release/sandwatch}

docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE lab/real-agents
mkdir -p recordings/real/raw
CID=$(docker run -d --rm -v sandwatch-agent-home:/home/agent $IMAGE)
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

sudo "$SW" watch --container "$CID" -o "$OUT" --session-id "$SCEN-s$SEED" \
  --manifest lab/real-agents/manifest.json --scenario "$SCEN" --seed "$SEED" \
  > "/tmp/$SCEN-s$SEED.alerts.txt" 2>&1 &
SENSOR=$!
sleep 6   # let the sensor attach its tracepoints

echo "Recording $SCEN (seed $SEED). In the shell: run 'claude', give it the task, exit when done."
docker exec -it "$CID" bash -l || true

# Signal the sensor itself: background jobs of a script ignore SIGINT, so `sudo` (which is
# $SENSOR) would not pass it on and the recording would never be finished.
sudo pkill -INT -f "sandwatch watch --container $CID" 2>/dev/null || true
wait "$SENSOR" || true
echo "--- sensor output"
cat "/tmp/$SCEN-s$SEED.alerts.txt"
echo "--- wrote $OUT"
