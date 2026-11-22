#!/usr/bin/env bash
# Records every scenario in lab/scenarios/manifest.json into recordings/*.swrec.gz (Linux / macOS).
#   ./lab/record-all.sh              build images, record everything
#   ONLY='escape*' ./lab/record-all.sh
#   NO_BUILD=1 ./lab/record-all.sh
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$LAB")"
cd "$LAB"

[ -n "${NO_BUILD:-}" ] || docker compose --profile run build
mkdir -p out/raw "$ROOT/recordings"
docker compose up -d labsvc >/dev/null

# Expand the manifest into "id script seed env..." lines using the agent image's python.
plan=$(docker run --rm --network none -v "$ROOT:/work" sandwatch-lab-agent:0.1 python3 -c '
import json
m = json.load(open("/work/lab/scenarios/manifest.json"))
for s in m["scenarios"]:
    env = " ".join(f"-e {k}={v}" for k, v in s.get("env", {}).items())
    for seed in s["seeds"]:
        print(s["id"], s["script"], seed, env)
')

while read -r id script seed envargs; do
  [ -z "$id" ] && continue
  case "$id" in ${ONLY:-*}) ;; *) continue ;; esac
  rid="$id-s$seed"
  # shellcheck disable=SC2086
  docker compose run --rm -e SANDWATCH_SEED="$seed" $envargs agent bash /lab/harness/record.sh "$script" "$rid"
  docker run --rm --network none -v "$ROOT:/work" sandwatch-lab-agent:0.1 \
    python3 /work/tools/swrec_convert.py \
      --raw "/work/lab/out/raw/$rid.strace" --env "/work/lab/out/raw/$rid.env.json" \
      --manifest /work/lab/scenarios/manifest.json --scenario "$id" --seed "$seed" \
      --out "/work/recordings/$rid.swrec.gz"
done <<< "$plan"

docker compose down >/dev/null
docker run --rm --network none -v "$ROOT:/work" -w /work sandwatch-lab-agent:0.1 \
  bash -c "python3 tools/swrec_verify.py recordings/*.swrec.gz && echo && python3 tools/swrec_stats.py recordings/*.swrec.gz"
