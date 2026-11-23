#!/usr/bin/env bash
# Recording checks run by CI (and runnable locally on Linux):
#   1. both verifiers accept every committed recording;
#   2. both verifiers give the expected verdict on every fixture (ok-* pass, bad-* fail);
#   3. the eval gate passes on the labeled lab sessions.
# Usage: scripts/ci-check-recordings.sh [path/to/sandwatch]
set -uo pipefail
SW=${1:-target/release/sandwatch}
fail=0

mapfile -t recs < <(find recordings -name '*.swrec.gz' -type f | sort)
echo "== verify ${#recs[@]} recordings"
"$SW" verify recordings | tail -1 || fail=1
python3 -I tools/swrec_verify.py "${recs[@]}" | tail -1 || fail=1

echo "== fixture verdicts (Rust and Python must agree with the file name)"
for f in crates/swrec/tests/fixtures/*.swrec*; do
  want=1; [[ $(basename "$f") == ok-* ]] && want=0
  "$SW" verify "$f" >/dev/null 2>&1; rust=$?
  python3 -I tools/swrec_verify.py "$f" >/dev/null 2>&1; py=$?
  [[ $rust -ne 0 ]] && rust=1
  [[ $py -ne 0 ]] && py=1
  if [[ $rust -ne $want || $py -ne $want ]]; then
    echo "MISMATCH $f: expected exit $want, rust $rust, python $py"; fail=1
  fi
done
echo "fixtures checked"

# live-freeze/ is excluded on purpose: those sessions are frozen before the later attack
# stages run, so their "expected detections" can never all fire.
echo "== eval gate (strace lab + live sensor sessions)"
"$SW" eval recordings/*.swrec.gz recordings/live | tail -4 || fail=1

exit $fail
