# Shared helpers for lab scenarios. Sourced, not executed.
#
# SANDWATCH_SEED  variant seed: changes ordering and jitter so variants differ
# SANDWATCH_PACE  machine | human | natural   (default: machine)

RANDOM=${SANDWATCH_SEED:-1}
SANDWATCH_PACE=${SANDWATCH_PACE:-machine}

# Ground-truth phase marker. Stats a path that never exists; the converter turns this
# into a header phase entry and removes it from the event stream.
# Always returns success so scripts using `set -e` are not aborted by it.
mark() { [ -e "/.sandwatch-mark/$1" ] || :; }

# Pause between steps according to pace.
#   machine: 0-30ms (agent-speed)
#   human:   1.0-2.9s (someone typing commands and reading output)
#   natural: no added delay
# Uses `read -t` on a pipe that never receives data instead of /bin/sleep, so pauses do
# not add process launches to the recording.
exec {_SANDWATCH_PAUSE_FD}<> <(:)
pause() {
  local t
  case "$SANDWATCH_PACE" in
    human)   t="$((RANDOM % 2 + 1)).$((RANDOM % 10))" ;;
    natural) return 0 ;;
    *)       t="0.0$((RANDOM % 4))" ;;
  esac
  read -rt "$t" -u "$_SANDWATCH_PAUSE_FD" _ || :
}

# Print arguments in a seed-dependent order, one per line. Seed 1 keeps every item;
# other seeds drop each item with ~20% probability, so variants differ in WHAT they touch,
# not only in order.
shuffled() {
  printf '%s\n' "$@" | shuf --random-source=<(yes "$SANDWATCH_SEED") \
    | awk -v s="${SANDWATCH_SEED:-1}" 'BEGIN { srand(s) } s == 1 || rand() >= 0.2'
}

# TCP connect attempt with a short timeout; never sends data.
tcp_probe() { timeout 1 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
