#!/usr/bin/env bash
# claudebox-supervisor.sh — Launch and monitor multiple claudebox sandboxes
#
# Usage:
#   claudebox-supervisor.sh [OPTIONS] --task "prompt 1" --task "prompt 2" ...
#   claudebox-supervisor.sh [OPTIONS] --task-file tasks.txt
#
# Each task runs in a separate sandbox with its own workdir, audit log,
# and optional token limit. The supervisor monitors all sandboxes and
# produces a summary on completion.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDEBOX="$SCRIPT_DIR/claudebox.sh"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TASKS=()               # array of task prompts
TASK_FILE=""           # file with one task per line
WORKDIR=""             # base workdir (each task gets a copy or subdirectory)
SHARED_WORKDIR=false   # all tasks share the same workdir (read-only)
MAX_PARALLEL=0         # 0 = all at once
TOKEN_LIMIT=""         # per-sandbox token limit
TIMEOUT=""             # per-sandbox wall-clock timeout
EXTRA_ARGS=()          # additional args passed to each claudebox instance
OUTPUT_BASE=""         # base directory for per-task output

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case $1 in
    --task)          TASKS+=("$2"); shift 2 ;;
    --task-file)     TASK_FILE=$2; shift 2 ;;
    --workdir)       WORKDIR=$(realpath "$2"); shift 2 ;;
    --shared-workdir) SHARED_WORKDIR=true; shift ;;
    --max-parallel)  MAX_PARALLEL=$2; shift 2 ;;
    --token-limit)   TOKEN_LIMIT=$2; shift 2 ;;
    --timeout)       TIMEOUT=$2; shift 2 ;;
    --output-dir)    OUTPUT_BASE=$2; shift 2 ;;
    --help|-h)
      cat <<'EOF'
claudebox-supervisor.sh — Launch and monitor multiple claudebox sandboxes

USAGE:
  claudebox-supervisor.sh [OPTIONS] --task "prompt 1" --task "prompt 2" ...
  claudebox-supervisor.sh [OPTIONS] --task-file tasks.txt

OPTIONS:
  --task "PROMPT"      Add a task. Claude runs with -p "PROMPT". Repeatable.
  --task-file FILE     Read tasks from FILE (one per line, # comments allowed).
  --workdir DIR        Base working directory. Each task gets a read-only view
                       unless --shared-workdir is set.
  --shared-workdir     All tasks share the same workdir (mounted read-only).
                       Default: each task gets its own copy.
  --max-parallel N     Max concurrent sandboxes (default: all at once).
  --token-limit N      Per-sandbox token limit.
  --timeout MINS       Per-sandbox wall-clock timeout.
  --output-dir DIR     Base output directory. Each task gets DIR/task-N/.
  --help               Show this help.

EXAMPLES:
  # Run 3 code review tasks in parallel
  claudebox-supervisor.sh \
    --workdir ~/projects/myapp \
    --shared-workdir \
    --task "review src/auth.ts for security issues" \
    --task "review src/api.ts for error handling" \
    --task "review src/db.ts for SQL injection"

  # Run tasks from a file with token budget
  claudebox-supervisor.sh \
    --workdir ~/projects/myapp \
    --task-file review-tasks.txt \
    --token-limit 500000 \
    --timeout 30

  # Parallel feature work (each task gets its own workdir copy)
  claudebox-supervisor.sh \
    --workdir ~/projects/myapp \
    --output-dir ~/review-output \
    --task "add input validation to the login form" \
    --task "add rate limiting to the API endpoints"
EOF
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

# SEC: reject --share-network in supervisor mode (causes TCP port collisions between tasks)
for _ea in "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"; do
  [[ "$_ea" == "--share-network" ]] && { echo "❌ --share-network is not supported in supervisor mode (port collision risk)"; exit 1; }
done

# ---------------------------------------------------------------------------
# Load tasks from file
# ---------------------------------------------------------------------------
if [[ -n "$TASK_FILE" ]]; then
  [[ -f "$TASK_FILE" ]] || { echo "❌ --task-file not found: $TASK_FILE"; exit 1; }
  while IFS= read -r _line; do
    # Skip empty lines and comments
    _line="${_line%%#*}"
    _line="${_line#"${_line%%[![:space:]]*}"}"  # trim leading whitespace
    _line="${_line%"${_line##*[![:space:]]}"}"  # trim trailing whitespace
    [[ -n "$_line" ]] && TASKS+=("$_line")
  done < "$TASK_FILE"
fi

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
[[ ${#TASKS[@]} -eq 0 ]] && { echo "❌ No tasks specified. Use --task or --task-file."; exit 1; }
[[ -z "$WORKDIR" ]] && { echo "❌ --workdir is required."; exit 1; }
[[ -d "$WORKDIR" ]] || { echo "❌ --workdir does not exist: $WORKDIR"; exit 1; }
[[ -x "$CLAUDEBOX" ]] || { echo "❌ claudebox.sh not found at: $CLAUDEBOX"; exit 1; }
# SEC: validate MAX_PARALLEL is a positive integer
[[ "$MAX_PARALLEL" =~ ^[0-9]+$ ]] || { echo "❌ --max-parallel: invalid value '$MAX_PARALLEL' (positive integer)"; exit 1; }

TASK_COUNT=${#TASKS[@]}
[[ $MAX_PARALLEL -le 0 ]] && MAX_PARALLEL=$TASK_COUNT

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CLAUDEBOX SUPERVISOR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Tasks: $TASK_COUNT"
echo "  Workdir: $WORKDIR"
echo "  Parallel: $MAX_PARALLEL"
[[ -n "$TOKEN_LIMIT" ]] && echo "  Token limit: $TOKEN_LIMIT per task"
[[ -n "$TIMEOUT" ]] && echo "  Timeout: ${TIMEOUT}m per task"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ---------------------------------------------------------------------------
# Setup output and log directories
# ---------------------------------------------------------------------------
if [[ -z "$OUTPUT_BASE" ]]; then
  # SEC: create temp dir with restrictive permissions
  OUTPUT_BASE=$(umask 077; mktemp -d "${WORKDIR%/*}/.claudebox-supervisor-XXXXXX")
fi
mkdir -p "$OUTPUT_BASE"
chmod 700 "$OUTPUT_BASE"

# ---------------------------------------------------------------------------
# Launch tasks
# ---------------------------------------------------------------------------
# SEC: signal handler — kill all child sandboxes on interrupt
_supervisor_cleanup() {
  echo ""
  echo "⚠ Supervisor interrupted — stopping all tasks..."
  for _pid in "${!TASK_PIDS[@]}"; do
    kill -TERM "$_pid" 2>/dev/null || true
  done
  # Give children time to clean up, then force
  sleep 2
  for _pid in "${!TASK_PIDS[@]}"; do
    kill -KILL "$_pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "  All tasks stopped."
  exit 130
}
trap _supervisor_cleanup INT TERM

declare -A TASK_PIDS       # PID -> task index
declare -A TASK_STARTS     # index -> start time
declare -A TASK_EXITS      # index -> exit code
declare -A TASK_LOGS       # index -> log file path
declare -A TASK_AUDIT      # index -> audit log path

_running=0
_completed=0
_next=0

launch_task() {
  local idx=$1
  local prompt="${TASKS[$idx]}"
  local task_dir="$OUTPUT_BASE/task-$((idx + 1))"
  local log_file="$task_dir/sandbox.log"
  local audit_file="$task_dir/audit.jsonl"
  mkdir -p "$task_dir"

  # Build claudebox args
  local cb_args=()

  if [[ "$SHARED_WORKDIR" == true ]]; then
    cb_args+=(--read-only-workdir --workdir "$WORKDIR")
    cb_args+=(--output-dir "$task_dir")
  else
    # Each task gets its own copy of the workdir
    local task_workdir="$task_dir/workdir"
    cp -a --no-preserve=ownership "$WORKDIR/." "$task_workdir/"
    cb_args+=(--workdir "$task_workdir")
  fi

  cb_args+=(--audit-log "$audit_file")
  [[ -n "$TOKEN_LIMIT" ]] && cb_args+=(--token-limit "$TOKEN_LIMIT")
  [[ -n "$TIMEOUT" ]] && cb_args+=(--timeout "$TIMEOUT")
  cb_args+=("${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}")
  cb_args+=(-- -p "$prompt")

  echo "  [$((idx + 1))/$TASK_COUNT] Starting: ${prompt:0:60}$([ ${#prompt} -gt 60 ] && echo '...')"

  "$CLAUDEBOX" "${cb_args[@]}" > "$log_file" 2>&1 &
  local pid=$!
  TASK_PIDS[$pid]=$idx
  TASK_STARTS[$idx]=$(date +%s)
  TASK_LOGS[$idx]="$log_file"
  TASK_AUDIT[$idx]="$audit_file"
  (( _running++ )) || true
}

# Launch initial batch
while [[ $_next -lt $TASK_COUNT && $_running -lt $MAX_PARALLEL ]]; do
  launch_task $_next
  (( _next++ )) || true
done

# ---------------------------------------------------------------------------
# Wait for tasks and launch new ones as slots free up
# ---------------------------------------------------------------------------
_exited_pid=""
while [[ $_completed -lt $TASK_COUNT ]]; do
  # Wait for any child to exit
  _exited_pid=""
  wait -n -p _exited_pid 2>/dev/null
  _wait_exit=$?

  if [[ -n "${_exited_pid:-}" && -n "${TASK_PIDS[$_exited_pid]+x}" ]]; then
    _idx=${TASK_PIDS[$_exited_pid]}
    TASK_EXITS[$_idx]=$_wait_exit
    unset "TASK_PIDS[$_exited_pid]"
    (( _running-- )) || true
    (( _completed++ )) || true

    _elapsed=$(( $(date +%s) - ${TASK_STARTS[$_idx]} ))
    _prompt="${TASKS[$_idx]}"
    if [[ $_wait_exit -eq 0 ]]; then
      echo "  [$((_idx + 1))/$TASK_COUNT] Done (${_elapsed}s): ${_prompt:0:50}"
    else
      echo "  [$((_idx + 1))/$TASK_COUNT] FAILED (exit $_wait_exit, ${_elapsed}s): ${_prompt:0:50}"
    fi

    # Launch next task if available
    if [[ $_next -lt $TASK_COUNT && $_running -lt $MAX_PARALLEL ]]; then
      launch_task $_next
      (( _next++ )) || true
    fi
  else
    sleep 1
  fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SUPERVISOR SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

_total_tokens=0
_failures=0

for (( i=0; i<TASK_COUNT; i++ )); do
  _exit=${TASK_EXITS[$i]:-unknown}
  _prompt="${TASKS[$i]}"

  # Extract token totals from audit log
  _tokens="n/a"
  if [[ -f "${TASK_AUDIT[$i]}" ]]; then
    _stop_line=$(grep '"proxy_stop"' "${TASK_AUDIT[$i]}" 2>/dev/null | tail -1) || true
    if [[ -n "${_stop_line:-}" ]]; then
      _tokens=$(echo "$_stop_line" | grep -oP '"total":\s*\K[0-9]+' 2>/dev/null) || _tokens="0"
      (( _total_tokens += _tokens )) || true
    fi
  fi

  _status_icon="✔"
  [[ "$_exit" != "0" ]] && { _status_icon="✘"; (( _failures++ )) || true; }

  printf "  %s [%d] %-50s  exit=%s  tokens=%s\n" \
    "$_status_icon" "$((i + 1))" "${_prompt:0:50}" "$_exit" "$_tokens"
done

echo ""
echo "  Total tasks: $TASK_COUNT ($(( TASK_COUNT - _failures )) succeeded, $_failures failed)"
echo "  Total tokens: $_total_tokens"
echo "  Output: $OUTPUT_BASE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Exit with failure if any task failed
[[ $_failures -gt 0 ]] && exit 1
exit 0
