#!/usr/bin/env bash
# claudebox.sh — Run Claude Code in a bubblewrap (bwrap) sandbox with host-side credential proxy.
#
# Security model:
#   - Workdir is the only read-write location
#   - Everything else is read-only or not exposed
#   - Real home directory NOT mounted (fake tmpfs home)
#   - Real credentials never enter the sandbox; dummy tokens replaced by host proxy via Unix socket
#   - All outbound HTTPS is routed through a host-side CONNECT proxy (allowlist enforced)
#
# Network model:
#   Default: --unshare-net (full network isolation). All external access goes through
#   Unix socket bridges to host-side proxies. On Ubuntu 22.04+ this requires:
#     sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
#   Use --share-network to share the host network namespace (weaker isolation).
#
# REQUIREMENTS:
#   - bwrap (bubblewrap) installed
#   - Node.js on the host (for credential-proxy.js)
#
# USAGE:
#   ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]
#
# EXAMPLES:
#   ./claudebox.sh
#   ./claudebox.sh -- -p "explain this codebase"
#   ./claudebox.sh --mount-claude-md
#   ./claudebox.sh --workdir ~/projects/myapp
#   ./claudebox.sh --enable-github
#   ./claudebox.sh --share-network --bind-binaries -- --continue
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/credential-proxy.js"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
# HIGH-2/MED-3: use XDG_RUNTIME_DIR (user-private, tmpfs on systemd) to avoid
# world-readable sockets in /tmp and TOCTOU races.
# HIGH-4 fix: if XDG_RUNTIME_DIR is unset, create a private temp directory.
if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
  _SOCK_DIR="$XDG_RUNTIME_DIR"
else
  _SOCK_DIR=$(mktemp -d /tmp/claudebox-XXXXXX)
  chmod 700 "$_SOCK_DIR"
  _SOCK_DIR_CREATED=true
fi
SOCKET_ANTHROPIC="$_SOCK_DIR/claude-proxy-anthropic-$$.sock"
SOCKET_GITHUB="$_SOCK_DIR/claude-proxy-github-$$.sock"
SOCKET_MCP="$_SOCK_DIR/claude-proxy-mcp-$$.sock"
SANDBOX_SOCKET_ANTHROPIC="/tmp/claude-proxy-anthropic.sock"
SANDBOX_SOCKET_MCP="/tmp/claude-proxy-mcp.sock"
SANDBOX_SOCKET_GITHUB="/tmp/claude-proxy-github.sock"
PORT_ANTHROPIC=58080
PORT_GITHUB_CONNECT=58081   # HTTPS CONNECT proxy for api.github.com (in-sandbox bridge)
SANDBOX_HOME="/home/sandbox"
WORKDIR="$(pwd)"
MOUNT_CLAUDE_MD=false
SHARE_CLAUDE_DIR=false
SHARE_SESSIONS=false
ISOLATE_NET=true
BIND_BINARIES=false
LAUNCH_SHELL=false
ENABLE_GITHUB=false
ENABLE_GITHUB_MCP=false
PORT_MCP=58082             # in-sandbox TCP port for MCP bridge
MCP_SERVER_PID=""
CLAUDE_ARGS=()
PROXY_PID=""
TEMP_CREDS=""
DUMMY_CREDS_FILE=""
SANDBOX_HOME_SEED=""
MEM_LIMIT=""           # e.g. 4G, 8G, 512M
CPU_LIMIT=""           # percentage: 100 = 1 core, 200 = 2 cores
IDLE_TIMEOUT=15        # minutes: warn if no Anthropic request for this long (0=disable)
ATTACH_MODE=false      # --attach: connect to existing sandbox
NOTIFY_COMMAND=""      # shell command for event notifications
NOTIFY_WEBHOOK=""      # webhook URL for event notifications (Slack, etc.)
GH_TOKEN_FILE=""       # file containing GitHub PAT (alternative to GH_TOKEN env var)
ALLOWLIST_URLS=()      # additional HTTPS hosts to whitelist via CONNECT proxy
READONLY_WORKDIR=false # mount workdir read-only
WALL_TIMEOUT=""        # wall-clock timeout in minutes
DRY_RUN=false          # print bwrap command without executing
SNAPSHOT=false         # overlayfs snapshot mode
OVERLAY_DIR=""         # host-side overlay directory (auto-created)
TOKEN_LIMIT=""         # max tokens (input+output); empty = unlimited
AUDIT_LOG=""           # path to audit log file

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case $1 in
    --mount-claude-md)   MOUNT_CLAUDE_MD=true; shift ;;
    --share-claude-dir)  SHARE_CLAUDE_DIR=true; shift ;;
    --share-sessions)    SHARE_SESSIONS=true; shift ;;
    --share-network)     ISOLATE_NET=false; shift ;;
    --bind-binaries)     BIND_BINARIES=true; shift ;;
    --shell)             LAUNCH_SHELL=true; shift ;;
    --dummy-credentials) DUMMY_CREDS_FILE=$2; shift 2 ;;
    --workdir)           WORKDIR=$2; shift 2 ;;
    --sandbox-home)      SANDBOX_HOME_SEED=$2; shift 2 ;;
    --enable-github)     ENABLE_GITHUB=true;  shift ;;
    --disable-github)    ENABLE_GITHUB=false; shift ;;
    --gh-token-file)     GH_TOKEN_FILE=$2; shift 2 ;;
    --enable-github-mcp) ENABLE_GITHUB_MCP=true; shift ;;
    --mcp-port)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1024 && $2 <= 65535 )) || { echo "❌ --mcp-port: invalid port '$2' (1024-65535)"; exit 1; }
      PORT_MCP=$2; shift 2 ;;
    --mem-limit)
      [[ "$2" =~ ^[0-9]+[KMG]$ ]] || { echo "❌ --mem-limit: invalid value '$2' (e.g. 4G, 512M)"; exit 1; }
      MEM_LIMIT=$2; shift 2 ;;
    --cpu-limit)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1 && $2 <= 100000 )) || { echo "❌ --cpu-limit: invalid value '$2' (percentage, e.g. 200 = 2 cores)"; exit 1; }
      CPU_LIMIT=$2; shift 2 ;;
    --idle-timeout)
      [[ "$2" =~ ^[0-9]+$ ]] || { echo "❌ --idle-timeout: invalid value '$2' (minutes)"; exit 1; }
      IDLE_TIMEOUT=$2; shift 2 ;;
    --attach)  ATTACH_MODE=true; shift ;;
    --notify-command)  NOTIFY_COMMAND=$2; shift 2 ;;
    --notify-webhook)
      # MED-1: only allow https webhooks to prevent SSRF to internal services.
      [[ "$2" =~ ^https:// ]] || { echo "❌ --notify-webhook: only https:// URLs allowed"; exit 1; }
      NOTIFY_WEBHOOK=$2; shift 2 ;;
    --allowlist-url)
      # Validate: must be a hostname (no scheme, no path, no port)
      [[ "$2" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || { echo "❌ --allowlist-url: invalid hostname '$2' (e.g. registry.npmjs.org)"; exit 1; }
      ALLOWLIST_URLS+=("$2"); shift 2 ;;
    --read-only-workdir) READONLY_WORKDIR=true; shift ;;
    --snapshot) SNAPSHOT=true; shift ;;
    --timeout)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1 )) || { echo "❌ --timeout: invalid value '$2' (minutes, >= 1)"; exit 1; }
      WALL_TIMEOUT=$2; shift 2 ;;
    --dry-run)  DRY_RUN=true; shift ;;
    --token-limit)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1000 )) || { echo "❌ --token-limit: invalid value '$2' (minimum 1000)"; exit 1; }
      TOKEN_LIMIT=$2; shift 2 ;;
    --audit-log)
      AUDIT_LOG=$2; shift 2 ;;
    --anthropic-port)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1024 && $2 <= 65535 )) || { echo "❌ --anthropic-port: invalid port '$2' (1024-65535)"; exit 1; }
      PORT_ANTHROPIC=$2; shift 2 ;;
    --github-port)
      [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1024 && $2 <= 65535 )) || { echo "❌ --github-port: invalid port '$2' (1024-65535)"; exit 1; }
      PORT_GITHUB_CONNECT=$2; shift 2 ;;
    --help|-h)
      cat <<'EOF'
claudebox.sh — Run Claude Code in a bwrap sandbox with host-side credential proxy

USAGE:
  claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]

OPTIONS:
  --share-claude-dir     Mount ~/.claude read-only into the sandbox (history, settings, etc.)
                         .credentials.json is automatically replaced with dummy tokens.
  --share-sessions       Share session data (read-write) so conversations can be resumed
                         from the host or another sandbox. Mounts the project-specific
                         directory under ~/.claude/projects/ and ~/.claude/session-env/.
  --mount-claude-md      Mount ~/.claude/CLAUDE.md only (subset of --share-claude-dir)
  --share-network        Share host network namespace (weaker isolation; default: isolated).
                         Default (isolated) requires on Ubuntu 22.04+:
                           sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  --bind-binaries        Bind-mount node and claude from their host paths into the sandbox
                         under /run/sandbox-bin. Use this when they live outside /usr.
  --shell                Launch bash instead of claude (useful for debugging the sandbox).
  --dummy-credentials FILE  Use FILE as the dummy .credentials.json.
  --workdir DIR          Working directory to mount read-write (default: CWD).
                         Must be an existing path; symlinks are resolved.
  --sandbox-home DIR     Copy files from DIR into the sandbox home at startup.
  --enable-github-mcp    Enable GitHub access via MCP server (recommended; requires GH_TOKEN
                         and github-mcp-server binary on host).
  --enable-github        Enable GitHub access via CONNECT proxy + gh CLI (unrecommended;
                         use --enable-github-mcp instead). Requires GH_TOKEN on host.
  --gh-token-file FILE   Read GitHub PAT from FILE (default: ~/.config/claudebox/gh-token).
                         The GH_TOKEN env var takes priority if set.
  --mcp-port PORT        TCP port for MCP server bridge (default: 58082; range 1024-65535).
  --allowlist-url HOST   Allow HTTPS access to HOST via CONNECT proxy. Repeatable.
                         e.g. --allowlist-url registry.npmjs.org --allowlist-url pypi.org
  --read-only-workdir    Mount workdir read-only (for analysis/review tasks).
  --snapshot             Snapshot mode: copy workdir to staging before launch.
                         Sandbox writes to staging copy; original untouched.
                         On exit: review diff, then apply or rollback.
  --timeout MINS         Wall-clock timeout: kill sandbox after MINS minutes.
  --token-limit N        Max tokens (input+output). Proxy rejects requests after limit.
  --audit-log FILE       Log API requests (method, path, tokens, timing) to JSONL file.
  --dry-run              Print the bwrap command without executing it.
  --mem-limit SIZE       Memory limit (e.g. 4G, 512M). Uses cgroups via systemd-run.
  --cpu-limit PERCENT    CPU limit as percentage (100 = 1 core, 200 = 2 cores).
  --idle-timeout MINS    Warn when no Anthropic API request for MINS minutes (default: 15, 0=off).
  --attach               Attach to an existing sandbox (connect to its shell socket).
  --notify-command CMD   Run CMD on events (env: CLAUDEBOX_EVENT, CLAUDEBOX_MESSAGE).
  --notify-webhook URL   POST JSON to URL on events (Slack incoming webhook compatible).
  --anthropic-port PORT  TCP port for Anthropic proxy bridge (default: 58080; range 1024-65535)
  --github-port PORT     TCP port for GitHub CONNECT proxy (default: 58081; range 1024-65535)
  --help                 Show this help

NETWORK:
  default: full isolation via --unshare-net (no outbound network; Unix socket bridges only).
    Requires kernel.apparmor_restrict_unprivileged_userns=0 on Ubuntu 22.04+.

  --share-network
    Share host network namespace (weaker: raw sockets can bypass proxy).

ENVIRONMENT:
  GH_TOKEN               GitHub token (or use --gh-token-file / ~/.config/claudebox/gh-token)
  CLAUDE_CREDENTIALS_FILE  Override Claude credentials file path

SECURITY PROPERTIES:
  - Only <workdir> is writable; everything else read-only or tmpfs
  - Real home NOT exposed (fake home at /home/sandbox on tmpfs)
  - Anthropic credentials never in sandbox (dummy token injected by host proxy)
  - All outbound HTTPS goes through CONNECT proxy; api.github.com allowed only with --enable-github
  - /etc exposed only as individual files (not full directory)
  - Init script uses no shell string interpolation for user-controlled values
EOF
      exit 0 ;;
    --) shift; CLAUDE_ARGS+=("$@"); break ;;
    *)  CLAUDE_ARGS+=("$1"); shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Attach socket directory (shared between host and sandbox for shell access)
# ---------------------------------------------------------------------------
ATTACH_DIR="$_SOCK_DIR/claudebox-attach-$$"
ATTACH_SOCK="$ATTACH_DIR/shell.sock"

# ---------------------------------------------------------------------------
# --attach: connect to an existing sandbox's shell socket
# ---------------------------------------------------------------------------
if [[ "$ATTACH_MODE" == true ]]; then
  # Find the most recent attach socket
  _found_sock=""
  for _d in "$_SOCK_DIR"/claudebox-attach-*/shell.sock; do
    [[ -S "$_d" ]] && _found_sock="$_d"
  done
  if [[ -z "$_found_sock" ]]; then
    echo "❌ No running sandbox found (no attach socket in $_SOCK_DIR/claudebox-attach-*/)"
    echo "   Tip: list available sockets with: ls $_SOCK_DIR/claudebox-attach-*/shell.sock"
    exit 1
  fi
  echo "▶ Attaching to sandbox: $_found_sock"
  echo "  (Ctrl-C to detach)"
  exec socat -,raw,echo=0 UNIX-CONNECT:"$_found_sock"
fi

# ---------------------------------------------------------------------------
# Validate ports don't collide
# ---------------------------------------------------------------------------
[[ "$PORT_ANTHROPIC" -ne "$PORT_GITHUB_CONNECT" ]] || {
  echo "❌ --anthropic-port and --github-port must be different"; exit 1; }
[[ "$PORT_ANTHROPIC" -ne "$PORT_MCP" && "$PORT_GITHUB_CONNECT" -ne "$PORT_MCP" ]] || {
  echo "❌ --mcp-port must differ from --anthropic-port and --github-port"; exit 1; }

# ---------------------------------------------------------------------------
# Load GH_TOKEN from file if --gh-token-file or default location
# Priority: GH_TOKEN env > --gh-token-file > ~/.config/claudebox/gh-token
# ---------------------------------------------------------------------------
_DEFAULT_GH_TOKEN_FILE="$HOME/.config/claudebox/gh-token"
if [[ -z "${GH_TOKEN:-}" ]]; then
  _token_file="${GH_TOKEN_FILE:-$_DEFAULT_GH_TOKEN_FILE}"
  if [[ -n "$GH_TOKEN_FILE" ]]; then
    [[ -f "$_token_file" ]] || { echo "❌ --gh-token-file: file not found: $_token_file"; exit 1; }
  fi
  if [[ -f "$_token_file" ]]; then
    GH_TOKEN=$(head -1 "$_token_file" | tr -d '[:space:]')
    [[ -n "$GH_TOKEN" ]] || { echo "❌ GitHub token file is empty: $_token_file"; exit 1; }
    echo "✔ GitHub token loaded from $_token_file"
  fi
fi

# ---------------------------------------------------------------------------
# Validate and canonicalise workdir (HIGH-4: symlink/path traversal)
# ---------------------------------------------------------------------------
WORKDIR=$(realpath --canonicalize-existing "$WORKDIR" 2>/dev/null) || {
  echo "❌ --workdir does not exist: $WORKDIR"; exit 1; }
[[ "$WORKDIR" == "/" ]]     && { echo "❌ --workdir cannot be /";     exit 1; }
[[ "$WORKDIR" == "$HOME" ]] && { echo "❌ --workdir cannot be \$HOME"; exit 1; }

# --snapshot and --read-only-workdir are mutually exclusive
[[ "$SNAPSHOT" == true && "$READONLY_WORKDIR" == true ]] && {
  echo "❌ --snapshot and --read-only-workdir are mutually exclusive"; exit 1; }

# ---------------------------------------------------------------------------
# Snapshot: copy workdir to staging area (sandbox writes to staging, original safe)
# ---------------------------------------------------------------------------
SNAPSHOT_STAGING=""
_SNAPSHOT_PHASE=""  # "copy" | "sandbox" | "merge" — used by cleanup to decide staging fate
if [[ "$SNAPSHOT" == true ]]; then
  # LOW-3: warn if workdir is large (> 1 GB)
  _workdir_size_kb=$(du -sk "$WORKDIR" 2>/dev/null | cut -f1)
  if [[ "${_workdir_size_kb:-0}" -gt 1048576 ]]; then
    _workdir_size_human=$(du -sh "$WORKDIR" 2>/dev/null | cut -f1)
    echo "⚠ Workdir is ${_workdir_size_human} — snapshot will copy the entire directory."
    echo -n "  Continue? [y/n]: "
    read -r _confirm </dev/tty 2>/dev/null || _confirm="y"
    [[ "$_confirm" =~ ^[Yy] ]] || { echo "Aborted."; exit 0; }
  fi

  _SNAPSHOT_PHASE="copy"
  # MED-2: enforce umask before mktemp to prevent TOCTOU permission window
  # Use a directory next to the workdir to stay on the same filesystem (faster cp, same partition)
  SNAPSHOT_STAGING=$(umask 077; mktemp -d "${WORKDIR%/*}/.claudebox-snapshot-XXXXXX")
  echo "▶ Snapshot: copying workdir to staging..."
  # MED-6: --no-preserve=ownership avoids failure on files owned by other users
  if ! cp -a --no-preserve=ownership "$WORKDIR/." "$SNAPSHOT_STAGING/"; then
    echo "❌ Snapshot copy failed — aborting"
    rm -rf "$SNAPSHOT_STAGING" 2>/dev/null || true
    exit 1
  fi
  echo "✔ Snapshot staging: $SNAPSHOT_STAGING ($(du -sh "$SNAPSHOT_STAGING" 2>/dev/null | cut -f1))"

  # MED-4: save workdir state fingerprint to detect concurrent modifications
  find "$WORKDIR" -not -path "$SNAPSHOT_STAGING*" -printf '%P %T@ %s\n' 2>/dev/null | sort > "$SNAPSHOT_STAGING/.claudebox-manifest"
  _SNAPSHOT_PHASE="sandbox"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  local code=$?
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  [[ -n "$MCP_SERVER_PID" ]] && kill "$MCP_SERVER_PID" 2>/dev/null || true
  rm -f "$SOCKET_ANTHROPIC" "$SOCKET_GITHUB" "$SOCKET_MCP" 2>/dev/null || true
  rm -rf "$ATTACH_DIR" 2>/dev/null || true
  [[ -n "$TEMP_CREDS" && -f "$TEMP_CREDS" && -z "$DUMMY_CREDS_FILE" ]] && rm -f "$TEMP_CREDS" || true
  # HIGH-4: clean up private temp dir if we created it
  [[ "${_SOCK_DIR_CREATED:-}" == true ]] && rm -rf "$_SOCK_DIR" 2>/dev/null || true
  # MED-7: snapshot staging handling depends on phase:
  # - "copy" phase (cp in progress): clean up partial staging
  # - "sandbox" phase (sandbox running): clean up staging (sandbox was interrupted, no useful changes)
  # - "merge" phase (user at merge prompt): PRESERVE staging so user can recover changes
  if [[ -n "${SNAPSHOT_STAGING:-}" && -d "$SNAPSHOT_STAGING" && "${_SNAPSHOT_MERGED:-}" != true ]]; then
    if [[ "${_SNAPSHOT_PHASE:-}" == "merge" ]]; then
      echo ""
      echo "⚠ Snapshot staging PRESERVED (interrupted during merge):"
      echo "  $SNAPSHOT_STAGING"
      echo "  To apply:   rsync -aH --delete '$SNAPSHOT_STAGING/' '$WORKDIR/'"
      echo "  To discard: rm -rf '$SNAPSHOT_STAGING'"
    else
      echo "⚠ Snapshot not merged — cleaning up staging: $SNAPSHOT_STAGING"
      rm -rf "$SNAPSHOT_STAGING" 2>/dev/null || true
    fi
  fi
  exit $code
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------------------
# Notification helper — sends events to --notify-command and/or --notify-webhook
# Usage: notify EVENT_TYPE "message text"
# Events: sandbox_start, sandbox_exit, oom_kill, idle_timeout
# ---------------------------------------------------------------------------
notify() {
  local event="$1" message="$2"

  if [[ -n "$NOTIFY_COMMAND" ]]; then
    CLAUDEBOX_EVENT="$event" CLAUDEBOX_MESSAGE="$message" \
    CLAUDEBOX_WORKDIR="$WORKDIR" CLAUDEBOX_PID="$$" \
      bash -c "$NOTIFY_COMMAND" &>/dev/null &
  fi

  if [[ -n "$NOTIFY_WEBHOOK" ]]; then
    local json
    json=$(node -e "
      console.log(JSON.stringify({
        text: process.argv[1],
        blocks: [{
          type: 'section',
          text: { type: 'mrkdwn', text: process.argv[1] }
        }],
        // Extra fields for non-Slack webhooks
        event: process.argv[2],
        workdir: process.argv[3],
        pid: process.argv[4],
        timestamp: new Date().toISOString()
      }));
    " "$message" "$event" "$WORKDIR" "$$" 2>/dev/null)
    curl -s -X POST -H 'Content-Type: application/json' \
      -d "$json" "$NOTIFY_WEBHOOK" &>/dev/null &
  fi
}

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
command -v bwrap >/dev/null 2>&1 || { echo "❌ bwrap not found (install bubblewrap)"; exit 1; }
command -v node  >/dev/null 2>&1 || { echo "❌ node not found"; exit 1; }
[[ -f "$PROXY_SCRIPT" ]] || { echo "❌ credential-proxy.js not found at $PROXY_SCRIPT"; exit 1; }

# ---------------------------------------------------------------------------
# Locate binaries — only needed when --bind-binaries is set
# ---------------------------------------------------------------------------
resolve_bin() {
  local cmd real
  cmd=$(command -v "$1" 2>/dev/null) || { echo ""; return 0; }
  real=$(realpath "$cmd" 2>/dev/null) || { echo "$cmd"; return 0; }
  echo "$real"
}

NODE_BIN=""
CLAUDE_BIN=""
if [[ "$BIND_BINARIES" == true ]]; then
  NODE_BIN=$(resolve_bin node)
  CLAUDE_BIN=$(resolve_bin claude)
  [[ -n "$NODE_BIN"   ]] || { echo "❌ node binary not found";   exit 1; }
  [[ -n "$CLAUDE_BIN" ]] || { echo "❌ claude binary not found"; exit 1; }
fi

# ---------------------------------------------------------------------------
# Start credential proxy on the host
# ---------------------------------------------------------------------------
echo "▶ Starting credential proxy"
PROXY_ARGS=(
  --anthropic-socket "$SOCKET_ANTHROPIC"
  # CONNECT proxy: Unix socket for bind-mounting into sandbox.
  --github-socket "$SOCKET_GITHUB"
)
if [[ "$ISOLATE_NET" == false ]]; then
  PROXY_ARGS+=(--anthropic-tcp-port "$PORT_ANTHROPIC")
  PROXY_ARGS+=(--github-connect-port "$PORT_GITHUB_CONNECT")
fi
[[ "$ENABLE_GITHUB" == true ]] && PROXY_ARGS+=(--enable-github)
for _url in "${ALLOWLIST_URLS[@]+"${ALLOWLIST_URLS[@]}"}"; do
  PROXY_ARGS+=(--connect-allowlist "$_url")
done
[[ -n "$TOKEN_LIMIT" ]] && PROXY_ARGS+=(--token-limit "$TOKEN_LIMIT")
[[ -n "$AUDIT_LOG" ]] && PROXY_ARGS+=(--audit-log "$AUDIT_LOG")

# GitHub MCP server: start on host, add reverse bridge args to proxy
if [[ "$ENABLE_GITHUB_MCP" == true ]]; then
  [[ -n "${GH_TOKEN:-}" ]] || { echo "❌ --enable-github-mcp requires GH_TOKEN to be set on the host"; exit 1; }
  command -v github-mcp-server >/dev/null 2>&1 || { echo "❌ github-mcp-server not found (install from https://github.com/github/github-mcp-server)"; exit 1; }
  echo "▶ Starting GitHub MCP server (HTTP mode, port $PORT_MCP)"
  GITHUB_PERSONAL_ACCESS_TOKEN="$GH_TOKEN" github-mcp-server http --port "$PORT_MCP" &
  MCP_SERVER_PID=$!
  # Wait for MCP server to be ready
  for _i in $(seq 1 30); do
    (echo >/dev/tcp/127.0.0.1/"$PORT_MCP") 2>/dev/null && break || true
    sleep 0.2
    kill -0 "$MCP_SERVER_PID" 2>/dev/null || { echo "❌ GitHub MCP server died"; exit 1; }
  done
  (echo >/dev/tcp/127.0.0.1/"$PORT_MCP") 2>/dev/null || { echo "❌ GitHub MCP server did not start"; exit 1; }
  echo "✔ GitHub MCP server ready (port $PORT_MCP)"
  # HIGH-3: pass bearer token via env var, not CLI arg (avoids /proc/PID/cmdline leak).
  export MCP_BEARER_TOKEN="$GH_TOKEN"
  PROXY_ARGS+=(--mcp-bridge-socket "$SOCKET_MCP" --mcp-bridge-port "$PORT_MCP")
fi
[[ "$IDLE_TIMEOUT" -gt 0 ]] && PROXY_ARGS+=(--idle-timeout "$IDLE_TIMEOUT")
[[ -n "$NOTIFY_COMMAND" ]] && PROXY_ARGS+=(--notify-command "$NOTIFY_COMMAND")
[[ -n "$NOTIFY_WEBHOOK" ]] && PROXY_ARGS+=(--notify-webhook "$NOTIFY_WEBHOOK")

node "$PROXY_SCRIPT" "${PROXY_ARGS[@]}" &
PROXY_PID=$!

_wait_sockets() {
  [[ -S "$SOCKET_ANTHROPIC" ]] || return 1
  [[ -S "$SOCKET_GITHUB" ]] || return 1
  [[ "$ENABLE_GITHUB_MCP" == true ]] && { [[ -S "$SOCKET_MCP" ]] || return 1; }
  return 0
}
for _i in $(seq 1 25); do
  _wait_sockets && break
  sleep 0.2
  kill -0 "$PROXY_PID" 2>/dev/null || { echo "❌ Proxy process died"; exit 1; }
done
[[ -S "$SOCKET_ANTHROPIC" ]] || { echo "❌ Anthropic proxy socket did not appear"; exit 1; }
[[ -S "$SOCKET_GITHUB" ]]    || { echo "❌ GitHub proxy socket did not appear"; exit 1; }
[[ "$ENABLE_GITHUB_MCP" == true ]] && { [[ -S "$SOCKET_MCP" ]] || { echo "❌ MCP bridge socket did not appear"; exit 1; }; }
_gh_desc="none"; [[ "$ENABLE_GITHUB" == true ]] && _gh_desc="api.github.com"
[[ "$ENABLE_GITHUB_MCP" == true ]] && _gh_desc="${_gh_desc}+mcp"
if [[ ${#ALLOWLIST_URLS[@]} -gt 0 ]]; then
  _extra="${ALLOWLIST_URLS[*]}"
  [[ "$_gh_desc" == "none" ]] && _gh_desc="$_extra" || _gh_desc="${_gh_desc},${_extra}"
fi
echo "✔ Proxy ready (anthropic=$SOCKET_ANTHROPIC, github=$SOCKET_GITHUB, allowlist=$_gh_desc)"

# ---------------------------------------------------------------------------
# Resolve dummy credentials file
# ---------------------------------------------------------------------------
if [[ -n "$DUMMY_CREDS_FILE" ]]; then
  # MED-3: canonicalize to prevent symlink-based file leaks into sandbox.
  DUMMY_CREDS_FILE=$(realpath --canonicalize-existing "$DUMMY_CREDS_FILE" 2>/dev/null) || {
    echo "❌ --dummy-credentials: file not found: $DUMMY_CREDS_FILE"; exit 1; }
  [[ -f "$DUMMY_CREDS_FILE" ]] || { echo "❌ --dummy-credentials: file not found: $DUMMY_CREDS_FILE"; exit 1; }
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$DUMMY_CREDS_FILE" \
    2>/dev/null || { echo "❌ --dummy-credentials: not valid JSON: $DUMMY_CREDS_FILE"; exit 1; }
  TEMP_CREDS="$DUMMY_CREDS_FILE"
  echo "✔ Using provided dummy credentials: $DUMMY_CREDS_FILE"
else
  # Store in XDG_RUNTIME_DIR if available (private tmpfs), else /tmp (LOW-1)
  _CREDS_DIR="${XDG_RUNTIME_DIR:-/tmp}"
  TEMP_CREDS=$(mktemp "$_CREDS_DIR/claude-dummy-creds-XXXXXX.json")
  # HIGH-4: generate a per-session random dummy token so attackers who know the
  # source code cannot forge proxy requests without stealing the session token.
  SESSION_DUMMY_TOKEN=$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
  SESSION_DUMMY_TOKEN="sk-ant-oat01-${SESSION_DUMMY_TOKEN}"
  export SESSION_DUMMY_TOKEN  # used by proxy via environment

  node - "$TEMP_CREDS" <<'NODEEOF'
const fs = require('fs'), os = require('os'), path = require('path');
const dest = process.argv[2];
const DUMMY  = process.env.SESSION_DUMMY_TOKEN;
const DUMMYR = 'sk-ant-ort01-dummyRefreshDummyRefreshDummyRefreshDummyRefreshDummy';
let creds = null;
for (const p of [
  path.join(os.homedir(), '.claude', '.credentials.json'),
  path.join(os.homedir(), '.config', 'claude', 'auth.json'),
]) {
  try { creds = JSON.parse(fs.readFileSync(p, 'utf8')); break; } catch (_) {}
}
if (!creds) {
  creds = { claudeAiOauth: { accessToken: DUMMY, refreshToken: DUMMYR } };
} else if (creds.claudeAiOauth) {
  creds.claudeAiOauth.accessToken  = DUMMY;
  creds.claudeAiOauth.refreshToken = DUMMYR;
} else {
  creds.accessToken = DUMMY;
}
fs.writeFileSync(dest, JSON.stringify(creds, null, 2));
NODEEOF
  echo "✔ Dummy credentials ready (auto-generated)"
fi

# ---------------------------------------------------------------------------
# Build bwrap command
# ---------------------------------------------------------------------------

system_dir_args() {
  local args=()
  args+=(--ro-bind /usr /usr)
  for d in bin sbin lib lib64; do
    local full="/$d"
    if [[ -L "$full" ]]; then
      local target; target=$(readlink "$full")
      args+=(--symlink "$target" "$full")
    elif [[ -d "$full" ]]; then
      args+=(--ro-bind "$full" "$full")
    fi
  done
  printf '%s\0' "${args[@]}"
}

# Create attach socket directory (host-side, bind-mounted rw into sandbox)
mkdir -p "$ATTACH_DIR"
chmod 700 "$ATTACH_DIR"

mapfile -d '' SYS_ARGS < <(system_dir_args)

BWRAP=(
  bwrap

  # ---- Namespace isolation ----
  --unshare-user
  --unshare-ipc
  --unshare-pid
  --unshare-uts
  --unshare-cgroup
  --die-with-parent

  --uid "$(id -u)"
  --gid "$(id -g)"

  # ---- Core filesystem ----
  "${SYS_ARGS[@]}"

  # MED-4: mount only the /etc files actually needed; avoids exposing SSH keys,
  # sudoers, shadow, and other sensitive host config.
  --dir /etc
  --ro-bind-try /etc/ld.so.cache      /etc/ld.so.cache
  --ro-bind-try /etc/ld.so.conf       /etc/ld.so.conf
  --ro-bind-try /etc/ld.so.conf.d     /etc/ld.so.conf.d
  --ro-bind-try /etc/ssl/certs        /etc/ssl/certs
  --ro-bind-try /etc/ca-certificates  /etc/ca-certificates
  --ro-bind-try /etc/pki              /etc/pki
  --ro-bind-try /etc/resolv.conf      /etc/resolv.conf
  --ro-bind-try /etc/nsswitch.conf    /etc/nsswitch.conf
  --ro-bind-try /etc/hosts            /etc/hosts
  --ro-bind-try /etc/hostname         /etc/hostname
  --ro-bind-try /etc/localtime        /etc/localtime
  --ro-bind-try /etc/timezone         /etc/timezone
  --ro-bind-try /etc/passwd           /etc/passwd
  --ro-bind-try /etc/group            /etc/group

  # MED-5: replace /sys with an empty tmpfs; removes hardware fingerprinting
  # and kernel interface exposure. Re-add specific paths if a tool requires them.
  --tmpfs /sys

  # ---- Pseudo-filesystems ----
  --proc /proc
  --dev  /dev
  --tmpfs /tmp
  --tmpfs /run

  # ---- Fake home (tmpfs; real home not exposed) ----
  --tmpfs /home
  --dir "$SANDBOX_HOME"

  # ---- Workdir (added conditionally after array) ----

  # ---- Proxy sockets ----
  --ro-bind "$SOCKET_ANTHROPIC" "$SANDBOX_SOCKET_ANTHROPIC"
  --ro-bind "$SOCKET_GITHUB"    "$SANDBOX_SOCKET_GITHUB"

  # MED-3: bind credential-proxy.js from SCRIPT_DIR (read-only) so the in-sandbox
  # bridge cannot be replaced by a tampered copy in the writable workspace.
  --ro-bind "$PROXY_SCRIPT" /run/credential-proxy.js

  # ---- Attach socket directory (rw — socat creates the socket here) ----
  --bind "$ATTACH_DIR" /run/attach

  # ---- Environment ----
  --clearenv
  --setenv HOME    "$SANDBOX_HOME"
  --setenv USER    "$(id -un)"
  --setenv LOGNAME "$(id -un)"
  --setenv SHELL   /bin/bash
  --setenv TERM    xterm-256color
  --setenv PATH    "$SANDBOX_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
  --setenv ANTHROPIC_BASE_URL "http://127.0.0.1:$PORT_ANTHROPIC"
  # 127.0.0.1 is in NO_PROXY so the Anthropic bridge is reached directly.
  --setenv HTTP_PROXY  ""
  --setenv ALL_PROXY   ""
  --setenv NO_PROXY    "127.0.0.1,localhost,::1"

  # CRIT-3: pass init-script control values via --setenv so the bash -c script
  # below contains NO interpolation of user-controlled strings.
  --setenv _PROXY_SOCK       "$SANDBOX_SOCKET_ANTHROPIC"
  --setenv _PROXY_PORT       "$PORT_ANTHROPIC"
  --setenv _GITHUB_SOCK      "$SANDBOX_SOCKET_GITHUB"
  --setenv _GITHUB_PORT      "$PORT_GITHUB_CONNECT"
  --setenv _ISOLATE_NET      "$ISOLATE_NET"
  --setenv _ENABLE_GITHUB    "$ENABLE_GITHUB"
  --setenv _LAUNCH_SHELL     "$LAUNCH_SHELL"

  --chdir /workspace
)

# Workdir bind mount: snapshot (staging copy), ro, or rw
if [[ "$SNAPSHOT" == true ]]; then
  # Snapshot: bind the staging copy (rw), original workdir untouched
  BWRAP+=(--bind "$SNAPSHOT_STAGING" /workspace)
elif [[ "$READONLY_WORKDIR" == true ]]; then
  BWRAP+=(--ro-bind "$WORKDIR" /workspace)
else
  BWRAP+=(--bind "$WORKDIR" /workspace)
fi

# GitHub: real GH_TOKEN passed directly (TLS tunnel prevents proxy injection).
# HTTPS_PROXY routes gh CLI through the CONNECT proxy (allowlist enforced there).
if [[ "$ENABLE_GITHUB" == true ]]; then
  [[ -n "${GH_TOKEN:-}" ]] || { echo "❌ --enable-github requires GH_TOKEN to be set on the host"; exit 1; }
  BWRAP+=(
    --setenv GH_TOKEN     "$GH_TOKEN"
    --setenv GITHUB_TOKEN "$GH_TOKEN"
    --setenv HTTPS_PROXY  "http://127.0.0.1:$PORT_GITHUB_CONNECT"
  )
fi

# Set HTTPS_PROXY when --allowlist-url is used (even without --enable-github)
# so tools inside sandbox can reach the allowed hosts.
if [[ ${#ALLOWLIST_URLS[@]} -gt 0 && "$ENABLE_GITHUB" != true ]]; then
  BWRAP+=(--setenv HTTPS_PROXY "http://127.0.0.1:$PORT_GITHUB_CONNECT")
fi

# GitHub MCP server: bind-mount the reverse bridge socket and pass config vars
if [[ "$ENABLE_GITHUB_MCP" == true ]]; then
  BWRAP+=(
    --ro-bind "$SOCKET_MCP" "$SANDBOX_SOCKET_MCP"
    --setenv _MCP_SOCK "$SANDBOX_SOCKET_MCP"
    --setenv _MCP_PORT "$PORT_MCP"
    --setenv _ENABLE_GITHUB_MCP "true"
  )
fi

# ~/.claude sharing
if [[ "$SHARE_CLAUDE_DIR" == true && -d "$HOME/.claude" ]]; then
  BWRAP+=(--ro-bind "$HOME/.claude" "$SANDBOX_HOME/.claude")
  BWRAP+=(--ro-bind "$TEMP_CREDS"   "$SANDBOX_HOME/.claude/.credentials.json")
else
  BWRAP+=(--dir     "$SANDBOX_HOME/.claude")
  BWRAP+=(--ro-bind "$TEMP_CREDS" "$SANDBOX_HOME/.claude/.credentials.json")
fi

if [[ "$MOUNT_CLAUDE_MD" == true && "$SHARE_CLAUDE_DIR" == false && -f "$HOME/.claude/CLAUDE.md" ]]; then
  BWRAP+=(--ro-bind "$HOME/.claude/CLAUDE.md" "$SANDBOX_HOME/.claude/CLAUDE.md")
fi

# Session sharing: bind-mount project-specific conversation data (rw) so that
# sessions can be resumed from the host or another sandbox.
# Claude Code stores sessions in ~/.claude/projects/<project-dir-name>/.
# The project dir name is the workdir path with / replaced by -.
if [[ "$SHARE_SESSIONS" == true ]]; then
  # Compute project directory name: /home/user/work/foo → -home-user-work-foo
  _project_dir_name=$(echo "$WORKDIR" | tr '/' '-')
  _host_project_dir="$HOME/.claude/projects/$_project_dir_name"
  _sandbox_project_dir="$SANDBOX_HOME/.claude/projects/$_project_dir_name"

  # Create host-side directories if they don't exist
  mkdir -p "$_host_project_dir"

  # Bind-mount project session data (rw — claude writes conversation JSONL here)
  BWRAP+=(
    --dir "$SANDBOX_HOME/.claude/projects"
    --bind "$_host_project_dir" "$_sandbox_project_dir"
  )

  # Share settings (read-only) for consistent behavior across sessions
  if [[ -f "$HOME/.claude/settings.json" ]]; then
    BWRAP+=(--ro-bind "$HOME/.claude/settings.json" "$SANDBOX_HOME/.claude/settings.json")
  fi

  # Share history (read-only) so `--continue` and `--resume` can find sessions.
  # HIGH-1: rw would let sandbox poison host session history; ro is sufficient
  # because Claude Code reads history to list sessions but writes new entries
  # to the project JSONL which is already rw.
  if [[ -f "$HOME/.claude/history.jsonl" ]]; then
    BWRAP+=(--ro-bind "$HOME/.claude/history.jsonl" "$SANDBOX_HOME/.claude/history.jsonl")
  fi

  echo "✔ Session sharing enabled (project: $_project_dir_name)"
  # HIGH-2: warn about session resume risk — sandboxed code can write crafted
  # JSONL that replays on the host when resumed without a sandbox.
  echo "  ⚠ When resuming shared sessions on the host, review conversation history first."
fi

# HIGH-5: only bind ~/.local/bin/claude if it is owned by the current user
# with no group/world write permission.
SANDBOX_CLAUDE_BIN="$HOME/.local/bin/claude"
if [[ -f "$SANDBOX_CLAUDE_BIN" ]]; then
  _bin_owner=$(stat -c '%U' "$SANDBOX_CLAUDE_BIN" 2>/dev/null || echo "")
  _bin_mode=$(stat -c '%a'  "$SANDBOX_CLAUDE_BIN" 2>/dev/null || echo "777")
  if [[ "$_bin_owner" == "$(id -un)" && ! "$_bin_mode" =~ [2367][0-9][0-9] ]]; then
    BWRAP+=(
      --dir "$SANDBOX_HOME/.local"
      --dir "$SANDBOX_HOME/.local/bin"
      --ro-bind "$SANDBOX_CLAUDE_BIN" "$SANDBOX_HOME/.local/bin/claude"
    )
  else
    echo "⚠ Skipping ~/.local/bin/claude bind: not owned by current user or group/world-writable"
  fi
fi

# --sandbox-home seed
if [[ -n "$SANDBOX_HOME_SEED" ]]; then
  SANDBOX_HOME_SEED=$(realpath --canonicalize-existing "$SANDBOX_HOME_SEED" 2>/dev/null) || {
    echo "❌ --sandbox-home: directory not found: $SANDBOX_HOME_SEED"; exit 1; }
  [[ -d "$SANDBOX_HOME_SEED" ]] || { echo "❌ --sandbox-home: not a directory: $SANDBOX_HOME_SEED"; exit 1; }
  BWRAP+=(--ro-bind "$SANDBOX_HOME_SEED" /run/sandbox-home-seed)
fi

# Network namespace isolation
if [[ "$ISOLATE_NET" == true ]]; then
  BWRAP+=(--unshare-net)
fi

# Out-of-tree binary binding
if [[ "$BIND_BINARIES" == true ]]; then
  BWRAP+=(
    --dir /run/sandbox-bin
    --ro-bind "$NODE_BIN"   /run/sandbox-bin/node
    --ro-bind "$CLAUDE_BIN" /run/sandbox-bin/claude
  )
  BWRAP+=(--setenv PATH "$SANDBOX_HOME/.local/bin:/run/sandbox-bin:/usr/local/bin:/usr/bin:/bin")
fi

# ---------------------------------------------------------------------------
# Build resource limit wrapper (systemd-run --user --scope)
# The wrapper script runs bwrap as a child process so the parent (this script)
# stays outside the cgroup and can detect OOM kills.
# ---------------------------------------------------------------------------
RESOURCE_WRAPPER=()
SCOPE_NAME=""
if [[ -n "$MEM_LIMIT" || -n "$CPU_LIMIT" ]]; then
  command -v systemd-run >/dev/null 2>&1 || { echo "❌ systemd-run required for --mem-limit/--cpu-limit"; exit 1; }
  SCOPE_NAME="claudebox-$$"
  RESOURCE_WRAPPER=(systemd-run --user --scope --unit="$SCOPE_NAME" --quiet)
  [[ -n "$MEM_LIMIT" ]] && RESOURCE_WRAPPER+=(-p "MemoryMax=$MEM_LIMIT" -p "MemorySwapMax=0")
  [[ -n "$CPU_LIMIT" ]] && RESOURCE_WRAPPER+=(-p "CPUQuota=${CPU_LIMIT}%")
  echo "✔ Resource limits: mem=${MEM_LIMIT:-unlimited} cpu=${CPU_LIMIT:-unlimited}%"
fi

# OOM check function — called after sandbox exits
oom_check() {
  local exit_code=$1
  [[ $exit_code -eq 0 ]] && return
  [[ -z "$MEM_LIMIT" ]] && return

  local is_oom=false

  # Signal 9 (exit 137) or SIGTERM from systemd (exit 143) are typical for OOM kills
  if [[ $exit_code -eq 137 || $exit_code -eq 143 ]]; then
    is_oom=true
  fi

  # Check systemd journal for OOM events in this scope
  if [[ -n "${SCOPE_NAME:-}" ]] && command -v journalctl >/dev/null 2>&1; then
    local oom_log
    oom_log=$(journalctl --user --unit="$SCOPE_NAME" --since="-60s" --no-pager -q 2>/dev/null \
      | grep -i -E "oom|kill|memory" || true)
    [[ -n "$oom_log" ]] && is_oom=true
  fi

  # Check dmesg for OOM kills (may need privileges)
  if [[ "$is_oom" == false ]]; then
    local dmesg_oom
    dmesg_oom=$(dmesg --time-format iso 2>/dev/null | tail -20 | grep -i "oom\|out of memory" || true)
    [[ -n "$dmesg_oom" ]] && is_oom=true
  fi

  if [[ "$is_oom" == true ]]; then
    echo ""
    echo "⚠ SANDBOX OOM KILLED — memory limit ($MEM_LIMIT) exceeded (exit code: $exit_code)"
    echo "  Increase with --mem-limit or reduce sandbox workload."
    notify oom_kill ":warning: Sandbox OOM killed — memory limit ($MEM_LIMIT) exceeded (exit code: $exit_code)"
  fi
}

# ---------------------------------------------------------------------------
# Launch sandbox
# CRIT-3 fix: the bash -c script below is a static single-quoted string.
# All runtime values are injected via --setenv above (_PROXY_SOCK, _PROXY_PORT,
# _ISOLATE_NET, _LAUNCH_SHELL) and referenced as $VAR — never interpolated here.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Wall-clock timeout wrapper
# ---------------------------------------------------------------------------
TIMEOUT_WRAPPER=()
if [[ -n "$WALL_TIMEOUT" ]]; then
  command -v timeout >/dev/null 2>&1 || { echo "❌ timeout command required for --timeout"; exit 1; }
  TIMEOUT_WRAPPER=(timeout --signal=TERM --kill-after=30 "${WALL_TIMEOUT}m")
  echo "✔ Wall-clock timeout: ${WALL_TIMEOUT} minutes"
fi

NET_DESC="$([[ "$ISOLATE_NET" == true ]] && echo "isolated (loopback + socket bridges)" || echo "shared host network")"
if [[ "$SNAPSHOT" == true ]]; then _rw_desc="snapshot"
elif [[ "$READONLY_WORKDIR" == true ]]; then _rw_desc="read-only"
else _rw_desc="read-write"; fi
echo "▶ Launching sandbox (workdir: $WORKDIR [$_rw_desc], network: $NET_DESC)"
echo "  Attach from another terminal: $0 --attach"
echo "  Attach socket: $ATTACH_SOCK"
notify sandbox_start ":rocket: Sandbox started — workdir: \`$(basename "$WORKDIR")\` [$_rw_desc], network: $NET_DESC, PID: $$"

SANDBOX_INIT_SCRIPT='
  set -euo pipefail

  # MED-6: --no-dereference prevents symlinks in the seed dir from leaking host files.
  if [[ -d /run/sandbox-home-seed ]]; then
    cp --no-dereference --no-preserve=mode,ownership -rT /run/sandbox-home-seed "$HOME"
  fi

  printf '\''{"hasCompletedOnboarding": true, "installMethod": "native"}'\'' > "$HOME/.claude.json"

  # Start in-sandbox TCP bridges for proxy sockets.
  # Uses /run/credential-proxy.js (read-only bind from SCRIPT_DIR, not /workspace).
  if [[ "$_ISOLATE_NET" == true ]]; then
    if command -v node >/dev/null 2>&1 && [[ -f /run/credential-proxy.js ]]; then
      # Anthropic bridge
      node /run/credential-proxy.js --bridge-only \
        --socket "$_PROXY_SOCK" --tcp-bridge-port "$_PROXY_PORT" &
      for _i in $(seq 1 20); do
        (echo >/dev/tcp/127.0.0.1/"$_PROXY_PORT") 2>/dev/null && break || true
        sleep 0.1
      done
      # GitHub CONNECT bridge (only when --enable-github)
      if [[ "$_ENABLE_GITHUB" == true ]]; then
        node /run/credential-proxy.js --bridge-only \
          --socket "$_GITHUB_SOCK" --tcp-bridge-port "$_GITHUB_PORT" &
        for _i in $(seq 1 20); do
          (echo >/dev/tcp/127.0.0.1/"$_GITHUB_PORT") 2>/dev/null && break || true
          sleep 0.1
        done
      fi
    elif command -v socat >/dev/null 2>&1; then
      socat TCP-LISTEN:"$_PROXY_PORT",fork,reuseaddr UNIX-CLIENT:"$_PROXY_SOCK" &
      if [[ "$_ENABLE_GITHUB" == true ]]; then
        socat TCP-LISTEN:"$_GITHUB_PORT",fork,reuseaddr UNIX-CLIENT:"$_GITHUB_SOCK" &
      fi
      sleep 0.3
    else
      echo "❌ need node or socat for in-sandbox bridge"
      exit 1
    fi
  fi

  # Start attach shell listener (socat) for external access via --attach
  if command -v socat >/dev/null 2>&1; then
    socat UNIX-LISTEN:/run/attach/shell.sock,fork,mode=600 \
      EXEC:"bash -li",pty,stderr,setsid,sigint,sane &
  fi

  # GitHub MCP server bridge (reverse bridge socket → in-sandbox TCP)
  if [[ "${_ENABLE_GITHUB_MCP:-}" == true ]]; then
    if [[ "$_ISOLATE_NET" == true ]]; then
      if command -v node >/dev/null 2>&1 && [[ -f /run/credential-proxy.js ]]; then
        node /run/credential-proxy.js --bridge-only \
          --socket "$_MCP_SOCK" --tcp-bridge-port "$_MCP_PORT" &
        for _i in $(seq 1 20); do
          (echo >/dev/tcp/127.0.0.1/"$_MCP_PORT") 2>/dev/null && break || true
          sleep 0.1
        done
      elif command -v socat >/dev/null 2>&1; then
        socat TCP-LISTEN:"$_MCP_PORT",fork,reuseaddr UNIX-CLIENT:"$_MCP_SOCK" &
        sleep 0.3
      fi
    fi
    # Write MCP server config for Claude Code (streamable-http transport)
    mkdir -p "$HOME/.claude"
    cat > "$HOME/.claude/settings.local.json" <<MCPEOF
{
  "mcpServers": {
    "github": {
      "type": "url",
      "url": "http://127.0.0.1:${_MCP_PORT}/mcp"
    }
  }
}
MCPEOF
    echo "✔ GitHub MCP server configured (port $_MCP_PORT)"
  fi

  echo "✔ Sandbox ready  ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL"

  # Save _LAUNCH_SHELL before cleaning up internal init vars.
  _ls="$_LAUNCH_SHELL"
  unset _PROXY_SOCK _PROXY_PORT _GITHUB_SOCK _GITHUB_PORT _ISOLATE_NET _ENABLE_GITHUB _LAUNCH_SHELL _ENABLE_GITHUB_MCP _MCP_SOCK _MCP_PORT

  if [[ "$_ls" == true ]]; then
    exec bash
  else
    exec claude "$@"
  fi
'

# ---------------------------------------------------------------------------
# Dry-run: print the full command and exit
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" == true ]]; then
  echo "# --- dry-run: bwrap command ---"
  _cmd=()
  [[ ${#TIMEOUT_WRAPPER[@]} -gt 0 ]] && _cmd+=("${TIMEOUT_WRAPPER[@]}")
  [[ ${#RESOURCE_WRAPPER[@]} -gt 0 ]] && _cmd+=("${RESOURCE_WRAPPER[@]}")
  _cmd+=("${BWRAP[@]}" -- bash -c '<SANDBOX_INIT_SCRIPT>' -- "${CLAUDE_ARGS[@]+"${CLAUDE_ARGS[@]}"}")
  printf '%q ' "${_cmd[@]}"
  echo ""
  echo ""
  echo "# --- sandbox init script ---"
  echo "$SANDBOX_INIT_SCRIPT"
  # Clean up snapshot staging created for dry-run inspection
  [[ -n "${SNAPSHOT_STAGING:-}" && -d "$SNAPSHOT_STAGING" ]] && rm -rf "$SNAPSHOT_STAGING"
  _SNAPSHOT_MERGED=true  # prevent cleanup from warning
  exit 0
fi

# Timeout exit code check — called after sandbox exits
timeout_check() {
  local exit_code=$1
  if [[ -n "$WALL_TIMEOUT" && $exit_code -eq 124 ]]; then
    echo ""
    echo "⚠ SANDBOX TIMED OUT — wall-clock limit (${WALL_TIMEOUT}m) reached"
    notify wall_timeout ":alarm_clock: Sandbox timed out — wall-clock limit (${WALL_TIMEOUT}m) reached (workdir: \`$(basename "$WORKDIR")\`)"
  fi
}

# ---------------------------------------------------------------------------
# Diff-on-exit: show git diff --stat if workdir is a git repo
# ---------------------------------------------------------------------------
diff_on_exit() {
  # Skip for snapshot mode (snapshot_merge handles its own diff)
  [[ "$SNAPSHOT" == true ]] && return 0
  # Skip for read-only workdir (no changes possible)
  [[ "$READONLY_WORKDIR" == true ]] && return 0

  # Only if workdir is a git repo
  if [[ -d "$WORKDIR/.git" ]] || git -C "$WORKDIR" rev-parse --git-dir &>/dev/null; then
    local _stat
    _stat=$(git -C "$WORKDIR" diff --stat 2>/dev/null) || true
    local _untracked
    _untracked=$(git -C "$WORKDIR" ls-files --others --exclude-standard 2>/dev/null | head -20) || true

    if [[ -n "$_stat" || -n "$_untracked" ]]; then
      echo ""
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "  WORKDIR CHANGES"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      if [[ -n "$_stat" ]]; then
        echo "$_stat" | sed 's/^/  /'
      fi
      if [[ -n "$_untracked" ]]; then
        local _ucount
        _ucount=$(git -C "$WORKDIR" ls-files --others --exclude-standard 2>/dev/null | wc -l)
        echo ""
        echo "  Untracked files ($((${_ucount}))):"
        echo "$_untracked" | sed 's/^/    /'
        [[ $_ucount -gt 20 ]] && echo "    ... and $((_ucount - 20)) more"
      fi
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Filesystem quarantine: scan modified/created files for suspicious patterns
# ---------------------------------------------------------------------------
quarantine_scan() {
  # Skip for read-only workdir
  [[ "$READONLY_WORKDIR" == true ]] && return 0

  local scan_dir="$WORKDIR"
  # For snapshot mode, scan the staging directory
  [[ "$SNAPSHOT" == true && -d "$SNAPSHOT_STAGING" ]] && scan_dir="$SNAPSHOT_STAGING"

  local warnings=()

  # Check for shell scripts with network commands (potential exfiltration)
  while IFS= read -r -d '' _f; do
    local _rel="${_f#"$scan_dir"/}"
    [[ "$_rel" == .git/* || "$_rel" == node_modules/* ]] && continue
    if grep -lqE '(curl|wget|nc |ncat|socat)\s' "$_f" 2>/dev/null; then
      warnings+=("  ⚠ Script with network commands: $_rel")
    fi
  done < <(find "$scan_dir" -maxdepth 5 -type f \( -name '*.sh' -o -name '*.bash' \) -print0 2>/dev/null)

  # Check for modified dotfiles (potential persistence)
  while IFS= read -r -d '' _f; do
    local _rel="${_f#"$scan_dir"/}"
    warnings+=("  ⚠ Dotfile present: $_rel")
  done < <(find "$scan_dir" -maxdepth 2 -type f \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' -o -name '.zshrc' \) -print0 2>/dev/null)

  # Check for potential encoded secrets (long base64 strings in text files)
  while IFS= read -r -d '' _f; do
    local _rel="${_f#"$scan_dir"/}"
    [[ "$_rel" == .git/* || "$_rel" == node_modules/* || "$_rel" == *.png || "$_rel" == *.jpg || "$_rel" == *.gz || "$_rel" == *.o ]] && continue
    if grep -qP '[A-Za-z0-9+/]{80,}={0,2}' "$_f" 2>/dev/null; then
      warnings+=("  ⚠ Possible encoded secret: $_rel")
    fi
  done < <(find "$scan_dir" -maxdepth 5 -type f -size -1M -print0 2>/dev/null | head -z -n 100)

  if [[ ${#warnings[@]} -gt 0 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  QUARANTINE SCAN (${#warnings[@]} findings)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf '%s\n' "${warnings[@]}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    notify quarantine_warning ":warning: Quarantine scan found ${#warnings[@]} suspicious items in \`$(basename "$WORKDIR")\`"
  fi
}

# ---------------------------------------------------------------------------
# Snapshot merge — review staging changes and apply or rollback
# ---------------------------------------------------------------------------
snapshot_merge() {
  [[ "$SNAPSHOT" != true ]] && return 0
  [[ ! -d "$SNAPSHOT_STAGING" ]] && return 0

  # Mark merge phase so cleanup preserves staging on signal (MED-7)
  _SNAPSHOT_PHASE="merge"

  # Compare staging (modified by sandbox) against original workdir
  # Exclude the manifest file from diff
  local _diff_summary
  _diff_summary=$(diff -rq "$WORKDIR" "$SNAPSHOT_STAGING" --exclude='.claudebox-manifest' 2>/dev/null) || true

  if [[ -z "$_diff_summary" ]]; then
    echo ""
    echo "✔ Snapshot: no changes detected — nothing to merge."
    _SNAPSHOT_MERGED=true
    rm -rf "$SNAPSHOT_STAGING" 2>/dev/null || true
    return 0
  fi

  local change_count
  change_count=$(echo "$_diff_summary" | wc -l)

  # MED-4: detect concurrent modifications to original workdir
  local _concurrent_warning=""
  if [[ -f "$SNAPSHOT_STAGING/.claudebox-manifest" ]]; then
    local _current_manifest
    _current_manifest=$(find "$WORKDIR" -not -path "$SNAPSHOT_STAGING*" -printf '%P %T@ %s\n' 2>/dev/null | sort)
    local _saved_manifest
    _saved_manifest=$(cat "$SNAPSHOT_STAGING/.claudebox-manifest" 2>/dev/null)
    if [[ "$_current_manifest" != "$_saved_manifest" ]]; then
      _concurrent_warning="  ⚠ WARNING: Original workdir was modified while sandbox was running!
    Applying changes may overwrite those modifications."
    fi
  fi

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  SNAPSHOT CHANGES ($change_count differences)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  [[ -n "$_concurrent_warning" ]] && echo "$_concurrent_warning" && echo ""
  echo "$_diff_summary" | head -30 | sed 's/^/  /'
  [[ $change_count -gt 30 ]] && echo "  ... and $((change_count - 30)) more"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Prompt user
  while true; do
    echo -n "  Apply changes to workdir? [y]es / [n]o (rollback) / [d]iff: "
    read -r _answer </dev/tty || _answer="n"
    case "$_answer" in
      y|yes|Y|YES)
        echo "  Applying changes..."
        # Remove manifest before merge
        rm -f "$SNAPSHOT_STAGING/.claudebox-manifest" 2>/dev/null || true
        # MED-5: --hard-links preserves hardlinks; HIGH-4: check rsync exit code
        if rsync -aH --delete "$SNAPSHOT_STAGING/" "$WORKDIR/"; then
          echo "  ✔ Changes applied to $WORKDIR"
          _SNAPSHOT_MERGED=true
          rm -rf "$SNAPSHOT_STAGING" 2>/dev/null || true
          notify snapshot_apply ":white_check_mark: Snapshot changes applied to \`$(basename "$WORKDIR")\` ($change_count differences)"
        else
          # HIGH-4: rsync failed — preserve staging for manual recovery
          echo ""
          echo "  ❌ rsync failed — workdir may be in an inconsistent state!"
          echo "  Staging preserved for manual recovery:"
          echo "    $SNAPSHOT_STAGING"
          echo "  To retry:   rsync -aH --delete '$SNAPSHOT_STAGING/' '$WORKDIR/'"
          echo "  To discard: rm -rf '$SNAPSHOT_STAGING'"
          _SNAPSHOT_MERGED=true  # prevent cleanup from deleting staging
          notify snapshot_error ":x: Snapshot merge failed — staging preserved at $SNAPSHOT_STAGING"
        fi
        return 0
        ;;
      n|no|N|NO)
        echo "  ✔ Rollback — original workdir unchanged."
        _SNAPSHOT_MERGED=true
        rm -rf "$SNAPSHOT_STAGING" 2>/dev/null || true
        notify snapshot_rollback ":rewind: Snapshot rolled back — \`$(basename "$WORKDIR")\` unchanged ($change_count changes discarded)"
        return 0
        ;;
      d|diff|D|DIFF)
        if command -v diff >/dev/null 2>&1; then
          diff -ru "$WORKDIR" "$SNAPSHOT_STAGING" --exclude='.claudebox-manifest' 2>/dev/null | "${PAGER:-less}" || true
        else
          echo "  (diff not available)"
        fi
        ;;
      *)
        echo "  Please answer y, n, or d."
        ;;
    esac
  done
}

# When resource limits are set, run sandbox in background and wait so the
# parent script (outside the cgroup) survives to detect OOM kills.
if [[ ${#RESOURCE_WRAPPER[@]} -gt 0 ]]; then
  "${TIMEOUT_WRAPPER[@]+"${TIMEOUT_WRAPPER[@]}"}" "${RESOURCE_WRAPPER[@]}" "${BWRAP[@]}" -- bash -c "$SANDBOX_INIT_SCRIPT" -- "${CLAUDE_ARGS[@]+"${CLAUDE_ARGS[@]}"}" &
  SANDBOX_PID=$!
  # Forward signals to the sandbox
  trap 'kill -TERM $SANDBOX_PID 2>/dev/null; wait $SANDBOX_PID 2>/dev/null; cleanup' INT TERM
  wait $SANDBOX_PID 2>/dev/null
  SANDBOX_EXIT=$?
  oom_check $SANDBOX_EXIT
  timeout_check $SANDBOX_EXIT
  diff_on_exit
  quarantine_scan
  snapshot_merge
  notify sandbox_exit ":stop_sign: Sandbox exited (code: $SANDBOX_EXIT, workdir: \`$(basename "$WORKDIR")\`)"
  exit $SANDBOX_EXIT
else
  "${TIMEOUT_WRAPPER[@]+"${TIMEOUT_WRAPPER[@]}"}" "${BWRAP[@]}" -- bash -c "$SANDBOX_INIT_SCRIPT" -- "${CLAUDE_ARGS[@]+"${CLAUDE_ARGS[@]}"}"
  SANDBOX_EXIT=$?
  timeout_check $SANDBOX_EXIT
  diff_on_exit
  quarantine_scan
  snapshot_merge
  notify sandbox_exit ":stop_sign: Sandbox exited (code: $SANDBOX_EXIT, workdir: \`$(basename "$WORKDIR")\`)"
  exit $SANDBOX_EXIT
fi
