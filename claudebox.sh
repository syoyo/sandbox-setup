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
# WARNING — default network mode:
#   Without --no-network the sandbox shares the host network namespace. Any compiled binary
#   or raw-socket code inside the sandbox can bypass HTTPS_PROXY and reach the internet
#   directly. Use --no-network for strong network isolation (requires the sysctl below on
#   Ubuntu 22.04+):
#     sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
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
#   ./claudebox.sh --no-network --bind-binaries -- --continue
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/credential-proxy.js"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SOCKET_ANTHROPIC="/tmp/claude-proxy-anthropic-$$.sock"
SANDBOX_SOCKET_ANTHROPIC="/tmp/claude-proxy-anthropic.sock"
PORT_ANTHROPIC=58080
PORT_GITHUB_CONNECT=58081   # HTTPS CONNECT proxy for api.github.com (host-side)
SANDBOX_HOME="/home/sandbox"
WORKDIR="$(pwd)"
MOUNT_CLAUDE_MD=false
SHARE_CLAUDE_DIR=false
ISOLATE_NET=false
BIND_BINARIES=false
LAUNCH_SHELL=false
ENABLE_GITHUB=false
CLAUDE_ARGS=()
PROXY_PID=""
TEMP_CREDS=""
DUMMY_CREDS_FILE=""
SANDBOX_HOME_SEED=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case $1 in
    --mount-claude-md)   MOUNT_CLAUDE_MD=true; shift ;;
    --share-claude-dir)  SHARE_CLAUDE_DIR=true; shift ;;
    --no-network)        ISOLATE_NET=true; shift ;;
    --bind-binaries)     BIND_BINARIES=true; shift ;;
    --shell)             LAUNCH_SHELL=true; shift ;;
    --dummy-credentials) DUMMY_CREDS_FILE=$2; shift 2 ;;
    --workdir)           WORKDIR=$2; shift 2 ;;
    --sandbox-home)      SANDBOX_HOME_SEED=$2; shift 2 ;;
    --enable-github)     ENABLE_GITHUB=true;  shift ;;
    --disable-github)    ENABLE_GITHUB=false; shift ;;
    --anthropic-port)
      [[ "$2" =~ ^[1-9][0-9]{3,4}$ ]] || { echo "❌ --anthropic-port: invalid port '$2'"; exit 1; }
      PORT_ANTHROPIC=$2; shift 2 ;;
    --github-port)
      [[ "$2" =~ ^[1-9][0-9]{3,4}$ ]] || { echo "❌ --github-port: invalid port '$2'"; exit 1; }
      PORT_GITHUB_CONNECT=$2; shift 2 ;;
    --help|-h)
      cat <<'EOF'
claudebox.sh — Run Claude Code in a bwrap sandbox with host-side credential proxy

USAGE:
  claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]

OPTIONS:
  --share-claude-dir     Mount ~/.claude read-only into the sandbox (history, settings, etc.)
                         .credentials.json is automatically replaced with dummy tokens.
  --mount-claude-md      Mount ~/.claude/CLAUDE.md only (subset of --share-claude-dir)
  --no-network           Isolate network namespace (blocks external traffic; loopback only).
                         On Ubuntu 22.04+ requires:
                           sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  --bind-binaries        Bind-mount node and claude from their host paths into the sandbox
                         under /run/sandbox-bin. Use this when they live outside /usr.
  --shell                Launch bash instead of claude (useful for debugging the sandbox).
  --dummy-credentials FILE  Use FILE as the dummy .credentials.json.
  --workdir DIR          Working directory to mount read-write (default: CWD).
                         Must be an existing path; symlinks are resolved.
  --sandbox-home DIR     Copy files from DIR into the sandbox home at startup.
  --enable-github        Enable GitHub access via CONNECT proxy (requires GH_TOKEN on host).
  --anthropic-port PORT  TCP port for Anthropic proxy bridge (default: 58080; range 1024-65535)
  --github-port PORT     TCP port for GitHub CONNECT proxy (default: 58081; range 1024-65535)
  --help                 Show this help

NETWORK:
  default (shared host network namespace)
    WARNING: raw sockets can bypass HTTPS_PROXY. Use --no-network for full isolation.

  --no-network
    Full isolation via --unshare-net. Requires kernel.apparmor_restrict_unprivileged_userns=0
    on Ubuntu 22.04+.

ENVIRONMENT:
  GH_TOKEN               GitHub token (required with --enable-github)
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
# Validate ports don't collide
# ---------------------------------------------------------------------------
[[ "$PORT_ANTHROPIC" -ne "$PORT_GITHUB_CONNECT" ]] || {
  echo "❌ --anthropic-port and --github-port must be different"; exit 1; }

# ---------------------------------------------------------------------------
# Validate and canonicalise workdir (HIGH-4: symlink/path traversal)
# ---------------------------------------------------------------------------
WORKDIR=$(realpath --canonicalize-existing "$WORKDIR" 2>/dev/null) || {
  echo "❌ --workdir does not exist: $WORKDIR"; exit 1; }
[[ "$WORKDIR" == "/" ]]     && { echo "❌ --workdir cannot be /";     exit 1; }
[[ "$WORKDIR" == "$HOME" ]] && { echo "❌ --workdir cannot be \$HOME"; exit 1; }

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  local code=$?
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  rm -f "$SOCKET_ANTHROPIC" 2>/dev/null || true
  [[ -n "$TEMP_CREDS" && -f "$TEMP_CREDS" && -z "$DUMMY_CREDS_FILE" ]] && rm -f "$TEMP_CREDS" || true
  exit $code
}
trap cleanup INT TERM EXIT

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
  # CONNECT proxy always runs; allowlist empty unless --enable-github.
  --github-connect-port "$PORT_GITHUB_CONNECT"
)
if [[ "$ISOLATE_NET" == false ]]; then
  PROXY_ARGS+=(--anthropic-tcp-port "$PORT_ANTHROPIC")
fi
[[ "$ENABLE_GITHUB" == true ]] && PROXY_ARGS+=(--enable-github)

node "$PROXY_SCRIPT" "${PROXY_ARGS[@]}" &
PROXY_PID=$!

for _i in $(seq 1 25); do
  [[ -S "$SOCKET_ANTHROPIC" ]] && break
  sleep 0.2
  kill -0 "$PROXY_PID" 2>/dev/null || { echo "❌ Proxy process died"; exit 1; }
done
[[ -S "$SOCKET_ANTHROPIC" ]] || { echo "❌ Proxy socket did not appear"; exit 1; }
echo "✔ Proxy ready (anthropic=$SOCKET_ANTHROPIC, CONNECT :$PORT_GITHUB_CONNECT allowlist=${ENABLE_GITHUB:+api.github.com}${ENABLE_GITHUB:-none})"

# ---------------------------------------------------------------------------
# Resolve dummy credentials file
# ---------------------------------------------------------------------------
if [[ -n "$DUMMY_CREDS_FILE" ]]; then
  [[ -f "$DUMMY_CREDS_FILE" ]] || { echo "❌ --dummy-credentials: file not found: $DUMMY_CREDS_FILE"; exit 1; }
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$DUMMY_CREDS_FILE" \
    2>/dev/null || { echo "❌ --dummy-credentials: not valid JSON: $DUMMY_CREDS_FILE"; exit 1; }
  TEMP_CREDS="$DUMMY_CREDS_FILE"
  echo "✔ Using provided dummy credentials: $DUMMY_CREDS_FILE"
else
  # Store in XDG_RUNTIME_DIR if available (private tmpfs), else /tmp (LOW-1)
  _CREDS_DIR="${XDG_RUNTIME_DIR:-/tmp}"
  TEMP_CREDS=$(mktemp "$_CREDS_DIR/claude-dummy-creds-XXXXXX.json")
  node - "$TEMP_CREDS" <<'NODEEOF'
const fs = require('fs'), os = require('os'), path = require('path');
const dest = process.argv[2];
const DUMMY  = 'sk-ant-oat01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';
const DUMMYR = 'sk-ant-ort01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';
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

mapfile -d '' SYS_ARGS < <(system_dir_args)

BWRAP=(
  bwrap

  # ---- Namespace isolation ----
  --unshare-user
  --unshare-ipc
  --unshare-pid
  --unshare-uts
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

  # ---- Workdir — the ONLY read-write bind mount ----
  --bind "$WORKDIR" /workspace

  # ---- Anthropic proxy socket ----
  --ro-bind "$SOCKET_ANTHROPIC" "$SANDBOX_SOCKET_ANTHROPIC"

  # MED-3: bind credential-proxy.js from SCRIPT_DIR (read-only) so the in-sandbox
  # bridge cannot be replaced by a tampered copy in the writable workspace.
  --ro-bind "$PROXY_SCRIPT" /run/credential-proxy.js

  # ---- Environment ----
  --clearenv
  --setenv HOME    "$SANDBOX_HOME"
  --setenv USER    "$(id -un)"
  --setenv LOGNAME "$(id -un)"
  --setenv SHELL   /bin/bash
  --setenv TERM    xterm-256color
  --setenv PATH    "$SANDBOX_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
  --setenv ANTHROPIC_BASE_URL "http://127.0.0.1:$PORT_ANTHROPIC"
  # All outbound HTTPS goes through the CONNECT proxy; allowlist enforced there.
  # 127.0.0.1 is in NO_PROXY so the Anthropic bridge is reached directly.
  --setenv HTTP_PROXY  ""
  --setenv HTTPS_PROXY "http://127.0.0.1:$PORT_GITHUB_CONNECT"
  --setenv ALL_PROXY   ""
  --setenv NO_PROXY    "127.0.0.1,localhost,::1"

  # CRIT-3: pass init-script control values via --setenv so the bash -c script
  # below contains NO interpolation of user-controlled strings.
  --setenv _PROXY_SOCK    "$SANDBOX_SOCKET_ANTHROPIC"
  --setenv _PROXY_PORT    "$PORT_ANTHROPIC"
  --setenv _ISOLATE_NET   "$ISOLATE_NET"
  --setenv _LAUNCH_SHELL  "$LAUNCH_SHELL"

  --chdir /workspace
)

# GitHub: real GH_TOKEN passed directly (TLS tunnel prevents proxy injection).
# Proxy CONNECT allowlist is empty unless --enable-github, blocking api.github.com.
if [[ "$ENABLE_GITHUB" == true ]]; then
  [[ -n "${GH_TOKEN:-}" ]] || { echo "❌ --enable-github requires GH_TOKEN to be set on the host"; exit 1; }
  BWRAP+=(
    --setenv GH_TOKEN     "$GH_TOKEN"
    --setenv GITHUB_TOKEN "$GH_TOKEN"
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
# Launch sandbox
# CRIT-3 fix: the bash -c script below is a static single-quoted string.
# All runtime values are injected via --setenv above (_PROXY_SOCK, _PROXY_PORT,
# _ISOLATE_NET, _LAUNCH_SHELL) and referenced as $VAR — never interpolated here.
# ---------------------------------------------------------------------------
NET_DESC="$([[ "$ISOLATE_NET" == true ]] && echo "isolated (loopback only)" || echo "shared host network")"
echo "▶ Launching sandbox (workdir: $WORKDIR, network: $NET_DESC)"

"${BWRAP[@]}" -- bash -c '
  set -euo pipefail

  # MED-6: --no-dereference prevents symlinks in the seed dir from leaking host files.
  if [[ -d /run/sandbox-home-seed ]]; then
    cp --no-dereference -rT /run/sandbox-home-seed "$HOME"
  fi

  printf '\''{"hasCompletedOnboarding": true, "installMethod": "native"}'\'' > "$HOME/.claude.json"

  # In --no-network mode start an in-sandbox TCP bridge for the Anthropic proxy.
  # Uses /run/credential-proxy.js (read-only bind from SCRIPT_DIR, not /workspace).
  if [[ "$_ISOLATE_NET" == true ]]; then
    if command -v node >/dev/null 2>&1 && [[ -f /run/credential-proxy.js ]]; then
      node /run/credential-proxy.js --bridge-only \
        --socket "$_PROXY_SOCK" --tcp-bridge-port "$_PROXY_PORT" &
      for _i in $(seq 1 20); do
        (echo >/dev/tcp/127.0.0.1/"$_PROXY_PORT") 2>/dev/null && break || true
        sleep 0.1
      done
    elif command -v socat >/dev/null 2>&1; then
      socat TCP-LISTEN:"$_PROXY_PORT",fork,reuseaddr UNIX-CLIENT:"$_PROXY_SOCK" &
      sleep 0.3
    else
      echo "❌ --no-network: need node or socat for in-sandbox bridge"
      exit 1
    fi
  fi

  echo "✔ Sandbox ready  ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL"

  # Save _LAUNCH_SHELL before cleaning up internal init vars.
  _ls="$_LAUNCH_SHELL"
  unset _PROXY_SOCK _PROXY_PORT _ISOLATE_NET _LAUNCH_SHELL

  if [[ "$_ls" == true ]]; then
    exec bash
  else
    exec claude "$@"
  fi
' -- "${CLAUDE_ARGS[@]+"${CLAUDE_ARGS[@]}"}"
