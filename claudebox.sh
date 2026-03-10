#!/usr/bin/env bash
# claudebox.sh — Run Claude Code in a bubblewrap (bwrap) sandbox with host-side credential proxy.
#
# Security model:
#   - Workdir is the only read-write location
#   - Everything else is read-only or not exposed
#   - Real home directory NOT mounted (fake tmpfs home)
#   - Real credentials never enter the sandbox; dummy tokens replaced by host proxy via Unix socket
#
# Network modes (see --no-network):
#   default     Sandbox shares host network namespace. The host-side proxy is reachable at
#               127.0.0.1:BRIDGE_PORT. Works everywhere, no kernel config needed.
#   --no-network  Full net namespace isolation (external traffic blocked; loopback only).
#               Requires unprivileged user namespaces to support RTM_NEWADDR, which on
#               Ubuntu 22.04+ needs:
#                 sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
#
# REQUIREMENTS:
#   - bwrap (bubblewrap) installed
#   - Node.js on the host (for credential-proxy.js)
#
# USAGE:
#   ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]
#
# EXAMPLES:
#   # Basic: run Claude interactively in the current directory
#   ./claudebox.sh
#
#   # Pass arguments directly to claude
#   ./claudebox.sh -- -p "explain this codebase"
#   ./claudebox.sh -- --continue
#
#   # Also mount your personal CLAUDE.md (read-only)
#   ./claudebox.sh --mount-claude-md
#
#   # Specific working directory
#   ./claudebox.sh --workdir ~/projects/myapp
#
#   # Enable GitHub credential injection as well
#   ./claudebox.sh --enable-github
#
#   # GitHub only (disable Anthropic injection, e.g. when using API key directly)
#   ./claudebox.sh --disable-anthropic --enable-github
#
#   # Custom socket path (useful when running multiple sandboxes in parallel)
#   ./claudebox.sh --socket /tmp/my-proxy.sock -- --bridge-port 58081
#
#   # Full network isolation (requires sysctl; see --no-network note above)
#   ./claudebox.sh --no-network
#
#   # Bind out-of-tree node/claude into the sandbox (needed when they live outside /usr)
#   ./claudebox.sh --bind-binaries
#
#   # Full example: specific dir, CLAUDE.md, github, no-network, bind binaries
#   ./claudebox.sh --workdir ~/projects/myapp --mount-claude-md --enable-github --no-network --bind-binaries -- --continue
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/credential-proxy.js"

# Defaults
SOCKET_ANTHROPIC="/tmp/claude-proxy-anthropic-$$.sock"
SANDBOX_SOCKET_ANTHROPIC="/tmp/claude-proxy-anthropic.sock"
PORT_ANTHROPIC=58080
PORT_GITHUB_CONNECT=58081   # HTTPS CONNECT proxy for api.github.com (host-side, internet-facing)
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
DUMMY_CREDS_FILE=""    # set via --dummy-credentials; skips auto-generation if provided
SANDBOX_HOME_SEED=""   # set via --sandbox-home; directory copied into sandbox home

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case $1 in
    --mount-claude-md)   MOUNT_CLAUDE_MD=true; shift ;;
    --share-claude-dir)  SHARE_CLAUDE_DIR=true; shift ;;
    --no-network)       ISOLATE_NET=true; shift ;;
    --bind-binaries)    BIND_BINARIES=true; shift ;;
    --shell)            LAUNCH_SHELL=true; shift ;;
    --dummy-credentials) DUMMY_CREDS_FILE=$2; shift 2 ;;
    --workdir)          WORKDIR=$2; shift 2 ;;
    --sandbox-home)     SANDBOX_HOME_SEED=$2; shift 2 ;;
    --enable-github)    ENABLE_GITHUB=true;  shift ;;
    --disable-github)   ENABLE_GITHUB=false; shift ;;
    --anthropic-port)   PORT_ANTHROPIC=$2; shift 2 ;;
    --github-port)      PORT_GITHUB_CONNECT=$2; shift 2 ;;
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
                         under /run/sandbox-bin. Use this when they live outside /usr and
                         are not otherwise visible inside the sandbox.
  --shell                Launch bash instead of claude (useful for debugging the sandbox).
  --dummy-credentials FILE  Use FILE as the dummy .credentials.json instead of auto-generating
                         one from the host credentials. The file must contain valid JSON with
                         the dummy token values that the proxy is configured to replace.
  --workdir DIR          Working directory to mount read-write (default: CWD)
  --sandbox-home DIR     Copy files from DIR into the sandbox home at startup
  --enable-github        Enable GitHub access: passes real GH_TOKEN into sandbox and starts
                         a host-side HTTPS CONNECT proxy whitelisting only api.github.com.
                         Requires GH_TOKEN to be set on the host.
  --anthropic-port PORT  TCP port for Anthropic proxy bridge (default: 58080)
  --github-port PORT     TCP port for GitHub CONNECT proxy (default: 58081)
  --help                 Show this help

NETWORK MODES:
  default (no --no-network)
    Sandbox shares host network namespace. Each service proxy listens on its own
    host loopback port, reachable from inside the sandbox at the same address.

  --no-network
    Full net namespace isolation via --unshare-net. External traffic is impossible.
    Each proxy socket is bridged to its own loopback port inside the sandbox.
    Requires kernel.apparmor_restrict_unprivileged_userns=0 on Ubuntu 22.04+.

ENVIRONMENT:
  GH_TOKEN               GitHub token forwarded to proxy (--enable-github also needed)
  CLAUDE_CREDENTIALS_FILE  Override Claude credentials file path

SANDBOX PROPERTIES:
  - Only <workdir> is writable; all other paths are read-only
  - Real home directory NOT exposed (fake home at /home/sandbox on tmpfs)
  - Real credentials NOT in sandbox (dummy tokens replaced by host proxy per-request)
  - Each service has a dedicated Unix socket + TCP port; no URL-based routing
EOF
      exit 0 ;;
    --) shift; CLAUDE_ARGS+=("$@"); break ;;
    *)  CLAUDE_ARGS+=("$1"); shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  local code=$?
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  rm -f "$SOCKET_ANTHROPIC" 2>/dev/null || true
  # Only delete if we auto-generated it, not if the user supplied their own file
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

# Returns realpath of a command, or empty string if not found
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
# Start credential proxy on the host (Unix socket)
# In default mode also open a host-side TCP bridge so the sandbox can reach it
# on 127.0.0.1:BRIDGE_PORT without needing a separate net namespace.
# ---------------------------------------------------------------------------
echo "▶ Starting credential proxy (anthropic)"
PROXY_ARGS=(--anthropic-socket "$SOCKET_ANTHROPIC")
# In shared-network mode, open a host-side TCP bridge so the sandbox can reach
# the proxy on 127.0.0.1:PORT_ANTHROPIC without its own net namespace.
if [[ "$ISOLATE_NET" == false ]]; then
  PROXY_ARGS+=(--anthropic-tcp-port "$PORT_ANTHROPIC")
fi
if [[ "$ENABLE_GITHUB" == true ]]; then
  PROXY_ARGS+=(--github-connect-port "$PORT_GITHUB_CONNECT")
fi

node "$PROXY_SCRIPT" "${PROXY_ARGS[@]}" &
PROXY_PID=$!

for _i in $(seq 1 25); do
  [[ -S "$SOCKET_ANTHROPIC" ]] && break
  sleep 0.2
  kill -0 "$PROXY_PID" 2>/dev/null || { echo "❌ Proxy process died"; exit 1; }
done
[[ -S "$SOCKET_ANTHROPIC" ]] || { echo "❌ Proxy socket did not appear"; exit 1; }
echo "✔ Proxy ready ($SOCKET_ANTHROPIC${ENABLE_GITHUB:+, github CONNECT :$PORT_GITHUB_CONNECT → api.github.com})"

# ---------------------------------------------------------------------------
# Resolve dummy credentials file
# ---------------------------------------------------------------------------
if [[ -n "$DUMMY_CREDS_FILE" ]]; then
  # User supplied their own dummy credentials file — validate and use directly
  [[ -f "$DUMMY_CREDS_FILE" ]] || { echo "❌ --dummy-credentials: file not found: $DUMMY_CREDS_FILE"; exit 1; }
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$DUMMY_CREDS_FILE" \
    2>/dev/null || { echo "❌ --dummy-credentials: file is not valid JSON: $DUMMY_CREDS_FILE"; exit 1; }
  TEMP_CREDS="$DUMMY_CREDS_FILE"
  echo "✔ Using provided dummy credentials: $DUMMY_CREDS_FILE"
else
  # Auto-generate: copy host credentials structure but replace tokens with dummy values
  TEMP_CREDS=$(mktemp /tmp/claude-dummy-creds-XXXXXX.json)
  node - "$TEMP_CREDS" <<'NODEEOF'
const fs = require('fs'), os = require('os'), path = require('path');
const dest = process.argv[2];
const DUMMY = 'sk-ant-oat01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';
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

# Determine whether /bin, /lib etc. are symlinks (usr-merge) or real dirs
# and generate the right mount arguments.
system_dir_args() {
  local args=()
  # Bind /usr read-only (covers /usr/bin, /usr/lib, /usr/local, etc.)
  args+=(--ro-bind /usr /usr)

  # For each legacy top-level dir: symlink if it's already a symlink, bind otherwise
  for d in bin sbin lib lib64; do
    local full="/$d"
    if [[ -L "$full" ]]; then
      # It's a symlink (e.g. /bin -> usr/bin); recreate the symlink in sandbox
      local target
      target=$(readlink "$full")
      args+=(--symlink "$target" "$full")
    elif [[ -d "$full" ]]; then
      args+=(--ro-bind "$full" "$full")
    fi
  done
  printf '%s\0' "${args[@]}"
}

# Read system dir args as null-separated into an array
mapfile -d '' SYS_ARGS < <(system_dir_args)

BWRAP=(
  bwrap

  # ---- Namespace isolation ----
  # Always unshare user/ipc/pid/uts. Net is only unshared with --no-network.
  # (Ubuntu 22.04+ AppArmor blocks RTM_NEWADDR in unprivileged net namespaces;
  #  use --no-network only after: sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)
  --unshare-user
  --unshare-ipc
  --unshare-pid
  --unshare-uts
  --die-with-parent      # kill sandbox if parent process dies

  # Keep the real uid/gid inside the sandbox (avoids running as fake root)
  --uid "$(id -u)"
  --gid "$(id -g)"

  # ---- Core filesystem (read-only from host) ----
  "${SYS_ARGS[@]}"
  --ro-bind /etc /etc                  # system config (ld.so, ssl certs, passwd, ...)
  --ro-bind-try /sys /sys              # needed by some tools; ignore if unavailable

  # ---- Pseudo-filesystems ----
  --proc /proc
  --dev  /dev                          # minimal devtmpfs (null, zero, urandom, tty, pts)
  --tmpfs /tmp                         # isolated /tmp
  --tmpfs /run                         # isolated /run

  # ---- Fake home (tmpfs; real home not exposed) ----
  --tmpfs /home
  --dir "$SANDBOX_HOME"

  # ---- Workdir — the ONLY read-write bind mount ----
  --bind "$WORKDIR" /workspace

  # ---- Credential proxy sockets (one per service, read-only) ----
  --ro-bind "$SOCKET_ANTHROPIC" "$SANDBOX_SOCKET_ANTHROPIC"

  # ---- Environment ----
  --clearenv
  --setenv HOME    "$SANDBOX_HOME"
  --setenv USER    "$(id -un)"
  --setenv LOGNAME "$(id -un)"
  --setenv SHELL   /bin/bash
  --setenv TERM    "${TERM:-xterm-256color}"
  --setenv PATH    "$SANDBOX_HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
  --setenv ANTHROPIC_BASE_URL "http://127.0.0.1:$PORT_ANTHROPIC"
  # Block all external HTTP/HTTPS traffic by default.
  # 127.0.0.1 is listed in NO_PROXY so the Anthropic bridge is reached directly.
  # When --enable-github is active, HTTPS_PROXY is overridden below to allow
  # api.github.com through the host-side CONNECT proxy.
  --setenv HTTP_PROXY  ""
  --setenv HTTPS_PROXY ""
  --setenv ALL_PROXY   ""
  --setenv NO_PROXY    "127.0.0.1,localhost,::1"

  --chdir /workspace
)

# GitHub: gh CLI uses HTTPS to api.github.com. We route it through a host-side
# CONNECT proxy (which has real internet access) that whitelists only api.github.com.
# The real GH_TOKEN is passed directly since we can't inject into a TLS tunnel.
if [[ "$ENABLE_GITHUB" == true ]]; then
  [[ -n "${GH_TOKEN:-}" ]] || { echo "❌ --enable-github requires GH_TOKEN to be set on the host"; exit 1; }
  BWRAP+=(
    --setenv GH_TOKEN     "$GH_TOKEN"
    --setenv GITHUB_TOKEN "$GH_TOKEN"
    --setenv HTTPS_PROXY  "http://127.0.0.1:$PORT_GITHUB_CONNECT"
  )
fi

# ~/.claude sharing
# Two modes:
#   --share-claude-dir  bind the whole ~/.claude ro, then overlay .credentials.json with dummies
#   neither             create a bare ~/.claude dir and mount only the dummy credentials
if [[ "$SHARE_CLAUDE_DIR" == true && -d "$HOME/.claude" ]]; then
  # 1. Bind real ~/.claude read-only
  BWRAP+=(--ro-bind "$HOME/.claude" "$SANDBOX_HOME/.claude")
  # 2. Overlay .credentials.json with dummy tokens (later mount wins in bwrap)
  BWRAP+=(--ro-bind "$TEMP_CREDS"   "$SANDBOX_HOME/.claude/.credentials.json")
else
  # Bare dir + dummy credentials only
  BWRAP+=(--dir "$SANDBOX_HOME/.claude")
  BWRAP+=(--ro-bind "$TEMP_CREDS" "$SANDBOX_HOME/.claude/.credentials.json")
fi

# --mount-claude-md on top (no-op if --share-claude-dir already included it)
if [[ "$MOUNT_CLAUDE_MD" == true && "$SHARE_CLAUDE_DIR" == false && -f "$HOME/.claude/CLAUDE.md" ]]; then
  BWRAP+=(--ro-bind "$HOME/.claude/CLAUDE.md" "$SANDBOX_HOME/.claude/CLAUDE.md")
fi

# Install ~/.local/bin/claude into the sandbox home's .local/bin
SANDBOX_CLAUDE_BIN="$HOME/.local/bin/claude"
if [[ -f "$SANDBOX_CLAUDE_BIN" ]]; then
  BWRAP+=(
    --dir "$SANDBOX_HOME/.local"
    --dir "$SANDBOX_HOME/.local/bin"
    --ro-bind "$SANDBOX_CLAUDE_BIN" "$SANDBOX_HOME/.local/bin/claude"
  )
fi

# Seed sandbox home from a host directory (bind-mount read-only; copy in init script)
if [[ -n "$SANDBOX_HOME_SEED" ]]; then
  [[ -d "$SANDBOX_HOME_SEED" ]] || { echo "❌ --sandbox-home: directory not found: $SANDBOX_HOME_SEED"; exit 1; }
  SANDBOX_HOME_SEED=$(realpath "$SANDBOX_HOME_SEED")
  BWRAP+=(--ro-bind "$SANDBOX_HOME_SEED" /run/sandbox-home-seed)
fi

# Network namespace isolation (opt-in; requires AppArmor userns sysctl on Ubuntu)
if [[ "$ISOLATE_NET" == true ]]; then
  BWRAP+=(--unshare-net)
fi

# Out-of-tree binary binding (opt-in via --bind-binaries)
# /usr is already ro-bound; use /run/sandbox-bin (tmpfs) to avoid "read-only fs" errors.
if [[ "$BIND_BINARIES" == true ]]; then
  BWRAP+=(
    --dir /run/sandbox-bin
    --ro-bind "$NODE_BIN"   /run/sandbox-bin/node
    --ro-bind "$CLAUDE_BIN" /run/sandbox-bin/claude
  )
  # Prepend to PATH so these take precedence over any system-installed versions
  BWRAP+=(--setenv PATH /run/sandbox-bin:/usr/local/bin:/usr/bin:/bin)
fi


# ---------------------------------------------------------------------------
# Sandbox init script (runs as PID 1 inside the sandbox)
# ---------------------------------------------------------------------------
SANDBOX_HOME_VAL="$SANDBOX_HOME"
SANDBOX_SOCKET_ANTHROPIC_VAL="$SANDBOX_SOCKET_ANTHROPIC"
PORT_ANTHROPIC_VAL="$PORT_ANTHROPIC"
ISOLATE_NET_VAL="$ISOLATE_NET"

NET_DESC="$([[ "$ISOLATE_NET" == true ]] && echo "isolated (loopback only)" || echo "shared host network")"
echo "▶ Launching sandbox (workdir: $WORKDIR, network: $NET_DESC)"

# Helper: start one TCP→Unix bridge inside the sandbox (for --no-network mode)
# Usage: start_bridge <socket> <port> <label>
# Tries node credential-proxy.js --bridge-only first, falls back to socat.
read -r -d '' _BRIDGE_HELPER <<'BASHEOF' || true
start_bridge() {
  local sock="$1" port="$2" label="$3"
  if command -v node >/dev/null 2>&1 && [[ -f /workspace/credential-proxy.js ]]; then
    node /workspace/credential-proxy.js --bridge-only --socket "$sock" --tcp-bridge-port "$port" &
    for _i in $(seq 1 20); do
      (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null && break || true
      sleep 0.1
    done
  elif command -v socat >/dev/null 2>&1; then
    socat TCP-LISTEN:"$port",fork,reuseaddr UNIX-CLIENT:"$sock" &
    sleep 0.3
  else
    echo "❌ --no-network: need node or socat for in-sandbox bridge ($label)"
    exit 1
  fi
}
BASHEOF

"${BWRAP[@]}" -- bash -c '
  set -euo pipefail

  # Copy sandbox-home seed files into the home directory
  if [[ -d /run/sandbox-home-seed ]]; then
    cp -rT /run/sandbox-home-seed "'"$SANDBOX_HOME_VAL"'"
  fi

  # Write minimal Claude config to skip onboarding screen
  printf '"'"'{"hasCompletedOnboarding": true, "installMethod": "native"}'"'"' > "'"$SANDBOX_HOME_VAL"'/.claude.json"

  # In --no-network mode the sandbox has its own net namespace, so we need an
  # in-sandbox TCP bridge from the mounted Unix socket to 127.0.0.1:PORT_ANTHROPIC.
  if [[ "'"$ISOLATE_NET_VAL"'" == true ]]; then
    '"$_BRIDGE_HELPER"'
    start_bridge "'"$SANDBOX_SOCKET_ANTHROPIC_VAL"'" '"$PORT_ANTHROPIC_VAL"' anthropic
  fi

  echo "✔ Sandbox ready  ANTHROPIC_BASE_URL=$ANTHROPIC_BASE_URL"
  if [[ "'"$LAUNCH_SHELL"'" == true ]]; then
    exec bash
  else
    exec claude "$@"
  fi
' -- "${CLAUDE_ARGS[@]+"${CLAUDE_ARGS[@]}"}"
