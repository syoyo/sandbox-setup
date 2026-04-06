#!/usr/bin/env bash
# ============================================================================
# run-remote-proxy.sh — Three-node credential proxy relay via SSH tunnels.
#
# Architecture:
#
#   Host node              Server node              Client node
#   (has credentials)      (intermediary)            (runs claudebox)
#   ┌─────────────┐        ┌─────────────┐          ┌─────────────┐
#   │ credential-  │  SSH   │             │   SSH    │ claudebox   │
#   │ proxy.js     │──-R──>│  :RELAY_PORT │<──-L──  │ :LOCAL_PORT │
#   │ :PROXY_PORT  │       │  (listening) │         │ (listening) │
#   └─────────────┘        └─────────────┘          └─────────────┘
#
#   Host and Client cannot reach each other directly.
#   Both can reach the Server node via SSH.
#
# Usage:
#   # 1. On the HOST node (has Claude credentials):
#   ./run-remote-proxy.sh host --server user@server.example.com
#
#   # 2. On the CLIENT node (runs Claude Code):
#   ./run-remote-proxy.sh client --server user@server.example.com
#
#   The "host" command starts the credential proxy and opens an SSH
#   reverse tunnel to the server. The "client" command opens an SSH
#   local tunnel from the server and prints the claudebox command
#   to run.
#
# Options (all modes):
#   --server USER@HOST     SSH destination for the server node (required)
#   --proxy-port PORT      Credential proxy listen port on host (default: 58080)
#   --relay-port PORT      Port on the server node (default: 58090)
#   --local-port PORT      Port on the client node (default: 58080)
#   --ssh-opts "OPTS"      Extra SSH options (e.g. "-i ~/.ssh/mykey -p 2222")
#
# Environment:
#   SSH_SERVER             Alternative to --server
#
# Example (3 terminals):
#   # Terminal 1 (host — has ~/.claude/.credentials.json):
#   ./run-remote-proxy.sh host --server admin@jump.example.com
#
#   # Terminal 2 (client — wants to run Claude Code):
#   ./run-remote-proxy.sh client --server admin@jump.example.com
#   # Then copy-paste the printed claudebox command.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
SSH_SERVER="${SSH_SERVER:-}"
PROXY_PORT=58080
RELAY_PORT=58090
LOCAL_PORT=58080
SSH_OPTS=""
MODE=""

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 {host|client} --server USER@HOST [OPTIONS]"
  exit 1
fi

MODE="$1"; shift

case "$MODE" in
  host|client) ;;
  -h|--help)
    sed -n '2,/^# =====/{ /^# =====/d; s/^# \{0,1\}//; p }' "$0"
    exit 0 ;;
  *)
    echo "❌ Unknown mode: $MODE (expected: host or client)"
    exit 1 ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)      SSH_SERVER="$2"; shift 2 ;;
    --proxy-port)  PROXY_PORT="$2"; shift 2 ;;
    --relay-port)  RELAY_PORT="$2"; shift 2 ;;
    --local-port)  LOCAL_PORT="$2"; shift 2 ;;
    --ssh-opts)    SSH_OPTS="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# =====/{ /^# =====/d; s/^# \{0,1\}//; p }' "$0"
      exit 0 ;;
    *)
      echo "❌ Unknown option: $1"; exit 1 ;;
  esac
done

[[ -n "$SSH_SERVER" ]] || { echo "❌ --server USER@HOST is required"; exit 1; }

# Build SSH options array
SSH_ARGS=()
if [[ -n "$SSH_OPTS" ]]; then
  read -ra SSH_ARGS <<< "$SSH_OPTS"
fi

# ---------------------------------------------------------------------------
# HOST mode: start credential proxy + SSH reverse tunnel to server
# ---------------------------------------------------------------------------
if [[ "$MODE" == "host" ]]; then
  echo "============================================================"
  echo "  HOST MODE — Credential Proxy + SSH Reverse Tunnel"
  echo "============================================================"
  echo ""
  echo "  Proxy port (local) : $PROXY_PORT"
  echo "  Relay port (server): $RELAY_PORT"
  echo "  Server             : $SSH_SERVER"
  echo ""

  # Check prerequisites
  command -v node >/dev/null 2>&1 || { echo "❌ node not found"; exit 1; }
  [[ -f "$SCRIPT_DIR/credential-proxy.js" ]] || { echo "❌ credential-proxy.js not found"; exit 1; }

  # Generate per-session dummy token
  SESSION_DUMMY_TOKEN=$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
  SESSION_DUMMY_TOKEN="sk-ant-oat01-${SESSION_DUMMY_TOKEN}"
  export SESSION_DUMMY_TOKEN

  # Socket path
  _RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
  SOCKET_ANTHROPIC="${_RUNTIME_DIR}/claude-proxy-anthropic-$$.sock"

  PROXY_PID=""
  SSH_PID=""

  cleanup() {
    echo ""
    echo "▶ Shutting down..."
    [[ -n "$SSH_PID" ]] && kill "$SSH_PID" 2>/dev/null || true
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    rm -f "$SOCKET_ANTHROPIC" 2>/dev/null || true
    # Write token file for the session
    rm -f "${_RUNTIME_DIR}/claudebox-remote-token-$$.txt" 2>/dev/null || true
    echo "✔ Stopped"
  }
  trap cleanup INT TERM EXIT

  # Start credential proxy
  echo "▶ Starting credential proxy on port $PROXY_PORT..."
  node "$SCRIPT_DIR/credential-proxy.js" \
    --anthropic-socket "$SOCKET_ANTHROPIC" \
    --anthropic-tcp-port "$PROXY_PORT" &
  PROXY_PID=$!

  # Wait for proxy to be ready
  for _i in $(seq 1 30); do
    (echo >/dev/tcp/127.0.0.1/"$PROXY_PORT") 2>/dev/null && break || true
    sleep 0.3
    kill -0 "$PROXY_PID" 2>/dev/null || { echo "❌ Proxy died"; exit 1; }
  done
  (echo >/dev/tcp/127.0.0.1/"$PROXY_PORT") 2>/dev/null || { echo "❌ Proxy did not start"; exit 1; }
  echo "✔ Credential proxy ready on 127.0.0.1:$PROXY_PORT"

  # Save token to file so user can retrieve it
  TOKEN_FILE="${_RUNTIME_DIR}/claudebox-remote-token-$$.txt"
  echo "$SESSION_DUMMY_TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"

  echo ""
  echo "▶ Opening SSH reverse tunnel: server:$RELAY_PORT → localhost:$PROXY_PORT"
  echo "  ssh -R $RELAY_PORT:127.0.0.1:$PROXY_PORT $SSH_SERVER"
  echo ""

  # SSH reverse tunnel: expose local proxy port on server's relay port
  # -N: no remote command, -o ExitOnForwardFailure: fail if port is taken
  ssh -N -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -R "0.0.0.0:${RELAY_PORT}:127.0.0.1:${PROXY_PORT}" \
    "${SSH_ARGS[@]+"${SSH_ARGS[@]}"}" \
    "$SSH_SERVER" &
  SSH_PID=$!

  sleep 2
  kill -0 "$SSH_PID" 2>/dev/null || { echo "❌ SSH tunnel failed to start"; exit 1; }

  echo "✔ SSH reverse tunnel active"
  echo ""
  echo "============================================================"
  echo "  Proxy is live. Give this info to the CLIENT:"
  echo "============================================================"
  echo ""
  echo "  Relay port on server : $RELAY_PORT"
  echo "  Dummy token          : $SESSION_DUMMY_TOKEN"
  echo ""
  echo "  Client command:"
  echo "    ./run-remote-proxy.sh client \\"
  echo "      --server $SSH_SERVER \\"
  echo "      --relay-port $RELAY_PORT"
  echo ""
  echo "  Then on the client, run claudebox with:"
  echo "    ./claudebox.sh --proxy-only \\"
  echo "      --external-proxy 127.0.0.1:$LOCAL_PORT \\"
  echo "      --external-proxy-token \"$SESSION_DUMMY_TOKEN\""
  echo ""
  echo "  Press Ctrl-C to stop."
  echo "============================================================"

  # Wait for SSH tunnel (blocks until killed)
  wait "$SSH_PID" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# CLIENT mode: SSH local tunnel from server + print claudebox command
# ---------------------------------------------------------------------------
if [[ "$MODE" == "client" ]]; then
  echo "============================================================"
  echo "  CLIENT MODE — SSH Local Tunnel from Server"
  echo "============================================================"
  echo ""
  echo "  Relay port (server): $RELAY_PORT"
  echo "  Local port (client): $LOCAL_PORT"
  echo "  Server             : $SSH_SERVER"
  echo ""

  SSH_PID=""

  cleanup() {
    echo ""
    echo "▶ Shutting down tunnel..."
    [[ -n "$SSH_PID" ]] && kill "$SSH_PID" 2>/dev/null || true
    echo "✔ Stopped"
  }
  trap cleanup INT TERM EXIT

  echo "▶ Opening SSH local tunnel: localhost:$LOCAL_PORT → server:$RELAY_PORT"
  echo "  ssh -L $LOCAL_PORT:127.0.0.1:$RELAY_PORT $SSH_SERVER"
  echo ""

  # SSH local tunnel: forward local port to server's relay port
  ssh -N -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -L "127.0.0.1:${LOCAL_PORT}:127.0.0.1:${RELAY_PORT}" \
    "${SSH_ARGS[@]+"${SSH_ARGS[@]}"}" \
    "$SSH_SERVER" &
  SSH_PID=$!

  sleep 2
  kill -0 "$SSH_PID" 2>/dev/null || { echo "❌ SSH tunnel failed to start"; exit 1; }

  echo "✔ SSH local tunnel active (127.0.0.1:$LOCAL_PORT → server:$RELAY_PORT)"
  echo ""

  # Test connectivity
  _connected=false
  for _i in $(seq 1 5); do
    if (echo >/dev/tcp/127.0.0.1/"$LOCAL_PORT") 2>/dev/null; then
      _connected=true
      break
    fi
    sleep 1
  done

  if [[ "$_connected" == true ]]; then
    echo "✔ Proxy reachable at 127.0.0.1:$LOCAL_PORT"
  else
    echo "⚠ Could not connect to 127.0.0.1:$LOCAL_PORT"
    echo "  Make sure the HOST has started: ./run-remote-proxy.sh host --server $SSH_SERVER"
  fi

  echo ""
  echo "============================================================"
  echo "  Tunnel is live. Run claudebox with:"
  echo "============================================================"
  echo ""
  echo "  # Get the dummy token from the HOST operator, then:"
  echo "  ./claudebox.sh --proxy-only \\"
  echo "    --external-proxy 127.0.0.1:$LOCAL_PORT \\"
  echo "    --external-proxy-token \"<TOKEN_FROM_HOST>\""
  echo ""
  echo "  # Or with sandbox (requires --share-network):"
  echo "  ./claudebox.sh --share-network \\"
  echo "    --external-proxy 127.0.0.1:$LOCAL_PORT \\"
  echo "    --external-proxy-token \"<TOKEN_FROM_HOST>\" \\"
  echo "    --workdir ~/projects/myapp"
  echo ""
  echo "  Press Ctrl-C to stop the tunnel."
  echo "============================================================"

  # Wait for SSH tunnel (blocks until killed)
  wait "$SSH_PID" 2>/dev/null || true
fi
