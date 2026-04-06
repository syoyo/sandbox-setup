#!/usr/bin/env bash
# ============================================================================
# run-credential-proxy.sh — Start only the Anthropic credential proxy (no sandbox).
#
# This runs credential-proxy.js standalone so you can point any LLM client
# at it from the same host. The proxy replaces a dummy token with real
# credentials before forwarding to api.anthropic.com.
#
# After the proxy starts it prints hostname, port, and the dummy token.
# Copy-paste the export lines into your client shell.
#
# Usage:
#   ./run-credential-proxy.sh
#   ./run-credential-proxy.sh --anthropic-tcp-port 9080
#
# Client configuration (copy from proxy output):
#   export ANTHROPIC_BASE_URL=http://<hostname>:<port>
#   export ANTHROPIC_API_KEY=<dummy-token>
#   claude
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate per-session random dummy token
SESSION_DUMMY_TOKEN=$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 64)
SESSION_DUMMY_TOKEN="sk-ant-oat01-${SESSION_DUMMY_TOKEN}"
export SESSION_DUMMY_TOKEN

# Default socket path
_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
SOCKET_ANTHROPIC="${_RUNTIME_DIR}/claude-proxy-anthropic-$$.sock"

echo "▶ Starting credential proxy (Anthropic only)"
echo ""

exec node "$SCRIPT_DIR/credential-proxy.js" \
  --anthropic-socket "$SOCKET_ANTHROPIC" \
  --anthropic-tcp-port "${ANTHROPIC_TCP_PORT:-58080}" \
  "$@"
