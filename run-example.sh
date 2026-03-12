#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./run-example.sh start
  ./run-example.sh list
  ./run-example.sh attach
  ./run-example.sh attach ID
  ./run-example.sh info ID

Commands:
  start   Launch the example sandbox shell with session sharing and GitHub MCP.
  list    Show current sandboxes with workspace and status info.
  attach  Reconnect to a running sandbox shell via claudebox --attach.
  info    Show detailed info for one running or stale sandbox.
EOF
}

case "${1:-start}" in
  start)
    exec ./claudebox.sh --bind-binaries --shell --share-claude-dir --share-sessions --enable-github-mcp --workdir work
    ;;
  list)
    exec ./claudebox.sh --list
    ;;
  attach)
    if [[ $# -gt 1 ]]; then
      exec ./claudebox.sh --attach "$2"
    fi
    exec ./claudebox.sh --attach
    ;;
  info)
    [[ $# -ge 2 ]] || { usage >&2; exit 1; }
    exec ./claudebox.sh --info "$2"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
