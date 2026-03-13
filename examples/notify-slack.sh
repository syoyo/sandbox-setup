#!/usr/bin/env bash
# notify-slack.sh — Example notification script for claudebox.
#
# Usage with claudebox.sh:
#   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx \
#     ./claudebox.sh --notify-command ./examples/notify-slack.sh --workdir ~/project
#
# Or use --notify-webhook directly (no script needed):
#   ./claudebox.sh --notify-webhook https://hooks.slack.com/services/T.../B.../xxx
#
# Environment variables set by claudebox:
#   CLAUDEBOX_EVENT    — event type (sandbox_start, sandbox_exit, oom_kill, idle_timeout)
#   CLAUDEBOX_MESSAGE  — human-readable message (Slack mrkdwn format)
#   CLAUDEBOX_WORKDIR  — sandbox workdir path (set by claudebox.sh, not proxy)
#   CLAUDEBOX_PID      — sandbox PID (set by claudebox.sh, not proxy)

set -euo pipefail

: "${SLACK_WEBHOOK_URL:?Set SLACK_WEBHOOK_URL to your Slack incoming webhook URL}"

# Map events to emoji/color
case "${CLAUDEBOX_EVENT:-unknown}" in
  sandbox_start) color="#36a64f" ;;  # green
  sandbox_exit)  color="#439FE0" ;;  # blue
  oom_kill)      color="#FF0000" ;;  # red
  idle_timeout)  color="#FFA500" ;;  # orange
  *)             color="#808080" ;;  # grey
esac

# MED-8: use jq for safe JSON construction to prevent injection via
# CLAUDEBOX_MESSAGE or other env vars containing quotes/special chars.
if ! command -v jq >/dev/null 2>&1; then
  echo "notify-slack.sh: jq is required but not installed" >&2
  exit 1
fi

payload=$(jq -n \
  --arg color "$color" \
  --arg text "${CLAUDEBOX_MESSAGE:-No message}" \
  --arg footer "claudebox | PID ${CLAUDEBOX_PID:-?} | $(date -Iseconds)" \
  '{attachments: [{color: $color, text: $text, footer: $footer, fallback: $text}]}')

curl -s -X POST -H 'Content-Type: application/json' \
  -d "$payload" "$SLACK_WEBHOOK_URL" >/dev/null
