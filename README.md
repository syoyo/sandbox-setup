# claudebox

Run [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or OpenAI Codex in a [bubblewrap](https://github.com/containers/bubblewrap) sandbox with a host-side credential proxy.

Real API credentials stay on the host. The sandbox only sees dummy tokens, which the host-side proxy replaces with real ones before forwarding to upstream APIs. The sandbox process never sees real credentials.

Supports multiple LLM services via presets (Anthropic, OpenAI, etc.) and a proxy-only mode for credential protection without full sandboxing.

## Architecture

```
Host                                              External APIs
┌──────────────────────────────────────┐         ┌──────────────────┐
│  credential-proxy.js                 │         │ api.anthropic.com│
│  ├─ Anthropic proxy (Unix socket)    │────────>│                  │
│  │  dummy token → real token         │         └──────────────────┘
│  ├─ OpenAI proxy (Unix socket)       │────────>┌──────────────────┐
│  │  (--proxy-service openai)         │         │ api.openai.com   │
│  │                                   │         └──────────────────┘
│  ├─ GitHub CONNECT proxy (Unix sock) │────────>┌──────────────────┐
│  └─ MCP reverse bridge (Unix sock)   │──┐      │ api.github.com   │
│                                      │  │      │ (CONNECT tunnel) │
│  github-mcp-server http :58082 ◄─────┘  │      └──────────────────┘
│  (--enable-github-mcp, recommended)  │  │
└──────────┬───────────────────────────┘  │
           │ bind-mount sockets (ro)      │
┌──────────▼───────────────────────────┐  │
│  bwrap sandbox (--unshare-net)       │  │
│                                      │  │
│  TCP bridges (loopback):             │  │   ← isolated net namespace
│    :58080 → Anthropic proxy socket   │  │
│    :58081 → GitHub CONNECT socket    │  │
│    :58082 → MCP bridge socket        │  │
│                                      │  │
│  claude                              │  │
│    ANTHROPIC_BASE_URL=:58080         │  │
│    MCP server "github" → :58082/mcp  │  │
│                                      │  │
│  /workspace (rw), /usr /etc (ro)     │  │
│  /home/sandbox (tmpfs)               │  │
└──────────────────────────────────────┘  │
                                          │
       github-mcp-server ────────────────>│ api.github.com
```

## Requirements

- Linux with [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
- Node.js on the host (for credential-proxy.js)
- Claude Code credentials configured on the host (`claude login`)
- `systemd-run` (for `--mem-limit` / `--cpu-limit`, included in systemd)

```bash
# Ubuntu / Debian
sudo apt install bubblewrap

# Fedora / RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

On Ubuntu 22.04+ (network isolation requires):
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Files

| File | Purpose |
|---|---|
| `claudebox.sh` | Sandbox launcher (bwrap + systemd-run) |
| `claudebox-supervisor.sh` | Multi-sandbox orchestrator for parallel tasks |
| `credential-proxy.js` | Host-side credential injection proxy + CONNECT proxy |
| `run-example.sh` | Example invocations |

## Quick Start

```bash
# Run Claude interactively in the current directory
./claudebox.sh

# Pass arguments to claude
./claudebox.sh -- -p "explain this codebase"

# Run Codex instead of Claude
./claudebox.sh --launcher codex --bind-binaries -- --help

# Run Codex with the OpenAI proxy bridge
OPENAI_API_KEY=sk-xxx ./claudebox.sh --launcher codex --bind-binaries

# Open a shell inside the sandbox (for debugging)
./claudebox.sh --shell

# Specific working directory
./claudebox.sh --workdir ~/projects/myapp

# Enable GitHub access (MCP server — recommended)
# Reads token from ~/.config/claudebox/gh-token automatically:
./claudebox.sh --enable-github-mcp
# Or pass token explicitly:
GH_TOKEN=ghp_xxx ./claudebox.sh --enable-github-mcp

# Enable GitHub access (CONNECT proxy — unrecommended)
GH_TOKEN=ghp_xxx ./claudebox.sh --enable-github

# With resource limits
./claudebox.sh --mem-limit 4G --cpu-limit 400

# Snapshot mode: review changes before applying (rollback-safe)
./claudebox.sh --snapshot --workdir ~/projects/myapp

# Read-only analysis with timeout
./claudebox.sh --read-only-workdir --timeout 30 --workdir ~/projects/myapp -- -p "review this code"

# Preview the sandbox command without running it
./claudebox.sh --dry-run --workdir ~/projects/myapp

# Multi-service: proxy OpenAI API alongside Anthropic
OPENAI_API_KEY=sk-xxx ./claudebox.sh --proxy-service openai

# Proxy-only mode: credential protection without sandbox isolation
./claudebox.sh --proxy-only

# Proxy-only with OpenAI + Anthropic
OPENAI_API_KEY=sk-xxx ./claudebox.sh --proxy-only --proxy-service openai

# Proxy-only with shell (for other LLM tools)
OPENAI_API_KEY=sk-xxx ./claudebox.sh --proxy-only --proxy-service openai --shell

# Full example
./claudebox.sh \
  --workdir ~/projects/myapp \
  --mount-claude-md \
  --enable-github-mcp \
  --mem-limit 8G \
  --cpu-limit 800 \
  -- --continue
```

## Options

```
--workdir DIR          Working directory to mount read-write (default: CWD).
                       Symlinks are resolved. Cannot be / or $HOME.
--shell                Launch bash instead of the selected CLI (useful for debugging).
--launcher NAME        Select the CLI to run inside the sandbox: claude (default) or codex.
--attach               Attach to a running sandbox from another terminal.
--mount-claude-md      Mount ~/.claude/CLAUDE.md into sandbox (read-only).
--share-claude-dir     Seed sandbox ~/.claude from the host (credentials replaced with dummies).
--sandbox-home DIR     Copy files from DIR into sandbox home at startup.
--enable-github-mcp    Enable GitHub access via MCP server (recommended). Requires GH_TOKEN
                       (env or ~/.config/claudebox/gh-token) and github-mcp-server on host.
--enable-github        Enable GitHub access via CONNECT proxy + gh CLI (unrecommended).
--gh-token-file FILE   Read GitHub PAT from FILE (default: ~/.config/claudebox/gh-token).
--mcp-port PORT        TCP port for MCP server bridge (default: 58082).
--disable-github       Explicitly disable GitHub access (default).
--share-network        Share host network namespace (weaker isolation; default: isolated).
--bind-binaries        Bind-mount node plus the selected CLI from host paths into the sandbox.
--dummy-credentials F  Use FILE as the dummy .credentials.json.
--mem-limit SIZE       Memory limit, e.g. 4G, 512M (uses cgroups via systemd-run).
--cpu-limit PERCENT    CPU limit as percentage: 100 = 1 core, 200 = 2 cores, etc.
--idle-timeout MINS    Warn when no Anthropic API request for MINS minutes (default: 15, 0=off).
--notify-webhook URL   POST JSON on events (Slack incoming webhook compatible).
--notify-command CMD   Run CMD on events (env: CLAUDEBOX_EVENT, CLAUDEBOX_MESSAGE).
--allowlist-url HOST   Allow HTTPS access to HOST via CONNECT proxy. Repeatable.
                       e.g. --allowlist-url registry.npmjs.org --allowlist-url pypi.org
--read-only-workdir    Mount workdir read-only (for analysis/review tasks).
--snapshot             Snapshot mode: copy workdir to staging, sandbox writes to copy.
                       On exit: review diff, then apply or rollback. Original untouched.
--timeout MINS         Wall-clock timeout in minutes. Kills sandbox after MINS minutes.
--token-limit N        Max tokens (input+output). Proxy rejects new requests after limit.
--audit-log FILE       Log API requests (method, path, tokens, timing) to JSONL file.
--output-dir DIR       Mount DIR as writable /output inside sandbox. Useful with
                       --read-only-workdir for analysis tasks that produce output.
--cache-home DIR       Persistent sandbox home directory across runs. Preserves
                       installed tools, configs, and cached data between sessions.
--seccomp              Enable seccomp filter blocking dangerous syscalls (ptrace, mount, etc.)
--profile NAME         Load options from ~/.config/claudebox/profiles/NAME.conf.
--image DIR            Use extracted container rootfs as base filesystem instead of host /usr.
--proxy-only           Proxy-only mode: no bwrap sandbox or cgroups. Runs the credential
                       proxy and launches the command directly. Provides credential
                       protection without full isolation (sync mode for project data).
--proxy-service NAME   Enable credential proxy for additional LLM services. Repeatable.
                       Available presets: anthropic (default, always on), openai.
                       e.g. --proxy-service openai
--openai-port PORT     TCP port for OpenAI proxy bridge (default: 58083).
--dry-run              Print the full bwrap command without executing it.
--anthropic-port PORT  TCP port for Anthropic proxy bridge (default: 58080).
--github-port PORT     TCP port for GitHub CONNECT proxy bridge (default: 58081).
--help                 Show help.
```

## Multi-Service Proxy

The credential proxy supports multiple LLM service presets. Each service gets its own
Unix socket and TCP bridge, with service-specific credential retrieval and path allowlists.

**Built-in presets:**

| Service | Upstream | Auth | Credential Source | Port |
|---------|----------|------|-------------------|------|
| `anthropic` | api.anthropic.com | OAuth / x-api-key | CLAUDE_CREDENTIALS_FILE, keychain, ~/.claude/.credentials.json | 58080 |
| `openai` | api.openai.com | Bearer token | OPENAI_API_KEY, OPENAI_CREDENTIALS_FILE, ~/.config/claudebox/openai-key, ~/.codex/auth.json | 58083 |

Preferred approach: use a project-scoped `OPENAI_API_KEY` (or `~/.config/claudebox/openai-key`) for OpenAI/Codex runs.
This is the most stable setup for the Responses API and avoids ChatGPT account scope mismatches.

Temporary compatibility: if no API key is configured, the OpenAI proxy will also read host Codex auth from
`~/.codex/auth.json` and can refresh it. This is useful for short-term local use, but it may still fail if the
current ChatGPT/Codex credential does not have `api.responses.write`.

```bash
# Enable OpenAI proxy alongside default Anthropic
OPENAI_API_KEY=sk-xxx ./claudebox.sh --proxy-service openai

# Inside sandbox, tools see:
#   ANTHROPIC_BASE_URL=http://127.0.0.1:58080
#   OPENAI_BASE_URL=http://127.0.0.1:58083
#   OPENAI_API_KEY=<dummy-token>  (replaced by proxy with real key)
```

## Proxy-Only Mode

`--proxy-only` provides credential protection without namespace/cgroup isolation.
The credential proxy runs on the host and the command is launched directly with
environment variables pointing to the proxy. No bwrap or systemd-run is used.

This is useful for:
- Machines where bwrap is unavailable
- Running other LLM tools (not just Claude Code) with credential protection
- Development workflows where full sandboxing is unnecessary

```bash
# Proxy-only with shell — run any LLM tool with proxied credentials
OPENAI_API_KEY=sk-xxx ./claudebox.sh --proxy-only --proxy-service openai --shell

# Temporary fallback: if OPENAI_API_KEY is unset, claudebox can reuse host
# Codex ChatGPT auth from ~/.codex/auth.json when available.

# Inside the shell:
#   ANTHROPIC_BASE_URL=http://127.0.0.1:58080
#   OPENAI_BASE_URL=http://127.0.0.1:58083
#   OPENAI_API_KEY=<dummy>  (real key never visible to child process)
```

Project data is accessed directly (sync mode): the working directory is used as-is,
and session data is synced back on exit when `--share-sessions` is used. `--snapshot`
mode is also supported for proxy-only (creates a staging copy, merges back on exit).

## Network Isolation

**Default: fully isolated** (`--unshare-net`). The sandbox has no external network access.
All API communication goes through Unix socket bridges:

```
sandbox 127.0.0.1:58080 → in-sandbox bridge → Unix socket (bind-mounted) → host proxy → api.anthropic.com
sandbox 127.0.0.1:58081 → in-sandbox bridge → Unix socket (bind-mounted) → host CONNECT proxy → api.github.com
```

The GitHub bridge is only started when `--enable-github` is set. Without it, `HTTPS_PROXY`
is not set and the GitHub CONNECT socket is mounted but not bridged — no GitHub access.

**`--share-network`**: Shares the host network namespace. Faster startup (no in-sandbox
bridges needed), but weaker isolation: any compiled binary or raw-socket code inside the
sandbox can bypass the proxy and reach the internet directly. Use only for convenience
during development.

## GitHub Access (MCP Server — Recommended)

The recommended way to access GitHub from the sandbox is via the
[GitHub MCP Server](https://github.com/github/github-mcp-server). This runs on the
host in HTTP mode and is bridged into the sandbox via a reverse Unix socket bridge.
Claude Code auto-discovers it through a generated MCP config.

```bash
# Install github-mcp-server (Go binary)
go install github.com/github/github-mcp-server@latest

# Store your GitHub PAT (once)
mkdir -p ~/.config/claudebox && chmod 700 ~/.config/claudebox
echo "ghp_xxx" > ~/.config/claudebox/gh-token
chmod 600 ~/.config/claudebox/gh-token

# Run with MCP server (token loaded automatically)
./claudebox.sh --enable-github-mcp --workdir ~/projects/myapp
```

**Architecture**: `github-mcp-server http --port 58082` runs on the host. The credential
proxy creates a reverse bridge (Unix socket → TCP 58082). The socket is bind-mounted
into the sandbox. An in-sandbox TCP bridge exposes it at `127.0.0.1:58082`. Claude Code
connects via MCP streamable-http transport.

**Advantages over `--enable-github`**:
- No `GH_TOKEN` exposed inside the sandbox
- No `gh` CLI or CONNECT proxy needed
- Claude Code uses GitHub tools natively via MCP protocol
- Token stays on the host (never enters the sandbox)

## GitHub Access (CONNECT Proxy — Unrecommended)

> **Note**: Prefer `--enable-github-mcp` above. This method exposes `GH_TOKEN` inside
> the sandbox and requires the `gh` CLI.

GitHub access uses an HTTPS CONNECT tunnel proxy. The sandbox's `HTTPS_PROXY` points
to the in-sandbox bridge, which tunnels through to the host-side CONNECT proxy, which
connects to `api.github.com:443`. The TLS session is end-to-end between `gh` and GitHub.

The CONNECT proxy enforces an allowlist: only `api.github.com:443` is permitted. All
other CONNECT targets are rejected with 403.

```bash
# Token loaded from ~/.config/claudebox/gh-token, or pass explicitly:
GH_TOKEN=ghp_xxx ./claudebox.sh --enable-github --shell --workdir work

# Inside sandbox:
gh repo view owner/repo
```

**Note**: `GH_TOKEN` is passed directly into the sandbox environment because the CONNECT
proxy tunnels encrypted TLS traffic and cannot inject authentication headers. The token
should be scoped with minimal permissions (read-only recommended).

## Session Sharing

By default, each sandbox starts with a fresh `~/.claude` directory and no conversation
history. Use `--share-sessions` to persist session data so you can resume conversations
from the host or another sandbox.

```bash
# Start a sandbox with session sharing
./claudebox.sh --share-sessions --workdir ~/projects/myapp

# Inside sandbox: have a conversation, then exit.
# Later, resume from the host:
claude --continue

# Or resume in a new sandbox:
./claudebox.sh --share-sessions --workdir ~/projects/myapp -- --continue
```

**What is shared** (read-write):
- `~/.claude/projects/<project>/` — conversation JSONL files, subagent data, tool results
- `~/.claude/history.jsonl` — session history for `--continue` and `--resume`

**What is shared** (read-only):
- `~/.claude/settings.json` — user settings for consistent behavior

**What is NOT shared**: credentials (always dummy), debug logs, cache, stats.

**Security note**: Session JSONL files written by the sandbox are replayed when resumed.
If you resume a shared session **on the host without a sandbox**, any tool calls in the
conversation history execute on the bare host. Always resume shared sessions inside a
sandbox, or review the conversation history before resuming on the host.

## Resource Limits

CPU and memory limits are enforced via cgroups using `systemd-run --user --scope`.

```bash
# 4 GB memory, 2 CPU cores
./claudebox.sh --mem-limit 4G --cpu-limit 200

# 8 GB memory, no CPU limit
./claudebox.sh --mem-limit 8G

# 400% CPU (4 cores), no memory limit
./claudebox.sh --cpu-limit 400
```

- `--mem-limit`: Sets `MemoryMax` and `MemorySwapMax=0` (no swap escape).
- `--cpu-limit`: Sets `CPUQuota` (100 = 1 core, 200 = 2 cores, etc.).

### OOM Behavior

When the sandbox exceeds its memory limit, the Linux cgroup v2 OOM killer selects and
kills the process using the most memory within the cgroup. Typically this means:

- **Child processes** (python, node, compiled programs) are killed first.
- **The shell** (bash) usually survives because it uses little memory.
- The sandbox continues running — the killed process exits with an error.

If the entire cgroup scope is killed (e.g., every process exceeds the limit simultaneously),
`claudebox.sh` detects the OOM condition by checking:
1. Exit code 137 (SIGKILL) or 143 (SIGTERM from systemd)
2. `journalctl --user` for OOM events in the scope
3. `dmesg` for kernel OOM killer messages

and prints:
```
⚠ SANDBOX OOM KILLED — memory limit (4G) exceeded (exit code: 137)
  Increase with --mem-limit or reduce sandbox workload.
```

**Important**: The OOM killer targets individual processes, not the entire sandbox.
A single process exceeding the limit will be killed, but the sandbox shell remains
operational. This is standard Linux cgroup v2 behavior.

## Attaching to a Running Sandbox

Each sandbox starts a `socat` listener on a Unix socket that provides shell access.
This allows you to inspect, debug, or interact with a running sandbox from another terminal.

```bash
# Terminal 1: start sandbox
./claudebox.sh --workdir ~/projects/myapp

# Terminal 2: attach to it
./claudebox.sh --attach
```

`--attach` finds the most recent sandbox's attach socket and connects to it.
You can also connect directly:

```bash
socat -,raw,echo=0 UNIX-CONNECT:/run/user/1000/claudebox-attach-PID/shell.sock
```

The attach socket is in `$XDG_RUNTIME_DIR/claudebox-attach-PID/` (mode 700, user-private).
Multiple attach sessions can connect simultaneously. The socket is cleaned up when the
sandbox exits.

**Requires**: `socat` installed in the sandbox (usually available via the system `/usr/bin`).

## Idle Timeout

The host-side proxy monitors Anthropic API activity. If no request is received for a
configurable period (default: 15 minutes), a warning is printed to the host's stderr:

```
[idle] ⚠ No Anthropic API request for 15 minutes (threshold: 15m)
[idle]   The sandbox process may be stuck or idle.
```

This helps detect stuck processes or forgotten sandboxes.

```bash
# Custom timeout (5 minutes)
./claudebox.sh --idle-timeout 5

# Disable idle timeout
./claudebox.sh --idle-timeout 0
```

The warning is printed once per idle period. It resets when the next API request arrives.

## Notifications

Receive notifications on sandbox events via a webhook URL or a custom command.

**Events**: `sandbox_start`, `sandbox_exit`, `oom_kill`, `idle_timeout`

### Slack Incoming Webhook (simplest)

```bash
./claudebox.sh \
  --notify-webhook https://hooks.slack.com/services/T.../B.../xxx \
  --workdir ~/projects/myapp
```

`--notify-webhook` POSTs Slack-compatible JSON (`text` + `blocks`) on every event.

### Custom Command

```bash
./claudebox.sh \
  --notify-command './examples/notify-slack.sh' \
  --workdir ~/projects/myapp
```

The command receives event details via environment variables:

| Variable | Description |
|---|---|
| `CLAUDEBOX_EVENT` | Event type (`sandbox_start`, `sandbox_exit`, `oom_kill`, `idle_timeout`) |
| `CLAUDEBOX_MESSAGE` | Human-readable message (Slack mrkdwn format) |
| `CLAUDEBOX_WORKDIR` | Sandbox workdir path |
| `CLAUDEBOX_PID` | Sandbox launcher PID |

### Example: Desktop notification

```bash
./claudebox.sh \
  --notify-command 'notify-send "claudebox [$CLAUDEBOX_EVENT]" "$CLAUDEBOX_MESSAGE"'
```

### Example: Log to file

```bash
./claudebox.sh \
  --notify-command 'echo "$(date -Iseconds) $CLAUDEBOX_EVENT: $CLAUDEBOX_MESSAGE" >> /tmp/claudebox.log'
```

### Both at once

```bash
./claudebox.sh \
  --notify-webhook https://hooks.slack.com/services/T.../B.../xxx \
  --notify-command 'notify-send "claudebox" "$CLAUDEBOX_MESSAGE"'
```

See `examples/notify-slack.sh` for a full Slack notification script with color-coded
attachments per event type.

## Snapshot Mode

Run the sandbox with `--snapshot` to protect your workdir from unwanted changes.
The original workdir is copied to a staging directory before launch; the sandbox
writes to the staging copy while the original remains untouched.

```bash
./claudebox.sh --snapshot --workdir ~/projects/myapp
```

On exit, you see a summary of changes and choose what to do:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SNAPSHOT CHANGES (3 differences)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Only in staging: new-file.ts
  Files src/index.ts and staging/src/index.ts differ
  Only in original: deleted-file.ts

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Apply changes to workdir? [y]es / [n]o (rollback) / [d]iff:
```

- **y**: Apply all changes from staging to the original workdir (`rsync --delete`)
- **n**: Rollback — discard staging, original untouched
- **d**: View full `diff -ru` before deciding

**Performance**: Snapshot creation copies the entire workdir (`cp -a`), so it's
best for repos under ~1 GB. See `doc/filesystem.md` for design notes and
alternative approaches considered (overlayfs, btrfs, ZFS).

## URL Allowlist

By default, the sandbox can only reach Anthropic's API. Use `--allowlist-url` to allow
additional HTTPS hosts through the CONNECT proxy:

```bash
# Allow npm registry and PyPI
./claudebox.sh --allowlist-url registry.npmjs.org --allowlist-url pypi.org --workdir work

# Combine with GitHub MCP
./claudebox.sh --enable-github-mcp --allowlist-url registry.npmjs.org --workdir work
```

Each allowed host is added to the CONNECT proxy's hostname allowlist. Only port 443
(HTTPS) is permitted. `HTTPS_PROXY` is automatically set in the sandbox.

## Read-Only Workdir

Mount the working directory read-only for analysis or code review tasks where
the sandbox should not modify files:

```bash
./claudebox.sh --read-only-workdir --workdir ~/projects/myapp -- -p "review this codebase"
```

## Wall-Clock Timeout

Kill the sandbox after a fixed duration to prevent runaway sessions:

```bash
# Kill after 60 minutes
./claudebox.sh --timeout 60 --workdir ~/projects/myapp

# Combine with notifications
./claudebox.sh --timeout 30 --notify-webhook https://hooks.slack.com/... --workdir work
```

When the timeout fires, the sandbox receives `SIGTERM` followed by `SIGKILL` after
30 seconds. A `wall_timeout` notification is sent if webhooks/commands are configured.

## Dry Run

Print the full `bwrap` command and init script without launching the sandbox:

```bash
./claudebox.sh --dry-run --workdir work
```

Useful for debugging sandbox configuration or generating commands for automation.

## Token Budget

Track and limit API token usage to prevent runaway costs:

```bash
# Kill after 500K tokens
./claudebox.sh --token-limit 500000 --workdir ~/projects/myapp

# With notifications
./claudebox.sh --token-limit 1000000 --notify-webhook https://hooks.slack.com/... --workdir work
```

The proxy parses Anthropic API response bodies to extract `usage.input_tokens` and
`usage.output_tokens`. When the cumulative total exceeds `--token-limit`, new requests
are rejected with HTTP 429. A `token_limit` notification is sent. A session summary
is printed when the proxy exits:

```
[tokens] Session total: 45,230 tokens (12,100 in + 33,130 out) across 8 requests
```

## Audit Log

Log all API requests to a JSONL file for post-session review:

```bash
./claudebox.sh --audit-log ~/claudebox-audit.jsonl --workdir ~/projects/myapp
```

Each line is a JSON object:

```json
{"ts":"2025-01-15T10:30:00.000Z","event":"api_request","method":"POST","path":"/v1/messages","status":200,"duration_ms":1234,"input_tokens":500,"output_tokens":1200,"cumulative_tokens":1700}
```

Events: `proxy_start`, `api_request`, `api_error`, `token_limit_exceeded`, `proxy_stop`.

## Diff-on-Exit

When the workdir is a git repository, a change summary is automatically shown after
the sandbox exits:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WORKDIR CHANGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   src/index.ts | 12 ++++++------
   1 file changed, 6 insertions(+), 6 deletions(-)

  Untracked files (2):
    src/new-feature.ts
    tests/new-feature.test.ts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Skipped for `--snapshot` (which has its own diff) and `--read-only-workdir`.

## Filesystem Quarantine

After sandbox exit, files are scanned for suspicious patterns:

- Shell scripts containing network commands (`curl`, `wget`, `nc`, `socat`)
- Dotfiles (`.bashrc`, `.profile`, `.zshrc`) — potential persistence
- Long base64-encoded strings — potential encoded secrets

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  QUARANTINE SCAN (2 findings)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⚠ Script with network commands: deploy.sh
  ⚠ Possible encoded secret: config/auth.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The scan runs automatically. A `quarantine_warning` notification is sent if findings
are detected. This is informational — files are not blocked or deleted.

## Output Directory

Use `--output-dir` with `--read-only-workdir` for analysis tasks that produce output
without modifying the original codebase:

```bash
mkdir -p ~/review-output
./claudebox.sh \
  --read-only-workdir \
  --output-dir ~/review-output \
  --workdir ~/projects/myapp \
  -- -p "analyze this codebase and write a report to /output/report.md"
```

Inside the sandbox, `/output` is writable while `/workspace` is read-only.
The output directory persists on the host after the sandbox exits.

## Cache Home

Use `--cache-home` to preserve the sandbox home directory across runs. This avoids
re-installing tools, re-downloading packages, or re-configuring settings each time:

```bash
# First run: tools are installed, configs written
./claudebox.sh --cache-home ~/.cache/claudebox/home --workdir ~/projects/myapp

# Second run: instant startup with all tools and configs preserved
./claudebox.sh --cache-home ~/.cache/claudebox/home --workdir ~/projects/myapp
```

The cache directory is bind-mounted as the sandbox home (`/home/sandbox`) instead
of using a fresh tmpfs. Contents persist between sandbox sessions.

## Multiple Sandbox Orchestration

`claudebox-supervisor.sh` launches multiple sandboxes in parallel, each running a
separate task. Useful for batch code reviews, parallel feature work, or running
multiple analyses concurrently.

```bash
# Parallel code reviews (shared read-only workdir)
./claudebox-supervisor.sh \
  --workdir ~/projects/myapp \
  --shared-workdir \
  --task "review src/auth.ts for security issues" \
  --task "review src/api.ts for error handling" \
  --task "review src/db.ts for SQL injection"

# Tasks from a file with token budget
./claudebox-supervisor.sh \
  --workdir ~/projects/myapp \
  --task-file review-tasks.txt \
  --token-limit 500000 \
  --timeout 30

# Parallel feature work (each task gets its own workdir copy)
./claudebox-supervisor.sh \
  --workdir ~/projects/myapp \
  --output-dir ~/review-output \
  --max-parallel 3 \
  --task "add input validation to the login form" \
  --task "add rate limiting to the API endpoints"
```

**Options**:
- `--task "PROMPT"`: Add a task (repeatable)
- `--task-file FILE`: Read tasks from file (one per line, `#` comments)
- `--shared-workdir`: All tasks share the same workdir (read-only)
- `--max-parallel N`: Limit concurrent sandboxes
- `--token-limit N`: Per-sandbox token budget
- `--timeout MINS`: Per-sandbox wall-clock timeout
- `--output-dir DIR`: Base directory for per-task output

On completion, a summary shows each task's status, token usage, and output location.

## Seccomp Filter

Use `--seccomp` to enable a syscall filter that blocks dangerous operations:

```bash
./claudebox.sh --seccomp --workdir ~/projects/myapp
```

Blocked syscalls: `ptrace`, `mount`, `umount2`, `reboot`, `kexec_load`, `init_module`,
`finit_module`, `delete_module`, `pivot_root`, `swapon`, `swapoff`, `acct`,
`settimeofday`, `clock_settime`, `adjtimex`.

These syscalls return `EPERM` if called. Normal development operations (file I/O,
networking, process management) are unaffected. Requires `python3` on the host to
generate the BPF filter. Supports x86_64 and aarch64.

## Sandbox Profiles

Profiles let you save commonly-used option combinations in a config file:

```bash
# Load a named profile
./claudebox.sh --profile review --workdir ~/projects/myapp

# Profile with CLI overrides (CLI takes precedence)
./claudebox.sh --profile development --workdir ~/projects/myapp --timeout 120
```

Profiles are stored at `~/.config/claudebox/profiles/NAME.conf` — one option per line,
`#` comments allowed. Example profiles are in `examples/profiles/`.

**Note:** Options are split on whitespace; quoted values (e.g., `--workdir "/path with spaces"`)
are not supported. Put one option per line and avoid spaces in paths.

Example `review.conf`:
```
# Read-only code review with security hardening
--read-only-workdir
--seccomp
--idle-timeout 10
--mem-limit 4G
```

## Container Image Support

Use `--image DIR` to run the sandbox with an extracted container rootfs instead of the
host's system directories:

```bash
# Extract a Docker image
mkdir -p /tmp/ubuntu-rootfs
docker export $(docker create ubuntu:24.04) | tar -C /tmp/ubuntu-rootfs -xf -

# Run sandbox with that rootfs
./claudebox.sh --image /tmp/ubuntu-rootfs --workdir ~/projects/myapp
```

The image directory must contain at least `/usr`. The sandbox will use the image's
`/usr`, `/bin`, `/lib`, `/sbin`, and `/etc` (with host network config overlaid).
The image's `/opt` is also mounted if present.

This is useful for:
- Running Claude Code with different system libraries or tool versions
- Testing against specific OS environments
- Reproducible sandbox environments across machines

## Sandbox Security Properties

| Property | Detail |
|---|---|
| **Network** | Fully isolated namespace by default; loopback only |
| **Filesystem** | Only `--workdir` is read-write; everything else read-only or tmpfs |
| **Home directory** | Real `$HOME` not mounted; fake home at `/home/sandbox` (tmpfs) |
| **Anthropic credentials** | Per-session random dummy token; real token injected by host proxy |
| **GitHub token (MCP)** | Token stays on host; MCP server runs on host, only bridged socket enters sandbox |
| **Proxy socket** | Bind-mounted read-only; sandbox can connect but not modify |
| **Environment** | `--clearenv`; only explicit allowlist set |
| **/etc** | Only ~12 specific files mounted (ld.so, SSL certs, DNS, passwd/group) |
| **/sys** | Empty tmpfs (no hardware fingerprinting) |
| **Namespaces** | user, ipc, pid, uts, cgroup, net (all unshared) |
| **Seccomp** | Optional (`--seccomp`): blocks ptrace, mount, reboot, kexec, and other dangerous syscalls |
| **Path allowlist** | Proxy only forwards `/v1/(messages\|complete\|models\|count_tokens)` |
| **URL normalization** | Path traversal (`../`) resolved before allowlist check |
| **Body size limit** | 10 MB max request body to prevent host OOM via proxy |
| **Socket location** | `$XDG_RUNTIME_DIR` (user-private) instead of `/tmp` |
| **Init script** | Fully static single-quoted string; no shell interpolation of user values |

## Credential Sources (Anthropic)

The host-side proxy checks in order:

1. `CLAUDE_CREDENTIALS_FILE` environment variable (path to JSON file)
2. macOS Keychain (`security find-generic-password -s "Claude Code-credentials"`)
3. `~/.claude/.credentials.json`
4. `~/.config/claude/auth.json`

## Running Multiple Sandboxes

Each invocation uses PID-scoped socket paths and you can specify different bridge ports:

```bash
./claudebox.sh --workdir ~/proj-a --anthropic-port 58080 --github-port 58081 &
./claudebox.sh --workdir ~/proj-b --anthropic-port 58082 --github-port 58083 &
```

## Troubleshooting

**`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`**

Network isolation requires on Ubuntu 22.04+:
```bash
# temporary
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# permanent
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system
```

**`bwrap: setting up uid map: Permission denied`**

User namespaces are disabled:
```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

**`❌ Proxy socket did not appear`**

Check that Node.js can read your credentials:
```bash
node -e "const fs=require('fs'),os=require('os'),p=require('path');
console.log(fs.readFileSync(p.join(os.homedir(),'.claude','.credentials.json'),'utf8').slice(0,80))"
```

**`❌ systemd-run required for --mem-limit/--cpu-limit`**

Install systemd (usually already present on modern Linux):
```bash
sudo apt install systemd  # Debian/Ubuntu
```

**Claude prompts for login inside sandbox**

The dummy credentials file wasn't generated correctly. Run with `bash -x ./claudebox.sh` to trace.
