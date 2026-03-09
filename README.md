# claudebox

Run Claude Code in a [bubblewrap](https://github.com/containers/bubblewrap) sandbox with a host-side credential proxy.

Real API credentials stay on the host machine and are injected into outgoing requests via a Unix domain socket. The sandbox process never sees them.

## Architecture

```
Host                                          Anthropic API
┌──────────────────────────────────┐         ┌─────────────┐
│  credential-proxy.js             │         │             │
│  (Unix socket: /tmp/proxy.sock)  │────────▶│  api.anthropic.com
│  reads ~/.claude/.credentials    │         │             │
└──────────────┬───────────────────┘         └─────────────┘
               │ Unix socket (bind-mounted, read-only)
               │
┌──────────────▼───────────────────┐
│  bwrap sandbox                   │
│  ┌────────────────────────────┐  │
│  │ TCP bridge (loopback only) │  │  ← isolated net namespace,
│  │ 127.0.0.1:58080            │  │    no external network
│  └────────────┬───────────────┘  │
│               │                  │
│  ┌────────────▼───────────────┐  │
│  │  claude                    │  │
│  │  ANTHROPIC_BASE_URL=       │  │
│  │    http://127.0.0.1:58080  │  │
│  └────────────────────────────┘  │
│                                  │
│  Filesystem:                     │
│    /workspace  ← rw (workdir)    │
│    /usr, /etc  ← ro              │
│    /home/sandbox ← tmpfs         │
│    (real home: not mounted)      │
└──────────────────────────────────┘
```

## Requirements

- Linux with [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
- Node.js on the host
- Claude Code credentials configured on the host (`claude login`)

```bash
# Ubuntu / Debian
sudo apt install bubblewrap

# Fedora / RHEL
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

## Files

| File | Purpose |
|---|---|
| `claudebox.sh` | Sandbox launcher (bwrap) |
| `credential-proxy.js` | Host-side credential injection proxy |

## Quick Start

```bash
# Run Claude interactively in the current directory
./claudebox.sh

# Pass arguments to claude
./claudebox.sh -- -p "explain this codebase"
./claudebox.sh -- --continue

# Mount your personal CLAUDE.md (read-only)
./claudebox.sh --mount-claude-md

# Specific working directory
./claudebox.sh --workdir ~/projects/myapp

# Enable GitHub credential injection as well
./claudebox.sh --enable-github

# Full example
./claudebox.sh --workdir ~/projects/myapp --mount-claude-md --enable-github -- --continue
```

## Options

### claudebox.sh

```
--mount-claude-md      Mount ~/.claude/CLAUDE.md into the sandbox (read-only)
--socket PATH          Host Unix socket path (default: /tmp/claude-proxy-PID.sock)
--bridge-port PORT     In-sandbox loopback port for the TCP bridge (default: 58080)
--workdir DIR          Working directory to mount read-write (default: CWD)
--enable-github        Enable GitHub credential injection in proxy
--disable-anthropic    Disable Anthropic credential injection in proxy
```

### credential-proxy.js (standalone)

```
--socket PATH          Unix socket path (default: /tmp/claude-proxy.sock)
--tcp-bridge-port PORT Also open a TCP listener bridging to the socket
--bridge-only          TCP→Unix bridge only; for use inside the sandbox
--enable-anthropic     Enable Anthropic injection (default: on)
--disable-anthropic    Disable Anthropic injection
--enable-github        Enable GitHub injection (default: off)
--disable-github       Disable GitHub injection
--verbose              Log all proxied requests
```

## Sandbox Security Properties

| Property | Detail |
|---|---|
| **Network** | Fully isolated namespace; loopback only (`127.0.0.1` for bridge) |
| **Filesystem writes** | Only `--workdir` is read-write; everything else is read-only or tmpfs |
| **Home directory** | Real `$HOME` is not mounted; fake home at `/home/sandbox` (tmpfs) |
| **Credentials** | Only dummy tokens inside; real tokens injected by host proxy per-request |
| **Proxy socket** | Bind-mounted read-only; sandbox can connect but not modify it |
| **Environment** | `--clearenv`; only an explicit allow-list is set |

## Credential Sources

### Claude Code (Anthropic)

Checked in order:

1. `CLAUDE_CREDENTIALS_FILE` environment variable (path to JSON file)
2. macOS Keychain (`security find-generic-password -s "Claude Code-credentials"`)
3. `~/.claude/.credentials.json`
4. `~/.config/claude/auth.json`

### GitHub (opt-in via `--enable-github`)

Checked in order:

1. `GH_TOKEN` / `GITHUB_TOKEN` / `GH_ENTERPRISE_TOKEN` environment variable
2. `~/.config/gh/hosts.yml` (gh CLI config)
3. `gh auth token` (gh CLI)

GitHub requests are routed to `api.github.com` when the incoming request has:
- Header `x-proxy-target: github`, or
- URL path starting with `/github/`, `/repos/`, or `/user`

## Network Modes

### Default (no `--no-network`)

The sandbox shares the host network namespace. The credential proxy starts a TCP bridge
on the **host** loopback (`127.0.0.1:58080`) which is directly reachable from inside the
sandbox. No in-sandbox bridge process is needed. Works on all systems with no kernel
configuration changes.

```
sandbox (shared net ns) → 127.0.0.1:58080 → host TCP bridge → Unix socket → proxy
```

### `--no-network`

bwrap creates an isolated network namespace (external traffic impossible; loopback only).
An in-sandbox TCP bridge is started to connect Claude to the mounted Unix socket.

```
sandbox loopback:58080 → in-sandbox bridge → Unix socket → host proxy → api.anthropic.com
```

Requires on Ubuntu 22.04+:
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Running Multiple Sandboxes in Parallel

Each invocation uses a unique socket path (`/tmp/claude-proxy-PID.sock`) and you can specify different bridge ports:

```bash
./claudebox.sh --workdir ~/proj-a --bridge-port 58080 &
./claudebox.sh --workdir ~/proj-b --bridge-port 58081 &
```

## Troubleshooting

**`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`**
This happens with `--no-network` on Ubuntu 22.04+ where AppArmor blocks unprivileged
user namespaces from configuring network interfaces. Without `--no-network` (the default)
this error does not occur — the sandbox shares the host network namespace and the proxy
is bridged on the host-side loopback instead.

To enable `--no-network`, relax the AppArmor restriction:
```bash
# temporary (until reboot)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# permanent
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl --system
```

**`bwrap: setting up uid map: Permission denied`**
User namespaces are fully disabled on this kernel. Check:
```bash
sysctl kernel.unprivileged_userns_clone   # should be 1
# If 0:
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

**`❌ Proxy socket did not appear`**
Check that Node.js can read your credentials:
```bash
node -e "const fs=require('fs'),os=require('os'),p=require('path');
console.log(fs.readFileSync(p.join(os.homedir(),'.claude','.credentials.json'),'utf8').slice(0,80))"
```

**Claude prompts for login inside sandbox**
The dummy credentials file wasn't generated correctly. Run with `bash -x ./claudebox.sh` to trace the issue.

**`Neither node nor socat found`**
The bridge needs either `node` (with `credential-proxy.js` in the workdir) or `socat` accessible inside the sandbox. Since `node` is bind-mounted to `/usr/local/bin/node` in the sandbox and `credential-proxy.js` is in `/workspace`, this should work automatically as long as you run `claudebox.sh` from the directory containing `credential-proxy.js`, or copy `credential-proxy.js` into your workdir.
