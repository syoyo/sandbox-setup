#!/usr/bin/env node
/**
 * credential-proxy.js
 *
 * Credential injection proxy for sandboxed Claude Code.
 * Listens on a Unix domain socket (host side), injects real credentials
 * before forwarding requests to Anthropic or GitHub APIs.
 *
 * Supports:
 *   - Claude Code OAuth tokens (accessToken from ~/.claude/.credentials.json or macOS Keychain)
 *   - GitHub tokens (from GH_TOKEN env, gh CLI config, or ~/.config/gh/hosts.yml)
 *
 * Normal usage: run claudebox.sh, which starts this proxy automatically.
 *   ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]
 *
 * Manual host usage (advanced):
 *   node credential-proxy.js [--socket /tmp/claude-proxy.sock] [--tcp-bridge-port 58080]
 *   node credential-proxy.js --enable-github          # Anthropic on (default) + GitHub on
 *   node credential-proxy.js --disable-anthropic      # GitHub only
 *
 * In-sandbox bridge mode (started automatically by claudebox.sh with --no-network):
 *   node credential-proxy.js --bridge-only --socket /tmp/claude-proxy.sock --tcp-bridge-port 58080
 */

'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_SOCKET_PATH = '/tmp/claude-proxy.sock';
const DEFAULT_TCP_BRIDGE_PORT = 58080;

// Dummy tokens placed in the sandbox credentials file by claudebox.sh.
// The proxy replaces these with real tokens before forwarding.
const DUMMY_CLAUDE_TOKEN =
  'sk-ant-oat01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';
const DUMMY_GITHUB_TOKEN = 'ghs_dummyDummyDummyDummyDummyDummyDummyDum';

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    socketPath: DEFAULT_SOCKET_PATH,
    tcpBridgePort: null,
    bridgeOnly: false,
    verbose: false,
    services: {
      anthropic: true,   // on by default
      github: false,     // off by default
    },
  };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--socket':
        args.socketPath = argv[++i];
        break;
      case '--tcp-bridge-port':
        args.tcpBridgePort = parseInt(argv[++i], 10);
        break;
      case '--bridge-only':
        args.bridgeOnly = true;
        if (!args.tcpBridgePort) args.tcpBridgePort = DEFAULT_TCP_BRIDGE_PORT;
        break;
      case '--verbose':
        args.verbose = true;
        break;
      // Service toggles
      case '--enable-anthropic':   args.services.anthropic = true;  break;
      case '--disable-anthropic':  args.services.anthropic = false; break;
      case '--enable-github':      args.services.github    = true;  break;
      case '--disable-github':     args.services.github    = false; break;
      case '--help':
        printHelp();
        process.exit(0);
    }
  }
  return args;
}

function printHelp() {
  console.log(`
credential-proxy.js — Credential injection proxy for containerized Claude Code

NORMAL USAGE — let claudebox.sh manage everything:
  ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]

MANUAL HOST USAGE (advanced; claudebox.sh does this automatically):
  node credential-proxy.js [OPTIONS]

IN-SANDBOX BRIDGE (started automatically by claudebox.sh --no-network):
  node credential-proxy.js --bridge-only --socket /tmp/claude-proxy.sock --tcp-bridge-port 58080

OPTIONS:
  --socket PATH          Unix socket path (default: ${DEFAULT_SOCKET_PATH})
  --tcp-bridge-port PORT Also open a TCP listener that bridges to the socket (host or container)
  --bridge-only          Only run TCP→Unix bridge (no proxy logic); for in-container use
  --verbose              Log all proxied requests
  --help                 Show this help

SERVICE TOGGLES (default: anthropic=on, github=off):
  --enable-anthropic     Enable Anthropic/Claude credential injection (default)
  --disable-anthropic    Disable Anthropic credential injection
  --enable-github        Enable GitHub credential injection
  --disable-github       Disable GitHub credential injection (default)

ENVIRONMENT VARIABLES (override credential sources):
  CLAUDE_CREDENTIALS_FILE   Path to Claude credentials JSON
  GH_TOKEN                  GitHub personal access token
  GH_ENTERPRISE_TOKEN       GitHub Enterprise token

SANDBOX SETUP EXAMPLE (manual, without claudebox.sh):
  # 1. Write a dummy credentials file (tokens must match DUMMY_CLAUDE_TOKEN above)
  DUMMY_CREDS=$(mktemp)
  echo '{"claudeAiOauth":{"accessToken":"${DUMMY_CLAUDE_TOKEN}","refreshToken":"sk-ant-ort01-dummy"}}' > "$DUMMY_CREDS"

  # 2. Start proxy on host (also opens host-side TCP bridge on port 58080)
  node credential-proxy.js --socket /tmp/claude-proxy.sock --tcp-bridge-port 58080

  # 3. Launch bwrap sandbox with empty ~/.claude and dummy credentials (no real home bind)
  SANDBOX_HOME=/home/sandbox
  bwrap --unshare-user --unshare-ipc --unshare-pid --unshare-uts --die-with-parent \\
    --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev \\
    --tmpfs /tmp --tmpfs /run \\
    --tmpfs /home \\
    --dir  \$SANDBOX_HOME \\
    --dir  \$SANDBOX_HOME/.claude \\
    --ro-bind "\$DUMMY_CREDS" \$SANDBOX_HOME/.claude/.credentials.json \\
    --ro-bind /tmp/claude-proxy.sock /tmp/claude-proxy.sock \\
    --bind \$(pwd) /workspace --chdir /workspace \\
    --setenv HOME \$SANDBOX_HOME \\
    --setenv ANTHROPIC_BASE_URL http://127.0.0.1:58080 \\
    -- bash -c 'echo '"'"'{"hasCompletedOnboarding":true}'"'"' > \$HOME/.claude.json && exec claude'

  # Or simply use claudebox.sh which handles all of the above:
  ./claudebox.sh --workdir \$(pwd)
`);
}

// ---------------------------------------------------------------------------
// Credential retrieval — Claude Code
// ---------------------------------------------------------------------------

let _claudeCredsCache = null;
let _claudeCredsCacheTime = 0;
const CREDS_CACHE_TTL_MS = 30_000; // 30 s

function getClaudeCredentials() {
  const now = Date.now();
  if (_claudeCredsCache && now - _claudeCredsCacheTime < CREDS_CACHE_TTL_MS) {
    return _claudeCredsCache;
  }

  let creds = null;

  // 1. Environment override
  const envFile = process.env.CLAUDE_CREDENTIALS_FILE;
  if (envFile) {
    try {
      creds = JSON.parse(fs.readFileSync(envFile, 'utf8'));
    } catch (_) {}
  }

  // 2. macOS Keychain
  if (!creds && process.platform === 'darwin') {
    try {
      const raw = execSync(
        `security find-generic-password -s "Claude Code-credentials" -a "${os.userInfo().username}" -w 2>/dev/null`,
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      ).trim();
      if (raw) creds = JSON.parse(raw);
    } catch (_) {}
  }

  // 3. Linux / standard file locations
  if (!creds) {
    const candidates = [
      path.join(os.homedir(), '.claude', '.credentials.json'),
      path.join(os.homedir(), '.config', 'claude', 'auth.json'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        try {
          creds = JSON.parse(fs.readFileSync(p, 'utf8'));
          break;
        } catch (_) {}
      }
    }
  }

  if (creds) {
    _claudeCredsCache = creds;
    _claudeCredsCacheTime = now;
  }
  return creds;
}

function getClaudeAccessToken() {
  const creds = getClaudeCredentials();
  return creds?.claudeAiOauth?.accessToken ?? creds?.accessToken ?? null;
}

function invalidateClaudeCredsCache() {
  _claudeCredsCache = null;
}

// ---------------------------------------------------------------------------
// Credential retrieval — GitHub
// ---------------------------------------------------------------------------

let _ghTokenCache = null;
let _ghTokenCacheTime = 0;

function getGitHubToken(hostname = 'github.com') {
  const now = Date.now();
  if (_ghTokenCache && now - _ghTokenCacheTime < CREDS_CACHE_TTL_MS) {
    return _ghTokenCache;
  }

  let token = null;

  // 1. Well-known env vars
  token =
    process.env.GH_TOKEN ||
    process.env.GITHUB_TOKEN ||
    process.env.GH_ENTERPRISE_TOKEN ||
    null;

  // 2. gh CLI config (~/.config/gh/hosts.yml)
  if (!token) {
    const hostsFile = path.join(
      process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'),
      'gh',
      'hosts.yml'
    );
    if (fs.existsSync(hostsFile)) {
      try {
        const raw = fs.readFileSync(hostsFile, 'utf8');
        // Simple YAML parse for the oauth_token field under the hostname block
        // Format:
        //   github.com:
        //     oauth_token: ghp_xxx
        const re = new RegExp(
          `^${escapeRegex(hostname)}:\\s*\\n(?:[^\\S\\n]+.*\\n)*?[^\\S\\n]+oauth_token:\\s*(\\S+)`,
          'm'
        );
        const m = raw.match(re);
        if (m) token = m[1];
      } catch (_) {}
    }
  }

  // 3. gh CLI binary
  if (!token) {
    try {
      const result = spawnSync('gh', ['auth', 'token', '--hostname', hostname], {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      if (result.status === 0 && result.stdout.trim()) {
        token = result.stdout.trim();
      }
    } catch (_) {}
  }

  if (token) {
    _ghTokenCache = token;
    _ghTokenCacheTime = now;
  }
  return token;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Determine upstream target from request headers / path
// ---------------------------------------------------------------------------

function resolveUpstream(req) {
  // Claude Code sets ANTHROPIC_BASE_URL to the proxy; all requests go to Anthropic by default.
  // Detect GitHub requests by path prefix or an x-proxy-target header (optional).
  const target = req.headers['x-proxy-target'];
  if (target === 'github') {
    return { host: 'api.github.com', port: 443, https: true, type: 'github' };
  }
  if (req.url.startsWith('/github/') || req.url.startsWith('/repos/') || req.url.startsWith('/user')) {
    return { host: 'api.github.com', port: 443, https: true, type: 'github', stripPrefix: '/github' };
  }
  return { host: 'api.anthropic.com', port: 443, https: true, type: 'claude' };
}

function serviceDisabledResponse(res, type) {
  const msg = `Service "${type}" is disabled on this proxy. Start proxy with --enable-${type} to allow it.`;
  console.warn(`[proxy] blocked request for disabled service: ${type}`);
  res.writeHead(403, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: msg }));
}

// ---------------------------------------------------------------------------
// Credential injection
// ---------------------------------------------------------------------------

function injectClaudeCredentials(headers, verbose) {
  let token = getClaudeAccessToken();
  if (!token) {
    return { ok: false, error: 'No Claude credentials found on host' };
  }

  const updated = {};
  let replaced = false;

  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (
      (key === 'authorization' || key === 'x-api-key') &&
      typeof v === 'string' &&
      v.includes(DUMMY_CLAUDE_TOKEN)
    ) {
      updated[k] = v.replace(DUMMY_CLAUDE_TOKEN, token);
      replaced = true;
    } else {
      updated[k] = v;
    }
  }

  // If no dummy token found, inject anyway (allows real containers with no pre-set creds)
  if (!replaced) {
    if (verbose) console.log('[proxy] No dummy Claude token found; injecting Authorization header');
    updated['Authorization'] = `Bearer ${token}`;
  }

  return { ok: true, headers: updated };
}

function injectGitHubCredentials(headers, verbose) {
  const token = getGitHubToken();
  if (!token) {
    return { ok: false, error: 'No GitHub credentials found on host' };
  }

  const updated = {};
  let replaced = false;

  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (
      (key === 'authorization' || key === 'x-api-key') &&
      typeof v === 'string' &&
      v.includes(DUMMY_GITHUB_TOKEN)
    ) {
      updated[k] = v.replace(DUMMY_GITHUB_TOKEN, token);
      replaced = true;
    } else {
      updated[k] = v;
    }
  }

  if (!replaced) {
    if (verbose) console.log('[proxy] No dummy GitHub token found; injecting Authorization header');
    updated['Authorization'] = `Bearer ${token}`;
  }

  return { ok: true, headers: updated };
}

// ---------------------------------------------------------------------------
// Proxy request forwarding
// ---------------------------------------------------------------------------

function forwardRequest(upstream, method, urlPath, headers, body, res, verbose, onRetry) {
  const opts = {
    hostname: upstream.host,
    port: upstream.port,
    path: upstream.stripPrefix ? urlPath.replace(upstream.stripPrefix, '') : urlPath,
    method,
    headers,
  };

  if (verbose) {
    console.log(`[proxy] → ${method} https://${upstream.host}${opts.path}`);
  }

  const proto = upstream.https ? https : http;
  const proxyReq = proto.request(opts, (proxyRes) => {
    if (verbose) console.log(`[proxy] ← ${proxyRes.statusCode}`);

    if (proxyRes.statusCode === 401 && onRetry) {
      // Consume body, then retry once with fresh credentials
      let _buf = [];
      proxyRes.on('data', (c) => _buf.push(c));
      proxyRes.on('end', () => onRetry());
      return;
    }

    res.writeHead(proxyRes.statusCode, filterResponseHeaders(proxyRes.headers));
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    console.error('[proxy] upstream error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502);
      res.end(`Bad Gateway: ${err.message}`);
    }
  });

  if (body && body.length) proxyReq.write(body);
  proxyReq.end();
}

function filterResponseHeaders(headers) {
  const drop = new Set(['connection', 'transfer-encoding', 'keep-alive']);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!drop.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function filterRequestHeaders(headers) {
  const drop = new Set(['connection', 'keep-alive', 'content-length', 'x-proxy-target']);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!drop.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Main proxy handler
// ---------------------------------------------------------------------------

function createProxyHandler(verbose, services) {
  return function handleRequest(req, res) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const upstream = resolveUpstream(req);

      // Enforce service enable/disable policy
      if (upstream.type === 'github' && !services.github) {
        return serviceDisabledResponse(res, 'github');
      }
      if (upstream.type === 'claude' && !services.anthropic) {
        return serviceDisabledResponse(res, 'anthropic');
      }

      let baseHeaders = filterRequestHeaders(req.headers);
      baseHeaders['host'] = upstream.host;

      // Inject credentials
      let inject;
      if (upstream.type === 'github') {
        inject = injectGitHubCredentials(baseHeaders, verbose);
      } else {
        inject = injectClaudeCredentials(baseHeaders, verbose);
      }

      if (!inject.ok) {
        console.error('[proxy] credential error:', inject.error);
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: inject.error }));
        return;
      }

      const headers = inject.headers;
      // Restore correct content-length
      if (body.length) headers['content-length'] = String(body.length);

      function doRequest(retry) {
        // On retry, invalidate cache and re-inject
        let h = headers;
        if (retry) {
          invalidateClaudeCredsCache();
          const fresh =
            upstream.type === 'github'
              ? injectGitHubCredentials(filterRequestHeaders(req.headers), verbose)
              : injectClaudeCredentials(filterRequestHeaders(req.headers), verbose);
          if (!fresh.ok) return;
          h = fresh.headers;
          if (body.length) h['content-length'] = String(body.length);
        }
        forwardRequest(
          upstream,
          req.method,
          req.url,
          h,
          body,
          res,
          verbose,
          retry ? null : () => doRequest(true) // retry once on 401
        );
      }

      doRequest(false);
    });
  };
}

// ---------------------------------------------------------------------------
// TCP ↔ Unix socket bridge (for use inside the container)
// ---------------------------------------------------------------------------

function startTcpBridge(socketPath, port) {
  const server = net.createServer((tcpSocket) => {
    const unixSocket = net.createConnection(socketPath);

    tcpSocket.pipe(unixSocket);
    unixSocket.pipe(tcpSocket);

    const cleanup = () => {
      tcpSocket.destroy();
      unixSocket.destroy();
    };
    tcpSocket.on('error', cleanup);
    unixSocket.on('error', (err) => {
      console.error('[bridge] unix socket error:', err.message);
      cleanup();
    });
    tcpSocket.on('close', cleanup);
    unixSocket.on('close', cleanup);
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[bridge] TCP 127.0.0.1:${port} → Unix ${socketPath}`);
  });

  server.on('error', (err) => {
    console.error('[bridge] TCP server error:', err.message);
    process.exit(1);
  });

  return server;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const args = parseArgs(process.argv);

if (args.bridgeOnly) {
  // ---- Bridge-only mode: used inside the container ----
  if (!fs.existsSync(args.socketPath)) {
    console.error(`[bridge] Socket not found: ${args.socketPath}`);
    console.error('Make sure the host proxy socket is mounted into the container.');
    process.exit(1);
  }
  startTcpBridge(args.socketPath, args.tcpBridgePort);
} else {
  // ---- Proxy mode: run on the host ----

  // Remove stale socket
  if (fs.existsSync(args.socketPath)) {
    fs.unlinkSync(args.socketPath);
  }

  const proxyServer = http.createServer(createProxyHandler(args.verbose, args.services));

  proxyServer.listen(args.socketPath, () => {
    console.log(`[proxy] Listening on Unix socket: ${args.socketPath}`);
    // Allow container user (often non-root) to connect
    try { fs.chmodSync(args.socketPath, 0o666); } catch (_) {}
  });

  proxyServer.on('error', (err) => {
    console.error('[proxy] Server error:', err.message);
    process.exit(1);
  });

  // Optionally also expose a TCP listener on the host (for host-side testing)
  if (args.tcpBridgePort) {
    startTcpBridge(args.socketPath, args.tcpBridgePort);
  }

  // Cleanup on exit
  const cleanup = () => {
    try { fs.unlinkSync(args.socketPath); } catch (_) {}
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  console.log(`[proxy] Services: anthropic=${args.services.anthropic ? 'enabled' : 'disabled'}  github=${args.services.github ? 'enabled' : 'disabled'}`);
  if (args.services.anthropic) {
    console.log('[proxy] Claude credential sources (priority order):');
    console.log('  1. CLAUDE_CREDENTIALS_FILE env var');
    console.log('  2. macOS Keychain (darwin only)');
    console.log('  3. ~/.claude/.credentials.json');
    console.log('  4. ~/.config/claude/auth.json');
  }
  if (args.services.github) {
    console.log('[proxy] GitHub credential sources (priority order):');
    console.log('  1. GH_TOKEN / GITHUB_TOKEN / GH_ENTERPRISE_TOKEN env var');
    console.log('  2. ~/.config/gh/hosts.yml');
    console.log('  3. gh auth token (gh CLI)');
  }
}
