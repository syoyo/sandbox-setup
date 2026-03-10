#!/usr/bin/env node
/**
 * credential-proxy.js
 *
 * Anthropic credential injection proxy for sandboxed Claude Code.
 * Listens on a Unix domain socket (host side), replaces dummy Claude tokens
 * with real ones before forwarding requests to api.anthropic.com.
 *
 * Also runs a HTTPS CONNECT proxy that whitelists specific upstream hosts
 * (empty allowlist by default; api.github.com added with --enable-github).
 *
 * Normal usage: run claudebox.sh, which starts this proxy automatically.
 *   ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]
 *
 * Manual host usage (advanced):
 *   node credential-proxy.js \
 *     --anthropic-socket /tmp/claude-proxy-anthropic.sock \
 *     --anthropic-tcp-port 58080 \
 *     --github-connect-port 58081 [--enable-github]
 *
 * In-sandbox bridge mode (started by claudebox.sh --no-network):
 *   node credential-proxy.js --bridge-only \
 *     --socket /tmp/claude-proxy-anthropic.sock --tcp-bridge-port 58080
 */

'use strict';

const http  = require('http');
const https = require('https');
const net   = require('net');
const fs    = require('fs');
const os    = require('os');
const path  = require('path');
const url   = require('url');
const { spawnSync, spawn } = require('child_process');

// ---------------------------------------------------------------------------
// Dummy token placed in the sandbox by claudebox.sh.
// The proxy replaces it with the real token before forwarding.
// HIGH-4: per-session random token from SESSION_DUMMY_TOKEN env; falls back to
// a fixed value only for manual/standalone proxy usage.
// ---------------------------------------------------------------------------
const DUMMY_CLAUDE_TOKEN = process.env.SESSION_DUMMY_TOKEN ||
  'sk-ant-oat01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';

const DEFAULT_ANTHROPIC_SOCKET    = '/tmp/claude-proxy-anthropic.sock';
const DEFAULT_ANTHROPIC_PORT      = 58080;
const DEFAULT_GITHUB_CONNECT_PORT = 58081;

// Paths the Anthropic proxy will forward. Anything outside this set is rejected
// with 403, preventing the sandbox from abusing the proxy for non-inference calls.
// (HIGH-2: restrict proxy to known-safe Anthropic API paths)
const ANTHROPIC_PATH_ALLOWLIST = /^\/v1\/(messages|complete|models|count_tokens)(\/|$)/;

// Hosts the CONNECT proxy is allowed to tunnel to (HIGH-1: enforced per-entry).
const GITHUB_ALLOWLIST = ['api.github.com'];

// MED-5: maximum request body size (bytes) to prevent host OOM via proxy.
const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

// Maximum concurrent connections per server (MED-4: prevent FD exhaustion).
const MAX_CONNECTIONS = 100;

// MCP proxy path allowlist — only /mcp and /sse endpoints.
const MCP_PATH_ALLOWLIST = /^\/(mcp|sse)(\/|$)/;

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    anthropicSocket:   null,
    anthropicTcpPort:  null,
    githubConnectPort: null,
    githubSocket:      null,
    enableGithub:      false,
    idleTimeout:       0,       // minutes; 0 = disabled
    notifyCommand:     null,
    notifyWebhook:     null,
    mcpBridgeSocket:   null,   // Unix socket for MCP auth proxy
    mcpBridgePort:     null,   // target TCP port of MCP server on localhost
    mcpBearerToken:    process.env.MCP_BEARER_TOKEN || null,   // Bearer token from env (not CLI)
    bridgeOnly:        false,
    bridgeSocket:      null,
    bridgeTcpPort:     null,
    verbose:           false,
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--anthropic-socket':    args.anthropicSocket   = argv[++i]; break;
      case '--anthropic-tcp-port':  args.anthropicTcpPort  = parseInt(argv[++i], 10); break;
      case '--github-connect-port': args.githubConnectPort = parseInt(argv[++i], 10); break;
      case '--github-socket':        args.githubSocket  = argv[++i]; break;
      case '--idle-timeout':        args.idleTimeout   = parseInt(argv[++i], 10); break;
      case '--notify-command':     args.notifyCommand = argv[++i]; break;
      case '--notify-webhook':     args.notifyWebhook = argv[++i]; break;
      case '--mcp-bridge-socket':  args.mcpBridgeSocket = argv[++i]; break;
      case '--mcp-bridge-port':    args.mcpBridgePort = parseInt(argv[++i], 10); break;
      // HIGH-3: bearer token read from MCP_BEARER_TOKEN env var (not CLI) to avoid /proc leak.
      // --mcp-bearer-token kept for backwards compat but env var is preferred.
      case '--mcp-bearer-token':   args.mcpBearerToken = argv[++i]; break;
      case '--enable-github':       args.enableGithub = true; break;
      case '--bridge-only':         args.bridgeOnly = true; break;
      case '--socket':              args.bridgeSocket  = argv[++i]; break;
      case '--tcp-bridge-port':     args.bridgeTcpPort = parseInt(argv[++i], 10); break;
      case '--verbose':             args.verbose = true; break;
      case '--help': printHelp(); process.exit(0); break;
      default: console.warn(`[proxy] Unknown argument: ${argv[i]}`);
    }
  }

  if (!args.bridgeOnly && !args.anthropicSocket) {
    args.anthropicSocket = DEFAULT_ANTHROPIC_SOCKET;
  }

  return args;
}

function printHelp() {
  console.log(`
credential-proxy.js — Anthropic credential proxy + HTTPS CONNECT gateway

PROXY MODE (host side — claudebox.sh manages this automatically):
  node credential-proxy.js \\
    --anthropic-socket PATH     Unix socket (default: ${DEFAULT_ANTHROPIC_SOCKET})
    --anthropic-tcp-port PORT   Host-side TCP bridge (default: ${DEFAULT_ANTHROPIC_PORT})
    --github-connect-port PORT  HTTPS CONNECT proxy port (default: ${DEFAULT_GITHUB_CONNECT_PORT})
    --enable-github             Add api.github.com to CONNECT allowlist
    --verbose

BRIDGE-ONLY MODE (in-sandbox, for --no-network):
  node credential-proxy.js --bridge-only \\
    --socket PATH --tcp-bridge-port PORT

ENVIRONMENT:
  CLAUDE_CREDENTIALS_FILE   Override Claude credentials file path
`);
}

// ---------------------------------------------------------------------------
// Credential retrieval (Anthropic)
// ---------------------------------------------------------------------------

let _credsCache = null;
let _credsCacheTime = 0;
const CACHE_TTL_MS = 30_000;

function getClaudeCredentials() {
  const now = Date.now();
  if (_credsCache && now - _credsCacheTime < CACHE_TTL_MS) return _credsCache;

  let creds = null;

  // 1. Environment override
  const envFile = process.env.CLAUDE_CREDENTIALS_FILE;
  if (envFile) {
    try { creds = JSON.parse(fs.readFileSync(envFile, 'utf8')); } catch (_) {}
  }

  // 2. macOS Keychain (LOW-5 fix: use spawnSync with arg array, not shell interpolation)
  if (!creds && process.platform === 'darwin') {
    try {
      const username = os.userInfo().username;
      // Validate username to guard against unexpected characters
      if (/^[a-zA-Z0-9._-]+$/.test(username)) {
        const result = spawnSync(
          'security',
          ['find-generic-password', '-s', 'Claude Code-credentials', '-a', username, '-w'],
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
        );
        if (result.status === 0 && result.stdout.trim()) {
          creds = JSON.parse(result.stdout.trim());
        }
      }
    } catch (_) {}
  }

  // 3. Standard file locations
  if (!creds) {
    for (const p of [
      path.join(os.homedir(), '.claude', '.credentials.json'),
      path.join(os.homedir(), '.config', 'claude', 'auth.json'),
    ]) {
      if (fs.existsSync(p)) {
        try { creds = JSON.parse(fs.readFileSync(p, 'utf8')); break; } catch (_) {}
      }
    }
  }

  if (creds) { _credsCache = creds; _credsCacheTime = now; }
  return creds;
}

function getAccessToken() {
  const creds = getClaudeCredentials();
  return creds?.claudeAiOauth?.accessToken ?? creds?.accessToken ?? null;
}

function invalidateCache() { _credsCache = null; }

// ---------------------------------------------------------------------------
// Idle tracking — updated on every Anthropic API request
// ---------------------------------------------------------------------------
let _lastRequestTime = Date.now();
function touchActivity() { _lastRequestTime = Date.now(); }
function getLastRequestTime() { return _lastRequestTime; }

// ---------------------------------------------------------------------------
// Notification helper — sends events via command and/or webhook
// ---------------------------------------------------------------------------
function sendNotification(event, message, notifyCommand, notifyWebhook) {
  if (notifyCommand) {
    const child = spawn('bash', ['-c', notifyCommand], {
      env: { ...process.env, CLAUDEBOX_EVENT: event, CLAUDEBOX_MESSAGE: message },
      stdio: 'ignore', detached: true,
    });
    child.unref();
  }
  if (notifyWebhook) {
    const payload = JSON.stringify({
      text: message,
      blocks: [{ type: 'section', text: { type: 'mrkdwn', text: message } }],
      event, timestamp: new Date().toISOString(),
    });
    const u = new URL(notifyWebhook);
    // MED-1: only allow https webhooks to prevent SSRF to internal services.
    if (u.protocol !== 'https:') {
      console.warn(`[notify] webhook rejected: only https allowed (got ${u.protocol})`);
      return;
    }
    const reqOpts = {
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    };
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(reqOpts, (res) => res.resume());
    req.on('error', () => {});
    req.end(payload);
  }
}

// ---------------------------------------------------------------------------
// Anthropic proxy request handling
// ---------------------------------------------------------------------------

function filterRequestHeaders(headers) {
  const drop = new Set(['connection', 'keep-alive', 'content-length']);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!drop.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function filterResponseHeaders(headers) {
  const drop = new Set(['connection', 'transfer-encoding', 'keep-alive']);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!drop.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function injectToken(headers, verbose) {
  const token = getAccessToken();
  if (!token) return { ok: false, error: 'No Claude credentials found on host' };

  const updated = {};
  let replaced = false;
  for (const [k, v] of Object.entries(headers)) {
    if ((k.toLowerCase() === 'authorization' || k.toLowerCase() === 'x-api-key') &&
        typeof v === 'string' && v.includes(DUMMY_CLAUDE_TOKEN)) {
      updated[k] = v.replace(DUMMY_CLAUDE_TOKEN, token);
      replaced = true;
    } else {
      updated[k] = v;
    }
  }

  // HIGH-2: require a dummy token to be present; reject requests with no auth.
  // This prevents sandbox code from making arbitrary Anthropic calls without
  // the dummy credential structure that Claude Code always sends.
  if (!replaced) {
    return { ok: false, error: 'Request carries no dummy Claude token; injection refused' };
  }

  return { ok: true, headers: updated };
}

function forward(method, urlPath, headers, body, res, verbose, onRetry) {
  const opts = { hostname: 'api.anthropic.com', port: 443, path: urlPath, method, headers };
  if (verbose) console.log(`[anthropic] → ${method} https://api.anthropic.com${urlPath}`);

  const req = https.request(opts, (upstream) => {
    if (verbose) console.log(`[anthropic] ← ${upstream.statusCode}`);
    if (upstream.statusCode === 401 && onRetry) {
      upstream.resume();
      onRetry();
      return;
    }
    res.writeHead(upstream.statusCode, filterResponseHeaders(upstream.headers));
    upstream.pipe(res);
  });

  req.on('error', (err) => {
    console.error('[anthropic] upstream error:', err.message);
    // MED-3: generic error to sandbox; details logged server-side only.
    if (!res.headersSent) { res.writeHead(502); res.end('Bad Gateway'); }
  });

  if (body && body.length) req.write(body);
  req.end();
}

function createHandler(verbose) {
  return function (req, res) {
    // MED-4: normalize URL path to prevent traversal (e.g. /v1/messages/../../admin).
    const parsed = new URL(req.url, 'http://localhost');
    const normalizedPath = path.posix.normalize(parsed.pathname);
    if (normalizedPath !== parsed.pathname) {
      if (verbose) console.log(`[anthropic] path normalized: ${req.url} → ${normalizedPath}`);
    }

    // HIGH-2: restrict to known Anthropic inference paths only.
    if (!ANTHROPIC_PATH_ALLOWLIST.test(normalizedPath)) {
      if (verbose) console.log(`[anthropic] blocked path: ${normalizedPath}`);
      res.writeHead(403, { 'content-type': 'application/json' });
      // MED-3: don't leak internal path details to sandbox.
      res.end(JSON.stringify({ error: 'Path not allowed' }));
      return;
    }

    // Use normalized path for forwarding.
    const forwardUrl = normalizedPath + parsed.search;
    touchActivity();

    const chunks = [];
    let bodyLen = 0;
    let aborted = false;  // MED-2: guard against post-destroy data events
    req.on('data', (c) => {
      if (aborted) return;
      bodyLen += c.length;
      if (bodyLen > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        if (!res.headersSent) {
          res.writeHead(413, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request body too large' }));
        }
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      const body = Buffer.concat(chunks);
      const base = filterRequestHeaders(req.headers);
      base['host'] = 'api.anthropic.com';

      function attempt(retry) {
        if (retry) invalidateCache();
        const result = injectToken(retry ? filterRequestHeaders(req.headers) : base, verbose);
        if (!result.ok) {
          console.error('[anthropic] credential error:', result.error);
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: result.error }));
          return;
        }
        const h = result.headers;
        if (body.length) h['content-length'] = String(body.length);
        forward(req.method, forwardUrl, h, body, res, verbose, retry ? null : () => attempt(true));
      }

      attempt(false);
    });
  };
}

// ---------------------------------------------------------------------------
// TCP ↔ Unix socket bridge (for --no-network in-sandbox use)
// ---------------------------------------------------------------------------

function startTcpBridge(socketPath, port, label) {
  const tag = `[${label ?? 'bridge'}]`;
  const server = net.createServer((tcp) => {
    const unix = net.createConnection(socketPath);
    tcp.pipe(unix);
    unix.pipe(tcp);
    const cleanup = () => { tcp.destroy(); unix.destroy(); };
    tcp.on('error', cleanup);
    unix.on('error', (err) => { console.error(`${tag} unix error:`, err.message); cleanup(); });
    tcp.on('close', cleanup);
    unix.on('close', cleanup);
  });
  server.maxConnections = MAX_CONNECTIONS;  // MED-4: prevent FD exhaustion
  server.listen(port, '127.0.0.1', () =>
    console.log(`${tag} TCP 127.0.0.1:${port} → Unix ${socketPath}`));
  server.on('error', (err) => { console.error(`${tag} TCP error:`, err.message); process.exit(1); });
  return server;
}

// ---------------------------------------------------------------------------
// MCP auth-injecting HTTP proxy: Unix socket → localhost MCP server
// Injects Authorization: Bearer <token> into every request so the sandbox
// never sees the real GitHub token.
// ---------------------------------------------------------------------------

function startMcpAuthProxy(targetPort, socketPath, bearerToken) {
  const tag = '[mcp-proxy]';
  if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);

  const server = http.createServer((req, res) => {
    // HIGH-2: path allowlist — only allow /mcp and /sse endpoints.
    const parsed = new URL(req.url, 'http://localhost');
    const normPath = path.posix.normalize(parsed.pathname);
    if (!MCP_PATH_ALLOWLIST.test(normPath)) {
      res.writeHead(403);
      res.end('Path not allowed');
      return;
    }

    // HIGH-2: body size limit (same as Anthropic proxy).
    let bodyLen = 0;
    let aborted = false;
    const chunks = [];

    req.on('data', (c) => {
      if (aborted) return;
      bodyLen += c.length;
      if (bodyLen > MAX_BODY_SIZE) {
        aborted = true;
        req.destroy();
        if (!res.headersSent) { res.writeHead(413); res.end('Request body too large'); }
        return;
      }
      chunks.push(c);
    });

    req.on('end', () => {
      if (aborted) return;
      const body = Buffer.concat(chunks);
      const opts = {
        hostname: '127.0.0.1',
        port: targetPort,
        path: normPath + parsed.search,
        method: req.method,
        headers: { ...req.headers, authorization: `Bearer ${bearerToken}` },
      };
      delete opts.headers.host;
      if (body.length) opts.headers['content-length'] = String(body.length);

      const upstream = http.request(opts, (upRes) => {
        res.writeHead(upRes.statusCode, upRes.headers);
        upRes.pipe(res);
      });
      upstream.on('error', (err) => {
        console.error(`${tag} upstream error:`, err.message);
        if (!res.headersSent) res.writeHead(502);
        res.end('Bad Gateway');
      });
      if (body.length) upstream.write(body);
      upstream.end();
    });
  });

  server.maxConnections = MAX_CONNECTIONS;
  // LOW-4: request timeout to prevent slowloris.
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;
  server.listen(socketPath, () =>
    console.log(`${tag} Unix ${socketPath} → HTTP 127.0.0.1:${targetPort} (auth injected, path: ${MCP_PATH_ALLOWLIST})`));
  server.on('error', (err) => { console.error(`${tag} error:`, err.message); process.exit(1); });
  return server;
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT proxy — whitelists specific upstream host:port pairs
// HIGH-1: enforces both hostname AND port (must be 443)
// ---------------------------------------------------------------------------

function makeConnectHandler(allowlist, verbose) {
  return function (client) {
    const bufs = [];
    let totalLen = 0;

    function onData(chunk) {
      bufs.push(chunk);
      totalLen += chunk.length;
      const combined = Buffer.concat(bufs, totalLen);
      const headerEnd = combined.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (totalLen > 8192) client.destroy();
        return;
      }

      client.removeListener('data', onData);

      const header      = combined.slice(0, headerEnd).toString('ascii');
      const afterHeader = combined.slice(headerEnd + 4);
      const firstLine   = header.split('\r\n')[0];
      const [method, target] = firstLine.split(' ');

      if (method !== 'CONNECT') {
        client.end('HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n');
        return;
      }

      const colonIdx   = target.lastIndexOf(':');
      const host       = colonIdx >= 0 ? target.slice(0, colonIdx) : target;
      const targetPort = colonIdx >= 0 ? parseInt(target.slice(colonIdx + 1), 10) : 443;

      // HIGH-1: reject anything that is not in the allowlist on exactly port 443.
      // HIGH-4: case-insensitive comparison to prevent bypass via mixed-case hostnames.
      const hostLower = host.toLowerCase();
      if (!allowlist.some(h => h.toLowerCase() === hostLower) || targetPort !== 443) {
        if (verbose || allowlist.length > 0) {
          console.warn(`[github-connect] blocked CONNECT ${target}`);
        }
        client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
        return;
      }

      if (verbose) console.log(`[github-connect] → CONNECT ${target}`);

      const upstream = net.createConnection(targetPort, host, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (afterHeader.length) upstream.write(afterHeader);
        client.pipe(upstream);
        upstream.pipe(client);
      });

      const cleanup = () => { client.destroy(); upstream.destroy(); };
      upstream.on('error', (err) => {
        console.error(`[github-connect] upstream error (${target}):`, err.message);
        if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      });
      client.on('error', cleanup);
      client.on('close', cleanup);
      upstream.on('close', cleanup);
    }

    client.on('data', onData);
    client.on('error', () => {});
  };
}

function startConnectProxy(port, allowlist, verbose) {
  const handler = makeConnectHandler(allowlist, verbose);
  const server = net.createServer(handler);
  server.maxConnections = MAX_CONNECTIONS;

  server.listen(port, '127.0.0.1', () => {
    const desc = allowlist.length ? `${allowlist.join(', ')}:443` : '(none — all blocked)';
    console.log(`[github-connect] CONNECT proxy 127.0.0.1:${port}, allowlist: ${desc}`);
  });
  server.on('error', (err) => {
    console.error('[github-connect] error:', err.message);
    process.exit(1);
  });
  return server;
}

function startConnectProxySocket(socketPath, allowlist, verbose) {
  const handler = makeConnectHandler(allowlist, verbose);
  const server = net.createServer(handler);
  server.maxConnections = MAX_CONNECTIONS;

  if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
  server.listen(socketPath, () => {
    console.log(`[github-connect] CONNECT proxy socket: ${socketPath}`);
  });
  server.on('error', (err) => {
    console.error('[github-connect] socket error:', err.message);
    process.exit(1);
  });
  return server;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const args = parseArgs(process.argv);

if (args.bridgeOnly) {
  if (!args.bridgeSocket)  { console.error('[bridge] --socket required');          process.exit(1); }
  if (!args.bridgeTcpPort) { console.error('[bridge] --tcp-bridge-port required'); process.exit(1); }
  if (!fs.existsSync(args.bridgeSocket)) {
    console.error(`[bridge] Socket not found: ${args.bridgeSocket}`);
    process.exit(1);
  }
  startTcpBridge(args.bridgeSocket, args.bridgeTcpPort);
} else {
  const socketPath = args.anthropicSocket;
  const tcpPort    = args.anthropicTcpPort ?? DEFAULT_ANTHROPIC_PORT;

  if (fs.existsSync(socketPath)) fs.unlinkSync(socketPath);

  const server = http.createServer(createHandler(args.verbose));
  server.maxConnections = MAX_CONNECTIONS;
  // LOW-4: request/headers timeout to prevent slowloris from sandbox.
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;
  server.listen(socketPath, () => {
    console.log(`[anthropic] Listening on ${socketPath}`);
    // HIGH-3: do NOT chmod to 0o666. Default umask (typically 0o600/0o660) is correct.
    // The sandbox user matches the host user (--uid $(id -u)), so no extra permissions needed.
  });
  server.on('error', (err) => {
    console.error('[anthropic] Server error:', err.message);
    process.exit(1);
  });

  startTcpBridge(socketPath, tcpPort, 'anthropic');

  const allowlist = args.enableGithub ? GITHUB_ALLOWLIST : [];
  if (args.githubConnectPort) {
    startConnectProxy(args.githubConnectPort, allowlist, args.verbose);
  }

  let githubSocketPath = null;
  if (args.githubSocket) {
    githubSocketPath = args.githubSocket;
    startConnectProxySocket(githubSocketPath, allowlist, args.verbose);
  }

  // MCP auth proxy (inject Bearer token, forward to MCP server on host)
  let mcpBridgeSocketPath = null;
  if (args.mcpBridgeSocket && args.mcpBridgePort && args.mcpBearerToken) {
    mcpBridgeSocketPath = args.mcpBridgeSocket;
    startMcpAuthProxy(args.mcpBridgePort, mcpBridgeSocketPath, args.mcpBearerToken);
  }

  const cleanup = () => {
    try { fs.unlinkSync(socketPath); } catch (_) {}
    if (githubSocketPath) { try { fs.unlinkSync(githubSocketPath); } catch (_) {} }
    if (mcpBridgeSocketPath) { try { fs.unlinkSync(mcpBridgeSocketPath); } catch (_) {} }
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  // Idle timeout monitor — warn when no Anthropic requests for N minutes
  if (args.idleTimeout > 0) {
    const idleMs = args.idleTimeout * 60 * 1000;
    let _idleWarned = false;
    setInterval(() => {
      const elapsed = Date.now() - getLastRequestTime();
      if (elapsed >= idleMs) {
        if (!_idleWarned) {
          const mins = Math.round(elapsed / 60000);
          const msg = `:hourglass: No Anthropic API request for ${mins} minutes (threshold: ${args.idleTimeout}m). Sandbox may be stuck or idle.`;
          console.warn(`[idle] ⚠ No Anthropic API request for ${mins} minutes (threshold: ${args.idleTimeout}m)`);
          console.warn('[idle]   The sandbox process may be stuck or idle.');
          sendNotification('idle_timeout', msg, args.notifyCommand, args.notifyWebhook);
          _idleWarned = true;
        }
      } else {
        _idleWarned = false;
      }
    }, 60_000); // check every minute
    console.log(`[idle] Idle timeout: ${args.idleTimeout} minutes`);
  }

  console.log('[anthropic] Credential sources: CLAUDE_CREDENTIALS_FILE → macOS Keychain → ~/.claude/.credentials.json');
  console.log('[anthropic] Path allowlist:', ANTHROPIC_PATH_ALLOWLIST.toString());
}
