#!/usr/bin/env node
/**
 * credential-proxy.js
 *
 * Anthropic credential injection proxy for sandboxed Claude Code.
 * Listens on a Unix domain socket (host side), replaces dummy Claude tokens
 * with real ones before forwarding requests to api.anthropic.com.
 *
 * GitHub credentials are NOT proxied — gh CLI uses HTTPS with no URL-override
 * mechanism, so GH_TOKEN is passed directly into the sandbox instead.
 *
 * Normal usage: run claudebox.sh, which starts this proxy automatically.
 *   ./claudebox.sh [OPTIONS] [-- CLAUDE_ARGS...]
 *
 * Manual host usage (advanced):
 *   node credential-proxy.js \
 *     --anthropic-socket /tmp/claude-proxy-anthropic.sock \
 *     --anthropic-tcp-port 58080
 *
 * In-sandbox bridge mode (started by claudebox.sh --no-network):
 *   node credential-proxy.js --bridge-only \
 *     --socket /tmp/claude-proxy-anthropic.sock --tcp-bridge-port 58080
 */

'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

// ---------------------------------------------------------------------------
// Dummy token placed in the sandbox by claudebox.sh.
// The proxy replaces it with the real token before forwarding.
// ---------------------------------------------------------------------------
const DUMMY_CLAUDE_TOKEN =
  'sk-ant-oat01-dummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDummyDQ-DummyAA';

const DEFAULT_ANTHROPIC_SOCKET = '/tmp/claude-proxy-anthropic.sock';
const DEFAULT_ANTHROPIC_PORT   = 58080;
const DEFAULT_GITHUB_CONNECT_PORT = 58081;

// Hosts the CONNECT proxy is allowed to tunnel to.
const GITHUB_CONNECT_ALLOWLIST = ['api.github.com'];

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    anthropicSocket:     null,
    anthropicTcpPort:    null,
    githubConnectPort:   null,   // HTTPS CONNECT proxy for api.github.com
    // Bridge-only mode
    bridgeOnly:    false,
    bridgeSocket:  null,
    bridgeTcpPort: null,
    verbose: false,
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--anthropic-socket':   args.anthropicSocket   = argv[++i]; break;
      case '--anthropic-tcp-port': args.anthropicTcpPort  = parseInt(argv[++i], 10); break;
      case '--github-connect-port':args.githubConnectPort = parseInt(argv[++i], 10); break;
      case '--bridge-only':        args.bridgeOnly = true; break;
      case '--socket':             args.bridgeSocket   = argv[++i]; break;
      case '--tcp-bridge-port':    args.bridgeTcpPort  = parseInt(argv[++i], 10); break;
      case '--verbose':            args.verbose = true; break;
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
credential-proxy.js — Anthropic credential proxy for sandboxed Claude Code

PROXY MODE (host side):
  node credential-proxy.js \\
    --anthropic-socket PATH   Unix socket (default: ${DEFAULT_ANTHROPIC_SOCKET})
    --anthropic-tcp-port PORT Also open a host-side TCP bridge (default: ${DEFAULT_ANTHROPIC_PORT})
    --verbose

BRIDGE-ONLY MODE (in-sandbox, for --no-network):
  node credential-proxy.js --bridge-only \\
    --socket PATH --tcp-bridge-port PORT

ENVIRONMENT:
  CLAUDE_CREDENTIALS_FILE   Override Claude credentials file path
`);
}

// ---------------------------------------------------------------------------
// Credential retrieval
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
// Request handling
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
  if (!replaced) {
    if (verbose) console.log('[anthropic] No dummy token; injecting Authorization header');
    updated['Authorization'] = `Bearer ${token}`;
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
    if (!res.headersSent) { res.writeHead(502); res.end(`Bad Gateway: ${err.message}`); }
  });

  if (body && body.length) req.write(body);
  req.end();
}

function createHandler(verbose) {
  return function (req, res) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const base = filterRequestHeaders(req.headers);
      base['host'] = 'api.anthropic.com';

      function attempt(retry) {
        if (retry) invalidateCache();
        const result = injectToken(retry ? filterRequestHeaders(req.headers) : base, verbose);
        if (!result.ok) {
          console.error('[anthropic] credential error:', result.error);
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: result.error }));
          return;
        }
        const h = result.headers;
        if (body.length) h['content-length'] = String(body.length);
        forward(req.method, req.url, h, body, res, verbose, retry ? null : () => attempt(true));
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
  server.listen(port, '127.0.0.1', () => console.log(`${tag} TCP 127.0.0.1:${port} → Unix ${socketPath}`));
  server.on('error', (err) => { console.error(`${tag} TCP error:`, err.message); process.exit(1); });
  return server;
}

// ---------------------------------------------------------------------------
// HTTPS CONNECT proxy — whitelists specific upstream hosts
// ---------------------------------------------------------------------------

function startConnectProxy(port, allowlist, verbose) {
  const server = net.createServer((client) => {
    // Accumulate data until the full HTTP CONNECT request headers arrive.
    const bufs = [];
    let totalLen = 0;

    function onData(chunk) {
      bufs.push(chunk);
      totalLen += chunk.length;
      const combined = Buffer.concat(bufs, totalLen);
      const headerEnd = combined.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (totalLen > 8192) { client.destroy(); } // header too large
        return;
      }

      // Stop accumulating; parse the CONNECT request.
      client.removeListener('data', onData);

      const header = combined.slice(0, headerEnd).toString('ascii');
      const afterHeader = combined.slice(headerEnd + 4); // any bytes past the headers
      const firstLine = header.split('\r\n')[0];
      const [method, target] = firstLine.split(' ');

      if (method !== 'CONNECT') {
        client.end('HTTP/1.1 405 Method Not Allowed\r\n\r\n');
        return;
      }

      const colonIdx = target.lastIndexOf(':');
      const host = colonIdx >= 0 ? target.slice(0, colonIdx) : target;
      const port  = colonIdx >= 0 ? parseInt(target.slice(colonIdx + 1), 10) : 443;

      if (!allowlist.includes(host)) {
        if (verbose) console.log(`[github-connect] blocked CONNECT ${target}`);
        client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
        return;
      }

      if (verbose) console.log(`[github-connect] → CONNECT ${target}`);

      const upstream = net.createConnection(port, host, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        // Replay any bytes that arrived after the CONNECT headers.
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
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[github-connect] CONNECT proxy 127.0.0.1:${port}, allowlist: ${allowlist.join(', ')}`);
  });
  server.on('error', (err) => { console.error('[github-connect] error:', err.message); process.exit(1); });
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
  server.listen(socketPath, () => {
    console.log(`[anthropic] Listening on ${socketPath}`);
    try { fs.chmodSync(socketPath, 0o666); } catch (_) {}
  });
  server.on('error', (err) => { console.error('[anthropic] Server error:', err.message); process.exit(1); });

  startTcpBridge(socketPath, tcpPort, 'anthropic');

  if (args.githubConnectPort) {
    startConnectProxy(args.githubConnectPort, GITHUB_CONNECT_ALLOWLIST, args.verbose);
  }

  const cleanup = () => { try { fs.unlinkSync(socketPath); } catch (_) {} process.exit(0); };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  console.log('[anthropic] Credential sources: CLAUDE_CREDENTIALS_FILE → macOS Keychain → ~/.claude/.credentials.json');
}
