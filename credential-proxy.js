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
// HIGH-4: per-session random token from SESSION_DUMMY_TOKEN env.
// MED-5: no static fallback — require the env var to be set.
// ---------------------------------------------------------------------------
const DUMMY_CLAUDE_TOKEN = process.env.SESSION_DUMMY_TOKEN || '';
if (!DUMMY_CLAUDE_TOKEN && !process.argv.includes('--bridge-only')) {
  console.error('[FATAL] SESSION_DUMMY_TOKEN environment variable is required');
  process.exit(1);
}

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

// SEC: maximum response body size to prevent host OOM from buffered responses.
const MAX_RESPONSE_SIZE = 100 * 1024 * 1024; // 100 MB

// Maximum concurrent connections per server (MED-4: prevent FD exhaustion).
const MAX_CONNECTIONS = 100;

// MCP proxy path allowlist — only /mcp and /sse endpoints.
const MCP_PATH_ALLOWLIST = /^\/(mcp|sse)(\/|$)/;

// Private/reserved IP check — covers RFC 1918, loopback, link-local,
// CGNAT (100.64/10), benchmarking (198.18/15), class E (240/4),
// broadcast, and IPv6 ULA/link-local/loopback (including expanded forms).
function isPrivateIP(addr) {
  // Strip IPv4-mapped and SIIT-translated IPv6 prefixes
  const ip = addr.replace(/^::ffff:(0+:)?/i, '');
  if (ip === '255.255.255.255') return true;
  // Normalize expanded IPv6 loopback (0000:...:0001) to ::1 for matching
  const collapsed = ip.replace(/^0{1,4}(:0{1,4}){6}:0{0,3}1$/, '::1');
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|100\.(6[4-9]|[7-9]\d|1[0-2][0-7])\.|198\.1[89]\.|240\.|::1$|fe80|fc|fd)/.test(collapsed);
}

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
    connectAllowlist:  [],     // additional CONNECT proxy hostnames
    idleTimeout:       0,       // minutes; 0 = disabled
    tokenLimit:        0,       // max tokens (input+output); 0 = unlimited
    auditLog:          null,    // path to audit log file
    notifyCommand:     null,
    notifyWebhook:     null,
    autoRefreshAuth:   false,
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
      case '--auto-refresh-auth':  args.autoRefreshAuth = true; break;
      case '--mcp-bridge-socket':  args.mcpBridgeSocket = argv[++i]; break;
      case '--mcp-bridge-port':    args.mcpBridgePort = parseInt(argv[++i], 10); break;
      // HIGH-3: bearer token read from MCP_BEARER_TOKEN env var (not CLI) to avoid /proc leak.
      // --mcp-bearer-token kept for backwards compat but env var is preferred.
      case '--mcp-bearer-token':   args.mcpBearerToken = argv[++i]; break;
      case '--token-limit':         args.tokenLimit = parseInt(argv[++i], 10); break;
      case '--audit-log':           args.auditLog = argv[++i]; break;
      case '--connect-allowlist':   args.connectAllowlist.push(argv[++i]); break;
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
    --auto-refresh-auth         Run a short host \`claude -p ...\` probe on 401, then retry once if the token changed
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
// Token usage tracking — accumulates input/output tokens from API responses
// ---------------------------------------------------------------------------
let _totalInputTokens = 0;
let _totalOutputTokens = 0;
let _totalRequests = 0;
let _tokenLimitExceeded = false;

function addTokenUsage(input, output) {
  _totalInputTokens += input || 0;
  _totalOutputTokens += output || 0;
  _totalRequests++;
}

function getTotalTokens() { return _totalInputTokens + _totalOutputTokens; }

// Module-level refs set at startup for use in forward()
let _forward_tokenLimit = 0;
let _forward_notifyCommand = null;
let _forward_notifyWebhook = null;
let _forward_autoRefreshAuth = false;
let _authRefreshPromise = null;

function getTokenSummary() {
  return { input: _totalInputTokens, output: _totalOutputTokens, total: getTotalTokens(), requests: _totalRequests };
}

function trackUsage(usage, verbose) {
  addTokenUsage(usage.input_tokens, usage.output_tokens);
  if (verbose) {
    const s = getTokenSummary();
    console.log(`[tokens] +${usage.input_tokens || 0}in +${usage.output_tokens || 0}out (total: ${s.total})`);
  }
  if (_forward_tokenLimit > 0 && getTotalTokens() >= _forward_tokenLimit && !_tokenLimitExceeded) {
    _tokenLimitExceeded = true;
    const s = getTokenSummary();
    const msg = `:money_with_wings: Token budget exceeded: ${s.total} tokens used (limit: ${_forward_tokenLimit}). New requests will be rejected.`;
    console.warn(`[tokens] ⚠ Token budget exceeded: ${s.total} (limit: ${_forward_tokenLimit})`);
    sendNotification('token_limit', msg, _forward_notifyCommand, _forward_notifyWebhook);
    auditLog({ event: 'token_limit_exceeded', ...s, limit: _forward_tokenLimit });
  }
}

function parseJsonSafe(text) {
  try { return JSON.parse(text); } catch (_) { return null; }
}

function isExpiredOauthResponse(statusCode, bodyText) {
  if (statusCode !== 401 || typeof bodyText !== 'string' || bodyText.length === 0) return false;
  const json = parseJsonSafe(bodyText);
  const msg = String(
    json?.error?.message ??
    json?.message ??
    bodyText
  ).toLowerCase();
  return msg.includes('oauth token has expired') ||
    (msg.includes('refresh your existing token') && msg.includes('oauth'));
}

async function refreshHostAuth(verbose) {
  if (_authRefreshPromise) return _authRefreshPromise;
  _authRefreshPromise = new Promise((resolve) => {
    const previousToken = getAccessToken();
    console.warn('[auth] Received 401; probing host Claude to trigger token refresh');
    const child = spawn('claude', ['-p', 'hi claude, may you be happy'], {
      stdio: 'ignore',
      env: process.env,
    });
    child.on('error', (err) => {
      console.error('[auth] refresh command failed:', err.message);
      resolve(false);
    });
    child.on('exit', (code) => {
      if (verbose) console.log(`[auth] refresh command exited with ${code}`);
      invalidateCache();
      const nextToken = getAccessToken();
      resolve(Boolean(previousToken && nextToken && nextToken !== previousToken));
    });
  }).finally(() => { _authRefreshPromise = null; });
  return _authRefreshPromise;
}

// ---------------------------------------------------------------------------
// Audit log — append structured entries to a JSONL file
// ---------------------------------------------------------------------------
let _auditLogPath = null;

function initAuditLog(logPath) {
  _auditLogPath = logPath;
  const entry = { ts: new Date().toISOString(), event: 'proxy_start', pid: process.pid };
  // SEC: create audit log with restrictive permissions (owner-only read/write)
  const fd = fs.openSync(_auditLogPath, 'a', 0o600);
  fs.writeSync(fd, JSON.stringify(entry) + '\n');
  fs.closeSync(fd);
}

function auditLog(entry) {
  if (!_auditLogPath) return;
  try {
    const record = { ts: new Date().toISOString(), ...entry };
    fs.appendFileSync(_auditLogPath, JSON.stringify(record) + '\n');
  } catch (e) { /* best effort */ }
}

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
    // MED-2: resolve hostname and reject private/internal IPs to prevent
    // DNS rebinding SSRF (checking hostname alone is insufficient).
    const host = u.hostname;
    if (host === 'localhost' || isPrivateIP(host)) {
      console.warn(`[notify] webhook rejected: private/internal address (${host})`);
      return;
    }
    const dns = require('dns');
    dns.lookup(host, (err, address) => {
      if (err) { console.warn(`[notify] webhook DNS lookup failed: ${err.message}`); return; }
      if (isPrivateIP(address)) {
        console.warn(`[notify] webhook rejected: ${host} resolved to private address ${address}`);
        return;
      }
      const reqOpts = {
        hostname: address, port: u.port || 443, path: u.pathname + u.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'Host': u.host },
      };
      const req = https.request(reqOpts, (r) => r.resume());
      req.on('error', () => {});
      req.end(payload);
    });
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
  if (!token) return { ok: false, error: 'Credential error' };

  const updated = {};
  let replaced = false;
  for (const [k, v] of Object.entries(headers)) {
    const kl = k.toLowerCase();
    if ((kl === 'authorization' || kl === 'x-api-key') && typeof v === 'string') {
      // SEC: reject if header contains anything besides the dummy token (no piggyback)
      // Strip "Bearer " prefix for comparison if present.
      const bare = /^Bearer /i.test(v) ? v.slice(7) : v;
      if (bare !== DUMMY_CLAUDE_TOKEN) {
        return { ok: false, error: 'Auth header rejected' };
      }
      updated[k] = v.replace(DUMMY_CLAUDE_TOKEN, token);
      replaced = true;
    } else if (kl === 'authorization' || kl === 'x-api-key') {
      // Reject non-string auth headers (array injection)
      return { ok: false, error: 'Auth header rejected' };
    } else {
      updated[k] = v;
    }
  }

  // HIGH-2: require a dummy token to be present; reject requests with no auth.
  if (!replaced) {
    return { ok: false, error: 'Auth header rejected' };
  }

  return { ok: true, headers: updated };
}

function forward(method, urlPath, headers, body, res, verbose, onRetry) {
  const opts = { hostname: 'api.anthropic.com', port: 443, path: urlPath, method, headers };
  if (verbose) console.log(`[anthropic] → ${method} https://api.anthropic.com${urlPath}`);

  const reqStartTime = Date.now();
  const req = https.request(opts, (upstream) => {
    if (verbose) console.log(`[anthropic] ← ${upstream.statusCode}`);
    const respHeaders = filterResponseHeaders(upstream.headers);
    const isStreaming = (upstream.headers['content-type'] || '').includes('text/event-stream');

    // MED-1: streaming responses are piped directly to the client to avoid
    // buffering the entire body in memory.  Non-streaming and error responses
    // are still buffered for 401 retry and usage extraction.
    if (isStreaming && upstream.statusCode === 200) {
      // Stream directly — keep a small rolling tail buffer for usage extraction.
      if (!res.headersSent) res.writeHead(upstream.statusCode, respHeaders);
      const TAIL_SIZE = 8192;
      let tail = '';
      upstream.on('data', (chunk) => {
        res.write(chunk);
        // Keep last TAIL_SIZE chars for usage parsing
        tail += chunk.toString('utf8');
        if (tail.length > TAIL_SIZE * 2) tail = tail.slice(-TAIL_SIZE);
      });
      upstream.on('end', () => {
        const durationMs = Date.now() - reqStartTime;
        let usage = null;
        try {
          const lines = tail.split('\n').filter(l => l.startsWith('data: ') && l.includes('"usage"'));
          if (lines.length > 0) {
            const lastData = JSON.parse(lines[lines.length - 1].slice(6));
            usage = lastData.usage || (lastData.message && lastData.message.usage) || null;
          }
        } catch (_) {}
        if (usage) trackUsage(usage, verbose);
        auditLog({ event: 'api_request', method, path: urlPath, status: upstream.statusCode,
          duration_ms: durationMs,
          input_tokens: usage ? usage.input_tokens : null,
          output_tokens: usage ? usage.output_tokens : null,
          cumulative_tokens: getTotalTokens() });
        res.end();
      });
    } else {
      // Non-streaming / error: buffer for retry + usage extraction.
      const respChunks = [];
      let respLen = 0;
      let respAborted = false;
      upstream.on('data', (chunk) => {
        if (respAborted) return;
        respLen += chunk.length;
        if (respLen > MAX_RESPONSE_SIZE) {
          respAborted = true;
          upstream.destroy();
          if (!res.headersSent) { res.writeHead(502); res.end('Response too large'); }
          return;
        }
        respChunks.push(chunk);
      });
      upstream.on('end', () => {
        if (respAborted) return;
        const respBody = Buffer.concat(respChunks);
        const durationMs = Date.now() - reqStartTime;
        const respText = respBody.toString('utf8');

        if (upstream.statusCode === 401 && onRetry) {
          if (_forward_autoRefreshAuth && isExpiredOauthResponse(upstream.statusCode, respText)) {
            refreshHostAuth(verbose).then((ok) => {
              if (!ok) {
                if (!res.headersSent) res.writeHead(upstream.statusCode, respHeaders);
                res.end(respBody);
                return;
              }
              invalidateCache();
              setImmediate(onRetry);
            });
            return;
          }
          if (!res.headersSent) res.writeHead(upstream.statusCode, respHeaders);
          res.end(respBody);
          return;
        }

        let usage = null;
        try {
          if (upstream.statusCode === 200) {
            const json = JSON.parse(respText);
            usage = json.usage || null;
          }
        } catch (_) {}
        if (usage) trackUsage(usage, verbose);

        auditLog({ event: 'api_request', method, path: urlPath, status: upstream.statusCode,
          duration_ms: durationMs,
          input_tokens: usage ? usage.input_tokens : null,
          output_tokens: usage ? usage.output_tokens : null,
          cumulative_tokens: getTotalTokens() });

        if (!res.headersSent) res.writeHead(upstream.statusCode, respHeaders);
        res.end(respBody);
      });
    }
  });

  req.on('error', (err) => {
    console.error('[anthropic] upstream error:', err.message);
    auditLog({ event: 'api_error', method, path: urlPath, error: err.message });
    // MED-3: generic error to sandbox; details logged server-side only.
    if (!res.headersSent) { res.writeHead(502); res.end('Bad Gateway'); }
  });

  if (body && body.length) req.write(body);
  req.end();
}

function createHandler(verbose, tokenLimit, notifyCommand, notifyWebhook) {
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

    // MED-3: Token budget — reject new requests if limit exceeded.
    // Check both the accumulated flag and current total to handle races
    // where parallel requests finish between check and accumulation.
    if (tokenLimit > 0 && (_tokenLimitExceeded || getTotalTokens() >= tokenLimit)) {
      _tokenLimitExceeded = true;
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token budget exceeded', total_tokens: getTotalTokens(), limit: tokenLimit }));
      auditLog({ event: 'token_limit_rejected', path: normalizedPath, total: getTotalTokens(), limit: tokenLimit });
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
          // SEC: generic error to sandbox; details logged server-side only.
          res.end(JSON.stringify({ error: 'Authentication failed' }));
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

      // SEC: require dummy token from sandbox (same gating as Anthropic proxy).
      // Reject requests that don't present the session dummy token.
      const authHeader = req.headers['authorization'] || req.headers['x-api-key'] || '';
      const bareToken = /^Bearer /i.test(authHeader) ? authHeader.slice(7) : authHeader;
      if (!bareToken || bareToken !== DUMMY_CLAUDE_TOKEN) {
        res.writeHead(401);
        res.end('Authentication required');
        return;
      }

      // SEC: filter request headers — drop hop-by-hop and sensitive headers
      // to prevent the sandbox from injecting trusted headers into the MCP server.
      const mcpDropHeaders = new Set([
        'connection', 'keep-alive', 'content-length', 'host',
        'authorization', 'x-api-key', 'cookie',
        'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'x-real-ip', 'cf-connecting-ip', 'true-client-ip',
      ]);
      const mcpHeaders = { authorization: `Bearer ${bearerToken}` };
      for (const [k, v] of Object.entries(req.headers)) {
        if (!mcpDropHeaders.has(k.toLowerCase())) mcpHeaders[k] = v;
      }
      const opts = {
        hostname: '127.0.0.1',
        port: targetPort,
        path: normPath + parsed.search,
        method: req.method,
        headers: mcpHeaders,
      };
      if (body.length) opts.headers['content-length'] = String(body.length);

      const upstream = http.request(opts, (upRes) => {
        // SEC: filter response headers — drop sensitive headers from MCP server
        const safeHeaders = {};
        const dropHeaders = new Set(['set-cookie', 'location', 'x-forwarded-for', 'x-forwarded-host']);
        for (const [k, v] of Object.entries(upRes.headers)) {
          if (!dropHeaders.has(k.toLowerCase())) safeHeaders[k] = v;
        }
        res.writeHead(upRes.statusCode, safeHeaders);
        // MED-4: enforce response size limit to prevent OOM from MCP server
        let mcpRespLen = 0;
        upRes.on('data', (chunk) => {
          mcpRespLen += chunk.length;
          if (mcpRespLen > MAX_RESPONSE_SIZE) {
            upRes.destroy();
            res.end();
            return;
          }
          res.write(chunk);
        });
        upRes.on('end', () => res.end());
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

      // SEC: reject targets with control characters (CRLF injection / request smuggling)
      if (!target || /[\x00-\x1f\x7f]/.test(target) || !/^[a-zA-Z0-9._-]+:\d+$/.test(target)) {
        client.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
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

      // SEC: DNS rebinding protection — resolve hostname and reject private IPs
      const dns = require('dns');
      dns.lookup(host, (err, address) => {
        if (err) {
          client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
          return;
        }
        // Reject private/loopback/link-local/CGNAT IPs (incl. IPv4-mapped IPv6)
        if (isPrivateIP(address)) {
          console.warn(`[github-connect] DNS rebinding blocked: ${host} resolved to ${address}`);
          client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
          return;
        }
        const unmapped = address.replace(/^::ffff:/i, '');

      const upstream = net.createConnection(targetPort, unmapped, () => {
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
      });

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

  // Set module-level refs for forward() token tracking
  _forward_tokenLimit = args.tokenLimit;
  _forward_notifyCommand = args.notifyCommand;
  _forward_notifyWebhook = args.notifyWebhook;
  _forward_autoRefreshAuth = args.autoRefreshAuth;

  // Initialize audit log if configured
  if (args.auditLog) initAuditLog(args.auditLog);

  const server = http.createServer(createHandler(args.verbose, args.tokenLimit, args.notifyCommand, args.notifyWebhook));
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

  const allowlist = [
    ...(args.enableGithub ? GITHUB_ALLOWLIST : []),
    ...args.connectAllowlist,
  ];
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
    // SEC: validate bearer token format (non-empty, no control characters)
    if (typeof args.mcpBearerToken !== 'string' || args.mcpBearerToken.length === 0 ||
        /[\x00-\x1f\x7f]/.test(args.mcpBearerToken)) {
      console.error('[mcp-proxy] MCP_BEARER_TOKEN is invalid (empty or contains control characters)');
      process.exit(1);
    }
    mcpBridgeSocketPath = args.mcpBridgeSocket;
    startMcpAuthProxy(args.mcpBridgePort, mcpBridgeSocketPath, args.mcpBearerToken);
  }

  const cleanup = () => {
    // Log final token summary
    const s = getTokenSummary();
    if (s.requests > 0) {
      console.log(`[tokens] Session total: ${s.total} tokens (${s.input} in + ${s.output} out) across ${s.requests} requests`);
    }
    auditLog({ event: 'proxy_stop', ...s });
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

  if (args.tokenLimit > 0) {
    console.log(`[tokens] Token budget: ${args.tokenLimit.toLocaleString()} tokens`);
  }
  if (args.auditLog) {
    console.log(`[audit] Logging to: ${args.auditLog}`);
  }

  console.log('[anthropic] Credential sources: CLAUDE_CREDENTIALS_FILE → macOS Keychain → ~/.claude/.credentials.json');
  console.log('[anthropic] Path allowlist:', ANTHROPIC_PATH_ALLOWLIST.toString());
}
