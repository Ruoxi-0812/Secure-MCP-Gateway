"use strict";

/**
 * S = Security Gateway (enforcement proxy)
 *
 * Cryptographic trust decisions (signature verification, nonce deduplication,
 * key management) are delegated to the remote Auth Server.  This process owns
 * only the enforcement layers: method allowlist, TLS, session state, and ACL.
 */

const express = require("express");
const { spawn } = require("child_process");
const readline = require("readline");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const PORT                = Number(process.env.SECURE_PROXY_PORT  || 4000);
const JSON_BODY_LIMIT     = process.env.JSON_BODY_LIMIT            || "256kb";
const DOWNSTREAM_TIMEOUT_MS = Number(process.env.DOWNSTREAM_TIMEOUT_MS || 15000);

const ENABLE_TLS  = process.env.ENABLE_TLS  === "true";
const ENABLE_MTLS = process.env.ENABLE_MTLS === "true";

const TLS_CERT_PATH = process.env.TLS_CERT_PATH || path.join(__dirname, "certs", "server.crt");
const TLS_KEY_PATH  = process.env.TLS_KEY_PATH  || path.join(__dirname, "certs", "server.key");
const TLS_CA_PATH   = process.env.TLS_CA_PATH   || path.join(__dirname, "certs", "ca.crt");

const AUTH_SERVER_URL   = process.env.AUTH_SERVER_URL   || "http://127.0.0.1:4001";
const GATEWAY_AUTH_TOKEN = process.env.GATEWAY_AUTH_TOKEN || "dev-gateway-token";
const AUTH_HTTP_AGENT = new http.Agent({
  keepAlive: true,
  maxSockets: Number(process.env.AUTH_MAX_SOCKETS || 64),
});

const SESSION_TTL_MS        = Number(process.env.SESSION_TTL_MS        || 5 * 60_000);
const READY_WINDOW_MS       = Number(process.env.READY_WINDOW_MS       || 60_000);
const MAX_OPS_PER_SESSION   = Number(process.env.MAX_OPS_PER_SESSION   || 10);
const MAX_SESSION_STORE_SIZE = Number(process.env.MAX_SESSION_STORE_SIZE || 20_000);
const MAX_SESSION_NONCES    = Number(process.env.MAX_SESSION_NONCES    || 10_000);
const MAC_TS_WINDOW_SEC     = Number(process.env.MAC_TS_WINDOW_SEC     || 60);
const PRUNE_INTERVAL_MS     = Number(process.env.PRUNE_INTERVAL_MS     || 30_000);

const MCP2_COMMAND = process.env.MCP2_COMMAND || process.execPath;
const MCP2_ARGS    = process.env.MCP2_ARGS
  ? JSON.parse(process.env.MCP2_ARGS)
  : [
      path.join(__dirname, "..", "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js"),
      path.join(__dirname, "..", "workspace"),
    ];

const RESERVED_TOOLS = new Set(["s.init", "s.ready"]);

const TOOL_POLICIES = {
  list_allowed_directories: { level: "metadata", safe: true },
};

const ALLOWED_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "tools/list",
  "tools/call",
]);

function remotePost(endpoint, body) {
  return new Promise((resolve) => {
    const url     = new URL(AUTH_SERVER_URL);
    const payload = Buffer.from(JSON.stringify(body), "utf8");

    const req = http.request(
      {
        hostname: url.hostname,
        port:     Number(url.port) || 4001,
        path:     endpoint,
        method:   "POST",
        agent:    AUTH_HTTP_AGENT,
        headers:  {
          "Content-Type":     "application/json",
          "Content-Length":   payload.length,
          "x-gateway-token":  GATEWAY_AUTH_TOKEN,
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve({ valid: false, reason: "auth_server_parse_error" }); }
        });
      }
    );

    req.on("error", (e) =>
      resolve({ valid: false, reason: `auth_server_unreachable:${e.message}` })
    );
    req.write(payload);
    req.end();
  });
}

function callRemoteAuth(body) {
  return remotePost("/verify", body);
}

function callRemoteVerifyProof(callerId, sid, challenge, proof) {
  return remotePost("/verify-proof", {
    caller_id:  callerId,
    session_id: sid,
    challenge,
    proof,
  });
}

function callRemoteWrapKey(callerId, macKey) {
  return remotePost("/wrap-key", {
    caller_id: callerId,
    mac_key: macKey,
  });
}

// ── Session management ────────────────────────────────────────────────────────

const sessionStore = new Map();

function pruneSessions(now = Date.now()) {
  for (const [sid, s] of sessionStore) {
    if (s.expiresAt <= now) sessionStore.delete(sid);
  }
  while (sessionStore.size > MAX_SESSION_STORE_SIZE) {
    const firstKey = sessionStore.keys().next().value;
    if (!firstKey) break;
    sessionStore.delete(firstKey);
  }
}

setInterval(() => pruneSessions(), PRUNE_INTERVAL_MS).unref();

function newSessionId() { return crypto.randomBytes(16).toString("hex"); }
function newChallenge()  { return crypto.randomBytes(16).toString("hex"); }
function newMacKey()     { return crypto.randomBytes(32).toString("base64"); }

function handleInit(callerId) {
  pruneSessions();
  const now       = Date.now();
  const sid       = newSessionId();
  const challenge = newChallenge();

  sessionStore.set(sid, {
    callerId,
    state:     "new",
    challenge,
    macKey:    null,
    macNonces: new Map(),
    nextNoncePruneAt: now + MAC_TS_WINDOW_SEC * 1000,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    opsLeft:   MAX_OPS_PER_SESSION,
  });

  return { session_id: sid, challenge, ready_within_ms: READY_WINDOW_MS, ttl_ms: SESSION_TTL_MS };
}

async function handleReady(callerId, sid, proof) {
  pruneSessions();
  if (!sid) return { ok: false, reason: "missing_session_id" };

  const s = sessionStore.get(String(sid));
  if (!s)                       return { ok: false, reason: "unknown_session" };
  if (s.callerId !== callerId)  return { ok: false, reason: "session_caller_mismatch" };
  if (s.state !== "new")        return { ok: false, reason: "bad_session_state" };

  if (Date.now() - s.createdAt > READY_WINDOW_MS) {
    sessionStore.delete(String(sid));
    return { ok: false, reason: "ready_timeout" };
  }

  const result = await callRemoteVerifyProof(callerId, String(sid), s.challenge, proof);
  if (!result.valid) return { ok: false, reason: result.reason || "bad_ready_proof" };

  s.state     = "ready";
  s.challenge = "";
  s.macKey    = newMacKey();
  const wrapped = await callRemoteWrapKey(callerId, s.macKey);
  if (!wrapped.valid) {
    s.state = "new";
    s.macKey = null;
    return { ok: false, reason: wrapped.reason || "key_wrap_failed" };
  }
  return { ok: true, wrapped_mac_key: wrapped.wrapped_key };
}

function requireReadySession(callerId, sid) {
  if (!sid) return { ok: false, reason: "missing_session_id" };

  const s = sessionStore.get(String(sid));
  if (!s)                       return { ok: false, reason: "unknown_session" };
  if (s.expiresAt <= Date.now()) {
    sessionStore.delete(String(sid));
    return { ok: false, reason: "unknown_session" };
  }
  if (s.callerId !== callerId)  return { ok: false, reason: "session_caller_mismatch" };
  if (s.state !== "ready")      return { ok: false, reason: "bad_session_state" };
  if (s.opsLeft <= 0)           return { ok: false, reason: "session_ops_exhausted" };

  return { ok: true, session: s };
}

function canonicalize(v) {
  if (v === null || v === undefined) return v;
  if (Array.isArray(v)) return v.map(canonicalize);
  if (typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
    return out;
  }
  return v;
}

function getCanonicalMacPayload(bodyObj) {
  const cloned = JSON.parse(JSON.stringify(bodyObj || {}));
  if (cloned.auth && typeof cloned.auth === "object") {
    cloned.auth.mac = "";
    cloned.auth.signature = "";
  }
  return JSON.stringify(canonicalize(cloned));
}

function verifyHmac(bodyObj, keyB64, macHex) {
  try {
    const expected = crypto
      .createHmac("sha256", Buffer.from(String(keyB64), "base64"))
      .update(getCanonicalMacPayload(bodyObj))
      .digest();
    const actual = Buffer.from(String(macHex), "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function rememberSessionNonce(session, nonce) {
  const now = Date.now();
  if (now >= session.nextNoncePruneAt || session.macNonces.size >= MAX_SESSION_NONCES) {
    for (const [k, exp] of session.macNonces) {
      if (exp <= now) session.macNonces.delete(k);
    }
    session.nextNoncePruneAt = now + MAC_TS_WINDOW_SEC * 1000;
  }
  if (session.macNonces.has(nonce)) return false;
  while (session.macNonces.size >= MAX_SESSION_NONCES) {
    const firstKey = session.macNonces.keys().next().value;
    if (!firstKey) break;
    session.macNonces.delete(firstKey);
  }
  session.macNonces.set(nonce, now + MAC_TS_WINDOW_SEC * 1000);
  return true;
}

function verifySessionMacAuth(body) {
  const auth = body?.auth;
  if (!auth || typeof auth !== "object") return { valid: false, reason: "missing_auth" };

  const { caller_id, timestamp, nonce, session_id, mac } = auth;
  if (!caller_id) return { valid: false, reason: "missing_caller_id" };
  if (timestamp === undefined || timestamp === null) return { valid: false, reason: "missing_timestamp" };
  if (!nonce) return { valid: false, reason: "missing_nonce" };
  if (!session_id) return { valid: false, reason: "missing_session_id" };
  if (!mac) return { valid: false, reason: "missing_mac" };

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { valid: false, reason: "bad_timestamp" };
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > MAC_TS_WINDOW_SEC) {
    return { valid: false, reason: "timestamp_out_of_window" };
  }

  const sessionCheck = requireReadySession(String(caller_id), String(session_id));
  if (!sessionCheck.ok) return { valid: false, reason: sessionCheck.reason };
  const session = sessionCheck.session;
  if (!session.macKey) return { valid: false, reason: "missing_session_mac_key" };

  if (!verifyHmac(body, session.macKey, String(mac))) {
    return { valid: false, reason: "bad_mac" };
  }
  if (!rememberSessionNonce(session, String(nonce))) {
    return { valid: false, reason: "replay_nonce_reused" };
  }

  return { valid: true, caller_id: String(caller_id), session };
}

function isToolInvocationAllowed(toolName) {
  const policy = TOOL_POLICIES[toolName];
  return policy?.safe === true;
}

function jsonRpcErrorObj(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function stripForDownstream(body) {
  const out = { jsonrpc: body?.jsonrpc || "2.0", method: body?.method };
  if (body?.id !== undefined)     out.id     = body.id;
  if (body?.params !== undefined) out.params = body.params;
  return out;
}

let mcp2Proc = null;
let mcp2Rl   = null;
const pending = new Map();
let downstreamInitialized = false;

function startMcp2() {
  if (mcp2Proc) return;

  mcp2Proc = spawn(MCP2_COMMAND, MCP2_ARGS, {
    stdio: ["pipe", "pipe", "pipe"],
    env:   { ...process.env, MCP_TRANSPORT: "stdio" },
  });

  mcp2Proc.on("exit", (code, signal) => {
    for (const [id, p] of pending) {
      clearTimeout(p.timer);
      p.reject(new Error(`downstream exited (code=${code}, signal=${signal})`));
      pending.delete(id);
    }
    try { if (mcp2Rl) mcp2Rl.close(); } catch {}
    mcp2Rl = null;
    mcp2Proc = null;
    downstreamInitialized = false;
  });

  mcp2Proc.stderr.on("data", (chunk) => {
    process.stderr.write(`[mcp2 stderr] ${chunk.toString("utf8")}`);
  });

  mcp2Rl = readline.createInterface({ input: mcp2Proc.stdout, crlfDelay: Infinity });
  mcp2Rl.on("line", (line) => {
    const trimmed = String(line).trim();
    if (!trimmed) return;
    let msg;
    try { msg = JSON.parse(trimmed); } catch { return; }
    if (msg.id !== undefined && msg.id !== null) {
      const key = String(msg.id);
      const p   = pending.get(key);
      if (p) { clearTimeout(p.timer); pending.delete(key); p.resolve(msg); }
    }
  });
}

function writeToMcp2(msg, timeoutMs = DOWNSTREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    startMcp2();
    if (!mcp2Proc || !mcp2Proc.stdin) return reject(new Error("downstream not running"));

    const id    = msg.id;
    const hasId = id !== undefined && id !== null;

    if (!hasId) {
      mcp2Proc.stdin.write(JSON.stringify(msg) + "\n");
      return resolve({ ok: true });
    }

    const key = String(id);
    if (pending.has(key)) return reject(new Error("duplicate in-flight id"));

    const timer = setTimeout(() => {
      pending.delete(key);
      reject(new Error("downstream timeout"));
    }, timeoutMs);

    pending.set(key, { resolve, reject, timer });
    mcp2Proc.stdin.write(JSON.stringify(msg) + "\n");
  });
}

async function initializeDownstreamIfNeeded() {
  if (downstreamInitialized) return;
  await writeToMcp2({
    jsonrpc: "2.0", id: "downstream-init", method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "secure-gateway", version: "1.0.0" } },
  });
  await writeToMcp2({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
  downstreamInitialized = true;
}

async function forwardToMcp2(body) {
  await initializeDownstreamIfNeeded();
  return writeToMcp2(stripForDownstream(body));
}

function filterToolsListResponse(resp) {
  if (!resp || typeof resp !== "object") return resp;
  const tools = resp?.result?.tools;
  if (!Array.isArray(tools)) return resp;
  return {
    ...resp,
    result: {
      ...resp.result,
      tools: tools.filter((t) => TOOL_POLICIES[String(t?.name || "")]?.safe === true),
    },
  };
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.get("/health",  (_req, res) => res.json({ ok: true }));
app.get("/metrics", (_req, res) => res.json({
  memory: process.memoryUsage(), cpu: process.cpuUsage(), uptime: process.uptime(),
}));

/**
 * Single entry point for all MCP JSON-RPC traffic.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ Layer 1 — Method allowlist                                          │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ Layer 2 — Transport security (TLS / mTLS)                          │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ Layer 3 — Cryptographic identity                                  │
 * │   Session setup uses RSA-SHA256 via Auth Server. Ready sessions    │
 * │   may use a cheaper session-bound MAC for subsequent tool calls.   │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ Layer 4 — mTLS CN binding (optional)                               │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ Layer 5 — Session state machine + ACL                              │
 * └─────────────────────────────────────────────────────────────────────┘
 */
app.post("/rpc", async (req, res) => {
  const body     = req.body || {};
  const toolName = String(body?.params?.name || "");

  // Layer 1 — Method allowlist
  if (!ALLOWED_METHODS.has(body.method)) {
    return res.status(403).json(jsonRpcErrorObj(body.id, 403, "not_allowed_method"));
  }

  // Layer 2 — TLS / mTLS
  if (ENABLE_TLS) {
    const tlsSocket = req.socket;
    if (!tlsSocket?.encrypted) {
      return res.status(400).json(jsonRpcErrorObj(body.id, 400, "tls_required"));
    }
    if (ENABLE_MTLS && !tlsSocket.authorized) {
      return res.status(401).json(jsonRpcErrorObj(body.id, 401, "client_cert_required"));
    }
  }

  // Layer 3 — Cryptographic identity.
  const wantsSessionMac =
    body.method === "tools/call" &&
    !RESERVED_TOOLS.has(toolName) &&
    body?.auth?.mac;
  const authResult = wantsSessionMac
    ? verifySessionMacAuth(body)
    : await callRemoteAuth(body);
  if (!authResult.valid) {
    return res.status(403).json(jsonRpcErrorObj(body.id, 403, authResult.reason));
  }
  const callerId = authResult.caller_id;

  // Layer 4 — mTLS CN binding
  if (ENABLE_MTLS) {
    const cert   = req.socket.getPeerCertificate?.();
    const certCn = cert?.subject?.CN;
    if (!certCn) {
      return res.status(401).json(jsonRpcErrorObj(body.id, 401, "client_cert_missing_cn"));
    }
    if (certCn !== callerId) {
      return res.status(403).json(jsonRpcErrorObj(body.id, 403, "tls_identity_mismatch"));
    }
  }

  if (body.method === "tools/list") {
    try {
      const resp = await forwardToMcp2(body);
      return res.json(filterToolsListResponse(resp));
    } catch (e) {
      return res.status(502).json(jsonRpcErrorObj(body.id, 502, `downstream_error:${e.message}`));
    }
  }

  // Layer 5 — Session state machine + ACL
  if (body.method === "tools/call" && RESERVED_TOOLS.has(toolName)) {
    if (toolName === "s.init") {
      return res.json({
        jsonrpc: "2.0", id: body.id ?? null,
        result: { status: "ok", ...handleInit(callerId) },
      });
    }

    if (toolName === "s.ready") {
      const sid   = body.auth?.session_id;
      const proof = body?.params?.arguments?.proof;
      const ready = await handleReady(callerId, sid, proof);
      if (!ready.ok) {
        return res.status(403).json(jsonRpcErrorObj(body.id, 403, ready.reason));
      }
      return res.json({
        jsonrpc: "2.0", id: body.id ?? null,
        result: { status: "ok", session_id: String(sid), wrapped_mac_key: ready.wrapped_mac_key },
      });
    }
  }

  if (body.method === "tools/call") {
    const sessionCheck = authResult.session
      ? { ok: true, session: authResult.session }
      : requireReadySession(callerId, body.auth?.session_id);
    if (!sessionCheck.ok) {
      return res.status(403).json(jsonRpcErrorObj(body.id, 403, sessionCheck.reason));
    }
    if (!isToolInvocationAllowed(toolName)) {
      return res.status(403).json(jsonRpcErrorObj(body.id, 403, "tool_not_allowed"));
    }
    sessionCheck.session.opsLeft -= 1;
  }

  try {
    const resp = await forwardToMcp2(body);
    return res.json(resp);
  } catch (e) {
    return res.status(502).json(jsonRpcErrorObj(body.id, 502, `downstream_error:${e.message}`));
  }
});

function startServer() {
  const logBanner = () => {
    const scheme = ENABLE_TLS ? "https" : "http";
    console.log(`S listening on ${scheme}://127.0.0.1:${PORT}/rpc`);
    console.log(`Auth Server:   ${AUTH_SERVER_URL}`);
    console.log(`Allowed tools: ${Object.keys(TOOL_POLICIES).join(", ")}`);
    console.log(`TLS: ${ENABLE_TLS ? "ON" : "OFF"}   mTLS: ${ENABLE_MTLS ? "ON" : "OFF"}`);
  };

  if (!ENABLE_TLS) {
    http.createServer(app).listen(PORT, () => { logBanner(); startMcp2(); });
    return;
  }

  const tlsOptions = {
    cert: fs.readFileSync(TLS_CERT_PATH),
    key:  fs.readFileSync(TLS_KEY_PATH),
    ca:   fs.readFileSync(TLS_CA_PATH),
    requestCert:       ENABLE_MTLS,
    rejectUnauthorized: ENABLE_MTLS,
  };
  https.createServer(tlsOptions, app).listen(PORT, () => { logBanner(); startMcp2(); });
}

function shutdown() {
  for (const [id, p] of pending) {
    clearTimeout(p.timer);
    p.reject(new Error("shutdown"));
    pending.delete(id);
  }
  try { if (mcp2Rl)   mcp2Rl.close();          } catch {}
  try { if (mcp2Proc) mcp2Proc.kill("SIGTERM"); } catch {}
  process.exit(0);
}

process.on("SIGINT",  shutdown);
process.on("SIGTERM", shutdown);

startServer();
