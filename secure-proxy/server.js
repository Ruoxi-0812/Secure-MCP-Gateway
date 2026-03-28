"use strict";

/**
 * S = Security Middleware
 */

const express = require("express");
const { spawn } = require("child_process");
const readline = require("readline");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const PORT = Number(process.env.SECURE_PROXY_PORT || 4000);
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "256kb";
const DOWNSTREAM_TIMEOUT_MS = Number(process.env.DOWNSTREAM_TIMEOUT_MS || 15000);

const ENABLE_TLS = process.env.ENABLE_TLS === "true";
const ENABLE_MTLS = process.env.ENABLE_MTLS === "true";

const TLS_CERT_PATH = process.env.TLS_CERT_PATH || path.join(__dirname, "certs", "server.crt");
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || path.join(__dirname, "certs", "server.key");
const TLS_CA_PATH = process.env.TLS_CA_PATH || path.join(__dirname, "certs", "ca.crt");

const AUTH_TS_WINDOW_SEC = Number(process.env.AUTH_TS_WINDOW_SEC || 60);
const NONCE_TTL_MS = Number(process.env.NONCE_TTL_MS || 60_000);
const MAX_NONCE_CACHE_SIZE = Number(process.env.MAX_NONCE_CACHE_SIZE || 50_000);

const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 5 * 60_000);
const READY_WINDOW_MS = Number(process.env.READY_WINDOW_MS || 60_000);
const MAX_OPS_PER_SESSION = Number(process.env.MAX_OPS_PER_SESSION || 10);
const MAX_SESSION_STORE_SIZE = Number(process.env.MAX_SESSION_STORE_SIZE || 20_000);
const PRUNE_INTERVAL_MS = Number(process.env.PRUNE_INTERVAL_MS || 30_000);

const MCP2_COMMAND = process.env.MCP2_COMMAND || process.execPath;
const MCP2_ARGS = process.env.MCP2_ARGS
  ? JSON.parse(process.env.MCP2_ARGS)
  : [
    path.join(__dirname, "..", "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js"),
    path.join(__dirname, "..", "workspace")
    ];

const MCP1_PUBLIC_KEY_PATH = process.env.MCP1_PUBLIC_KEY_PATH || "";
const CALLER_KEYS_CONFIG = process.env.CALLER_KEYS_CONFIG || path.join(__dirname, "caller_keys.json");

if (!MCP1_PUBLIC_KEY_PATH && !fs.existsSync(CALLER_KEYS_CONFIG)) {
  throw new Error("Provide MCP1_PUBLIC_KEY_PATH or caller_keys.json");
}

const RESERVED_TOOLS = new Set(["s.init", "s.ready"]);

const TOOL_POLICIES = {
  list_allowed_directories: {
    level: "metadata",
    safe: true,
  },

  // future extensible example:
  // read_file: {
  //   level: "read",
  //   safe: false,
  //   allowedRoots: ["/workspace/public"]
  // }
};

const ALLOWED_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "tools/list",
  "tools/call",
]);

function loadPublicKey(filePath) {
  return crypto.createPublicKey(fs.readFileSync(filePath, "utf8"));
}

function loadPublicKeysFromConfig(configPath) {
  const raw = fs.readFileSync(configPath, "utf8");
  const parsed = JSON.parse(raw);
  const out = {};
  for (const [callerId, keyPath] of Object.entries(parsed)) {
    out[String(callerId)] = loadPublicKey(path.resolve(__dirname, keyPath));
  }
  return out;
}

let PUBLIC_KEYS = {};
if (fs.existsSync(CALLER_KEYS_CONFIG)) {
  PUBLIC_KEYS = loadPublicKeysFromConfig(CALLER_KEYS_CONFIG);
} else if (MCP1_PUBLIC_KEY_PATH) {
  PUBLIC_KEYS.mcp1 = loadPublicKey(MCP1_PUBLIC_KEY_PATH);
}

function getPublicKey(callerId) {
  return PUBLIC_KEYS[String(callerId)] || null;
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

function canonicalJSONStringify(obj) {
  return JSON.stringify(canonicalize(obj));
}

function getCanonicalSignedPayload(bodyObj) {
  const cloned = JSON.parse(JSON.stringify(bodyObj || {}));
  if (cloned.auth && typeof cloned.auth === "object") {
    cloned.auth.signature = "";
  }
  return canonicalJSONStringify(cloned);
}

function verifyRequestSignature(bodyObj, publicKey, signatureB64) {
  try {
    const verifier = crypto.createVerify("sha256");
    verifier.update(getCanonicalSignedPayload(bodyObj));
    verifier.end();
    return verifier.verify(publicKey, Buffer.from(String(signatureB64), "base64"));
  } catch {
    return false;
  }
}

function verifyReadyProof(callerId, sid, challenge, publicKey, proofB64) {
  try {
    const verifier = crypto.createVerify("sha256");
    verifier.update(`${sid}|${challenge}|${callerId}`);
    verifier.end();
    return verifier.verify(publicKey, Buffer.from(String(proofB64), "base64"));
  } catch {
    return false;
  }
}

const nonceCache = new Map();
function pruneNonces(now = Date.now()) {
  for (const [k, exp] of nonceCache) {
    if (exp <= now) nonceCache.delete(k);
  }
  while (nonceCache.size > MAX_NONCE_CACHE_SIZE) {
    const firstKey = nonceCache.keys().next().value;
    if (!firstKey) break;
    nonceCache.delete(firstKey);
  }
}

function rememberNonce(callerId, nonce) {
  const now = Date.now();
  pruneNonces(now);
  const key = `${callerId}:${nonce}`;
  if (nonceCache.has(key)) return false;
  nonceCache.set(key, now + NONCE_TTL_MS);
  return true;
}

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

setInterval(() => {
  pruneNonces();
  pruneSessions();
}, PRUNE_INTERVAL_MS).unref();

function newSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function newChallenge() {
  return crypto.randomBytes(16).toString("hex");
}

function handleInit(callerId) {
  pruneSessions();
  const now = Date.now();
  const sid = newSessionId();
  const challenge = newChallenge();

  sessionStore.set(sid, {
    callerId,
    state: "new",
    challenge,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    opsLeft: MAX_OPS_PER_SESSION,
  });

  return {
    session_id: sid,
    challenge,
    ready_within_ms: READY_WINDOW_MS,
    ttl_ms: SESSION_TTL_MS,
  };
}

function handleReady(callerId, sid, proof) {
  pruneSessions();
  if (!sid) return { ok: false, reason: "missing_session_id" };

  const s = sessionStore.get(String(sid));
  if (!s) return { ok: false, reason: "unknown_session" };
  if (s.callerId !== callerId) return { ok: false, reason: "session_caller_mismatch" };
  if (s.state !== "new") return { ok: false, reason: "bad_session_state" };

  if (Date.now() - s.createdAt > READY_WINDOW_MS) {
    sessionStore.delete(String(sid));
    return { ok: false, reason: "ready_timeout" };
  }

  const publicKey = getPublicKey(callerId);
  if (!publicKey) return { ok: false, reason: "unknown_caller" };

  const ok = verifyReadyProof(callerId, String(sid), s.challenge, publicKey, proof);
  if (!ok) return { ok: false, reason: "bad_ready_proof" };

  s.state = "ready";
  s.challenge = "";
  return { ok: true };
}

function requireReadySession(callerId, sid) {
  pruneSessions();
  if (!sid) return { ok: false, reason: "missing_session_id" };

  const s = sessionStore.get(String(sid));
  if (!s) return { ok: false, reason: "unknown_session" };
  if (s.callerId !== callerId) return { ok: false, reason: "session_caller_mismatch" };
  if (s.state !== "ready") return { ok: false, reason: "bad_session_state" };
  if (s.opsLeft <= 0) return { ok: false, reason: "session_ops_exhausted" };

  return { ok: true, session: s };
}

function verifyAuth(body) {
  const auth = body?.auth;
  if (!auth || typeof auth !== "object") return { ok: false, reason: "missing_auth" };

  const { caller_id, timestamp, nonce, signature } = auth;
  if (!caller_id) return { ok: false, reason: "missing_caller_id" };
  if (timestamp === undefined || timestamp === null) return { ok: false, reason: "missing_timestamp" };
  if (!nonce) return { ok: false, reason: "missing_nonce" };
  if (!signature) return { ok: false, reason: "missing_signature" };

  const publicKey = getPublicKey(caller_id);
  if (!publicKey) return { ok: false, reason: "unknown_caller" };

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { ok: false, reason: "bad_timestamp" };

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > AUTH_TS_WINDOW_SEC) {
    return { ok: false, reason: "timestamp_out_of_window" };
  }

  if (!verifyRequestSignature(body, publicKey, signature)) {
    return { ok: false, reason: "bad_signature" };
  }

  if (!rememberNonce(String(caller_id), String(nonce))) {
    return { ok: false, reason: "replay_nonce_reused" };
  }

  return { ok: true, callerId: String(caller_id) };
}

function isToolInvocationAllowed(toolName) {
  const policy = TOOL_POLICIES[toolName];
  if (!policy) return false;          
  return policy.safe === true;        
}

function jsonRpcErrorObj(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function stripForDownstream(body) {
  const out = {
    jsonrpc: body?.jsonrpc || "2.0",
    method: body?.method,
  };
  if (body?.id !== undefined) out.id = body.id;
  if (body?.params !== undefined) out.params = body.params;
  return out;
}

let mcp2Proc = null;
let mcp2Rl = null;
const pending = new Map();
let downstreamInitialized = false;

function startMcp2() {
  if (mcp2Proc) return;

  mcp2Proc = spawn(MCP2_COMMAND, MCP2_ARGS, {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, MCP_TRANSPORT: "stdio" },
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
    try {
      msg = JSON.parse(trimmed);
    } catch {
      return;
    }

    if (msg.id !== undefined && msg.id !== null) {
      const key = String(msg.id);
      const p = pending.get(key);
      if (p) {
        clearTimeout(p.timer);
        pending.delete(key);
        p.resolve(msg);
      }
    }
  });
}

function writeToMcp2(msg, timeoutMs = DOWNSTREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    startMcp2();
    if (!mcp2Proc || !mcp2Proc.stdin) return reject(new Error("downstream not running"));

    const id = msg.id;
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
    jsonrpc: "2.0",
    id: "downstream-init",
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "secure-gateway", version: "1.0.0" },
    },
  });

  await writeToMcp2({
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
  });

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
      tools: tools.filter((tool) => {
        const name = String(tool?.name || "");
        return TOOL_POLICIES[name]?.safe === true;
      }),
    },
  };
}

const app = express();
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/rpc", async (req, res) => {
  const body = req.body || {};
  const toolName = String(body?.params?.name || "");

  if (!ALLOWED_METHODS.has(body.method)) {
    return res.status(403).json(jsonRpcErrorObj(body.id, 403, "not_allowed_method"));
  }

  if (ENABLE_TLS) {
    const tlsSocket = req.socket;
    if (!tlsSocket?.encrypted) {
      return res.status(400).json(jsonRpcErrorObj(body.id, 400, "tls_required"));
    }
    if (ENABLE_MTLS && !tlsSocket.authorized) {
      return res.status(401).json(jsonRpcErrorObj(body.id, 401, "client_cert_required"));
    }
  }

  const authResult = verifyAuth(body);
  if (!authResult.ok) {
    return res.status(403).json(jsonRpcErrorObj(body.id, 403, authResult.reason));
  }
  const callerId = authResult.callerId;

  if (ENABLE_MTLS) {
    const cert = req.socket.getPeerCertificate?.();
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

  if (body.method === "tools/call" && RESERVED_TOOLS.has(toolName)) {
    if (toolName === "s.init") {
      return res.json({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: { status: "ok", ...handleInit(callerId) },
      });
    }

    if (toolName === "s.ready") {
      const sid = body.auth?.session_id;
      const proof = body?.params?.arguments?.proof;
      const ready = handleReady(callerId, sid, proof);
      if (!ready.ok) {
        return res.status(403).json(jsonRpcErrorObj(body.id, 403, ready.reason));
      }
      return res.json({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: { status: "ok", session_id: String(sid) },
      });
    }
  }

  if (body.method === "tools/call") {
    const sessionCheck = requireReadySession(callerId, body.auth?.session_id);
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
    console.log(`Allowed tools: ${Object.keys(TOOL_POLICIES).join(", ")}`);
    console.log(`TLS: ${ENABLE_TLS ? "ON" : "OFF"}`);
    console.log(`mTLS: ${ENABLE_MTLS ? "ON" : "OFF"}`);
  };

  if (!ENABLE_TLS) {
    const server = http.createServer(app);
    server.listen(PORT, () => {
      logBanner();
      startMcp2();
    });
    return;
  }

  const tlsOptions = {
    cert: fs.readFileSync(TLS_CERT_PATH),
    key: fs.readFileSync(TLS_KEY_PATH),
    ca: fs.readFileSync(TLS_CA_PATH),
    requestCert: ENABLE_MTLS,
    rejectUnauthorized: ENABLE_MTLS,
  };

  const server = https.createServer(tlsOptions, app);
  server.listen(PORT, () => {
    logBanner();
    startMcp2();
  });
}

function shutdown() {
  for (const [id, p] of pending) {
    clearTimeout(p.timer);
    p.reject(new Error("shutdown"));
    pending.delete(id);
  }
  try { if (mcp2Rl) mcp2Rl.close(); } catch {}
  try { if (mcp2Proc) mcp2Proc.kill("SIGTERM"); } catch {}
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

startServer();