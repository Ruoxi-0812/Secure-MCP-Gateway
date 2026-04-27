"use strict";

/**
 * Remote Auth Server — trust anchor for the Secure MCP Gateway.
 *
 * Owns all cryptographic verification: public-key registry, RSA-SHA256
 * signature checks, timestamp window, nonce deduplication, and session-ready
 * proof verification.  The local Gateway (secure-proxy/server.js) delegates
 * every auth decision here; it only enforces the result.
 *
 * Endpoints
 *   POST /verify        — per-request auth (sig + timestamp + nonce)
 *   POST /verify-proof  — s.ready challenge-response proof
 *   GET  /health        — liveness check (no token required)
 *
 * Security: every request (except /health) must carry the shared
 * X-Gateway-Token header.  In production replace the default with a strong
 * secret and rotate it regularly.
 */

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");
const http    = require("http");

const PORT              = Number(process.env.AUTH_SERVER_PORT  || 4001);
const GATEWAY_TOKEN     = process.env.GATEWAY_AUTH_TOKEN       || "dev-gateway-token";
const CALLER_KEYS_CONFIG = process.env.CALLER_KEYS_CONFIG      ||
  path.join(__dirname, "..", "secure-proxy", "caller_keys.json");

const AUTH_TS_WINDOW_SEC   = Number(process.env.AUTH_TS_WINDOW_SEC   || 60);
const NONCE_TTL_MS         = Number(process.env.NONCE_TTL_MS         || 60_000);
const MAX_NONCE_CACHE_SIZE = Number(process.env.MAX_NONCE_CACHE_SIZE  || 50_000);
const PRUNE_INTERVAL_MS    = Number(process.env.PRUNE_INTERVAL_MS    || 30_000);

// ── Key management ────────────────────────────────────────────────────────────

function loadPublicKey(filePath) {
  return crypto.createPublicKey(fs.readFileSync(filePath, "utf8"));
}

function loadPublicKeysFromConfig(configPath) {
  const raw    = fs.readFileSync(configPath, "utf8");
  const parsed = JSON.parse(raw);
  const out    = {};
  for (const [callerId, keyPath] of Object.entries(parsed)) {
    out[String(callerId)] = loadPublicKey(
      path.resolve(path.dirname(configPath), keyPath)
    );
  }
  return out;
}

let PUBLIC_KEYS = {};

function reloadKeys() {
  try {
    PUBLIC_KEYS = loadPublicKeysFromConfig(CALLER_KEYS_CONFIG);
    console.log(
      `[auth] Loaded ${Object.keys(PUBLIC_KEYS).length} caller(s): ` +
      Object.keys(PUBLIC_KEYS).join(", ")
    );
  } catch (e) {
    console.error(`[auth] Key reload failed — keeping previous keys: ${e.message}`);
  }
}

reloadKeys();

fs.watch(CALLER_KEYS_CONFIG, (eventType) => {
  if (eventType === "change") {
    console.log("[auth] caller_keys.json changed — reloading...");
    reloadKeys();
  }
});

// ── Nonce cache ───────────────────────────────────────────────────────────────

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

setInterval(() => pruneNonces(), PRUNE_INTERVAL_MS).unref();

// ── Crypto helpers ────────────────────────────────────────────────────────────

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

function getCanonicalSignedPayload(bodyObj) {
  const cloned = JSON.parse(JSON.stringify(bodyObj || {}));
  if (cloned.auth && typeof cloned.auth === "object") cloned.auth.signature = "";
  return JSON.stringify(canonicalize(cloned));
}

function verifySignature(bodyObj, publicKey, signatureB64) {
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

// ── Verification logic ────────────────────────────────────────────────────────

function verifyAuth(body) {
  const auth = body?.auth;
  if (!auth || typeof auth !== "object") return { valid: false, reason: "missing_auth" };

  const { caller_id, timestamp, nonce, signature } = auth;
  if (!caller_id)                                  return { valid: false, reason: "missing_caller_id" };
  if (timestamp === undefined || timestamp === null) return { valid: false, reason: "missing_timestamp" };
  if (!nonce)                                       return { valid: false, reason: "missing_nonce" };
  if (!signature)                                   return { valid: false, reason: "missing_signature" };

  const publicKey = PUBLIC_KEYS[String(caller_id)];
  if (!publicKey) return { valid: false, reason: "unknown_caller" };

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { valid: false, reason: "bad_timestamp" };

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > AUTH_TS_WINDOW_SEC)
    return { valid: false, reason: "timestamp_out_of_window" };

  if (!verifySignature(body, publicKey, signature))
    return { valid: false, reason: "bad_signature" };

  if (!rememberNonce(String(caller_id), String(nonce)))
    return { valid: false, reason: "replay_nonce_reused" };

  return { valid: true, caller_id: String(caller_id) };
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: "256kb" }));

app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (req.headers["x-gateway-token"] !== GATEWAY_TOKEN) {
    return res.status(401).json({ valid: false, reason: "unauthorized_gateway" });
  }
  next();
});

app.post("/verify", (req, res) => {
  res.json(verifyAuth(req.body));
});

app.post("/verify-proof", (req, res) => {
  const { caller_id, session_id, challenge, proof } = req.body || {};
  if (!caller_id || !session_id || !challenge || !proof) {
    return res.status(400).json({ valid: false, reason: "missing_fields" });
  }
  const publicKey = PUBLIC_KEYS[String(caller_id)];
  if (!publicKey) return res.json({ valid: false, reason: "unknown_caller" });

  const ok = verifyReadyProof(
    String(caller_id), String(session_id), String(challenge), publicKey, String(proof)
  );
  res.json({ valid: ok, reason: ok ? null : "bad_ready_proof" });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

http.createServer(app).listen(PORT, () => {
  console.log(`[auth] Auth Server listening on http://127.0.0.1:${PORT}`);
  console.log(`[auth] CALLER_KEYS_CONFIG: ${CALLER_KEYS_CONFIG}`);
});
