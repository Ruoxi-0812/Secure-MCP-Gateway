"use strict";

/**
 * Protected attack tests — Gateway (S) deployed.
 *
 * Each test sends the same attack that succeeds in the baseline and verifies
 * that S detects and blocks it before it reaches MCP2.
 *
 * ┌────┬──────────────────────────┬─────────────────────┬──────────────────────────────────────┐
 * │ #  │ Attack                   │ Test case(s)        │ S response                           │
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 1  │ Impersonation            │ unknowncaller        │ 403 unknown_caller                   │
 * │    │                          │ noauth               │ 403 missing_auth                     │
 * │    │                          │ missing_caller_id    │ 403 missing_caller_id                │
 * │    │                          │ missing_timestamp    │ 403 missing_timestamp                │
 * │    │                          │ missing_nonce        │ 403 missing_nonce                    │
 * │    │                          │ missing_signature    │ 403 missing_signature                │
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 2  │ Replay                   │ replay               │ 403 replay_nonce_reused              │
 * │    │                          │ oldts                │ 403 timestamp_out_of_window          │
 * │    │                          │ futurets             │ 403 timestamp_out_of_window          │
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 3  │ Tampering                │ badsig               │ 403 bad_signature                    │
 * │    │                          │ tamper_method        │ 403 bad_signature (method rewritten) │
 * │    │                          │ tamper_auth          │ 403 bad_signature (auth nonce changed)│
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 4  │ Session Hijacking        │ bypass               │ 403 missing_session_id               │
 * │    │                          │ session_mismatch     │ 403 session_caller_mismatch          │
 * │    │                          │ badready             │ 403 bad_ready_proof                  │
 * │    │                          │ readytimeout         │ 403 ready_timeout                    │
 * │    │                          │ quota                │ 403 session_ops_exhausted            │
 * │    │                          │ unknown_session      │ 403 unknown_session                  │
 * │    │                          │ double_ready         │ 403 bad_session_state                │
 * │    │                          │ not_ready_session    │ 403 bad_session_state                │
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 5  │ Unauthorized Tool Access │ acldeny              │ 403 tool_not_allowed                 │
 * │    │                          │ listfilter           │ 200 (forbidden tools hidden)         │
 * │    │                          │ write_file_denied    │ 403 tool_not_allowed                 │
 * │    │                          │ allowed_tool         │ 200 (positive — whitelisted tool OK) │
 * │    │                          │ unknown_method       │ 403 not_allowed_method (Layer 1)     │
 * ├────┼──────────────────────────┼─────────────────────┼──────────────────────────────────────┤
 * │ 6  │ MITM                     │ (mitm_protected)     │ TLS blocks interception entirely     │
 * └────┴──────────────────────────┴─────────────────────┴──────────────────────────────────────┘
 *
 * Usage:  node tests/protected_attacks.js <test>
 * Tests:  unknowncaller | noauth | missing_caller_id | missing_timestamp |
 *         missing_nonce | missing_signature |
 *         replay | oldts | futurets |
 *         badsig | tamper_method | tamper_auth |
 *         bypass | session_mismatch | badready | readytimeout | quota |
 *         unknown_session | double_ready | not_ready_session |
 *         acldeny | listfilter | write_file_denied | allowed_tool |
 *         unknown_method | demo
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

// ── Logging ───────────────────────────────────────────────────────────────────
(function setupLog() {
  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `protected_attacks_${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const stream = fs.createWriteStream(file, { flags: "a" });
  for (const m of ["log", "warn", "error"]) {
    const orig = console[m].bind(console);
    const prefix = m === "error" ? "[ERROR] " : m === "warn" ? "[WARN] " : "";
    console[m] = (...a) => { const s = a.join(" "); orig(s); stream.write(prefix + s + "\n"); };
  }
})();
// ─────────────────────────────────────────────────────────────────────────────

const S_URL = process.env.S_URL || "http://127.0.0.1:4000/rpc";
const CALLER_ID = process.env.CALLER_ID || "mcp1";
const MCP1_PRIVATE_KEY_PATH = process.env.MCP1_PRIVATE_KEY_PATH || "";
const HIJACK_PRIVATE_KEY_PATH = process.env.HIJACK_PRIVATE_KEY_PATH || "";
const TLS_CA_PATH = process.env.TLS_CA_PATH || "";
const ENABLE_MTLS = process.env.ENABLE_MTLS === "true";
const TLS_CLIENT_CERT = process.env.TLS_CLIENT_CERT || "";
const TLS_CLIENT_KEY = process.env.TLS_CLIENT_KEY || "";
const SECRET_PATH = process.env.SECRET_PATH || path.join(__dirname, "..", "workspace", "sandbox", "secret.txt");

let PRIVATE_KEY = null;
let HIJACK_PRIVATE_KEY = null;

if (MCP1_PRIVATE_KEY_PATH) {
  PRIVATE_KEY = fs.readFileSync(MCP1_PRIVATE_KEY_PATH, "utf8");
}
if (HIJACK_PRIVATE_KEY_PATH) {
  HIJACK_PRIVATE_KEY = fs.readFileSync(HIJACK_PRIVATE_KEY_PATH, "utf8");
}

function die(msg) {
  console.error(msg);
  process.exit(1);
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
  const cloned = JSON.parse(JSON.stringify(bodyObj));
  if (cloned.auth && typeof cloned.auth === "object") cloned.auth.signature = "";
  return canonicalJSONStringify(cloned);
}

function signRequest(bodyObj, privateKey = PRIVATE_KEY) {
  if (!privateKey) die("private key is required.");
  const signer = crypto.createSign("sha256");
  signer.update(getCanonicalSignedPayload(bodyObj));
  signer.end();
  return signer.sign(privateKey).toString("base64");
}

function signReadyProof(sid, challenge, callerId = CALLER_ID, privateKey = PRIVATE_KEY) {
  if (!privateKey) die("private key is required.");
  const signer = crypto.createSign("sha256");
  signer.update(`${sid}|${challenge}|${callerId}`);
  signer.end();
  return signer.sign(privateKey).toString("base64");
}

function randNonce() {
  return crypto.randomBytes(12).toString("hex");
}

function nowSec(offsetSec = 0) {
  return Math.floor(Date.now() / 1000) + offsetSec;
}

function makeAuth({ callerId = CALLER_ID, timestamp = nowSec(), nonce = randNonce(), session_id } = {}) {
  const auth = {
    caller_id: callerId,
    timestamp,
    nonce,
    signature: "",
  };
  if (session_id !== undefined) auth.session_id = String(session_id);
  return auth;
}

function jsonRpc(id, method, params, auth) {
  return { jsonrpc: "2.0", id, method, params, auth };
}

function parseUrl(u) {
  const url = new URL(u);
  const isHttps = url.protocol === "https:";
  return {
    isHttps,
    hostname: url.hostname,
    port: url.port ? Number(url.port) : isHttps ? 443 : 80,
    path: url.pathname + (url.search || ""),
  };
}

function buildTlsOptions(isHttps) {
  if (!isHttps) return {};
  const out = { rejectUnauthorized: true };
  if (TLS_CA_PATH) out.ca = fs.readFileSync(TLS_CA_PATH);
  if (ENABLE_MTLS) {
    if (!TLS_CLIENT_CERT || !TLS_CLIENT_KEY) {
      die("ENABLE_MTLS=true but TLS_CLIENT_CERT / TLS_CLIENT_KEY missing");
    }
    out.cert = fs.readFileSync(TLS_CLIENT_CERT);
    out.key = fs.readFileSync(TLS_CLIENT_KEY);
  }
  return out;
}

async function postJson(urlStr, bodyObj) {
  const { isHttps, hostname, port, path } = parseUrl(urlStr);
  const lib = isHttps ? https : http;
  const payload = Buffer.from(JSON.stringify(bodyObj), "utf8");

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname,
        port,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": payload.length,
        },
        ...buildTlsOptions(isHttps),
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch {}
          resolve({ status: res.statusCode, raw: data, json: parsed });
        });
      }
    );

    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function signBody(body, privateKey = PRIVATE_KEY) {
  body.auth.signature = signRequest(body, privateKey);
  return body;
}

async function callToolAsCaller(name, args, callerId, privateKey, { id = "1", session_id, ...opts } = {}) {
  const body = jsonRpc(
    id,
    "tools/call",
    { name, arguments: args || {} },
    makeAuth({ ...opts, callerId, session_id })
  );
  signBody(body, privateKey);
  return postJson(S_URL, body);
}

async function callInitialize(id = "0", opts = {}) {
  const body = jsonRpc(
    id,
    "initialize",
    {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "secure-proxy-client", version: "1.0.0" },
    },
    makeAuth(opts)
  );
  signBody(body);
  return postJson(S_URL, body);
}

async function callInitialized(opts = {}) {
  const body = {
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
    auth: makeAuth(opts),
  };
  signBody(body);
  return postJson(S_URL, body);
}

async function callToolsList(id = "1", opts = {}) {
  const body = jsonRpc(id, "tools/list", {}, makeAuth(opts));
  signBody(body);
  return postJson(S_URL, body);
}

async function callTool(name, args, { id = "1", session_id, ...opts } = {}) {
  const body = jsonRpc(id, "tools/call", { name, arguments: args || {} }, makeAuth({ ...opts, session_id }));
  signBody(body);
  return postJson(S_URL, body);
}

async function createReadySession() {
  const initResp = await callTool("s.init", {}, { id: "2" });
  console.log("init:", initResp.status, initResp.json || initResp.raw);

  const sid = initResp.json?.result?.session_id;
  const challenge = initResp.json?.result?.challenge;
  if (!sid || !challenge) die("s.init failed");

  const proof = signReadyProof(String(sid), String(challenge));
  const readyResp = await callTool("s.ready", { proof }, { id: "3", session_id: sid });
  console.log("ready:", readyResp.status, readyResp.json || readyResp.raw);
  return { sid, challenge, readyResp };
}

async function demo() {
  console.log("initialize:");
  const initResult = await callInitialize("0");
  console.log(initResult.json || initResult.raw);

  console.log("notifications/initialized:");
  const initializedResult = await callInitialized();
  console.log(initializedResult.json || initializedResult.raw);

  console.log("tools/list:");
  const listResp = await callToolsList("1");
  console.log(listResp.status, listResp.json || listResp.raw);

  const { sid } = await createReadySession();

  console.log("allowed tool:");
  const r1 = await callTool("list_allowed_directories", {}, { id: "4", session_id: sid });
  console.log(r1.status, r1.json || r1.raw);

  console.log("denied tool:");
  const r2 = await callTool("read_file", { path: SECRET_PATH }, { id: "5", session_id: sid });
  console.log(r2.status, r2.json || r2.raw);
}

async function noauth() {
  const body = { jsonrpc: "2.0", id: "1", method: "tools/list", params: {} };
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
}

async function badsig() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  signBody(body);
  body.params = { tampered: true };
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
}

async function replay() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  signBody(body);
  const r1 = await postJson(S_URL, body);
  console.log("first:", r1.status, r1.json || r1.raw);
  const r2 = await postJson(S_URL, body);
  console.log("replay:", r2.status, r2.json || r2.raw);
}

async function bypass() {
  const r = await callTool("list_allowed_directories", {}, { id: "1" });
  console.log(r.status, r.json || r.raw);
}

async function acldeny() {
  await callInitialize("0");
  await callInitialized();
  const { sid } = await createReadySession();
  const r = await callTool("read_file", { path: SECRET_PATH }, { id: "4", session_id: sid });
  console.log(r.status, r.json || r.raw);
}

async function badready() {
  await callInitialize("0");
  await callInitialized();

  const initResp = await callTool("s.init", {}, { id: "1" });
  const sid = initResp.json?.result?.session_id;
  const badProof = Buffer.from("not-a-valid-proof").toString("base64");
  const r = await callTool("s.ready", { proof: badProof }, { id: "2", session_id: sid });
  console.log(r.status, r.json || r.raw);
}

async function readytimeout() {
  await callInitialize("0");
  await callInitialized();

  const initResp = await callTool("s.init", {}, { id: "1" });
  const sid = initResp.json?.result?.session_id;
  const challenge = initResp.json?.result?.challenge;
  const readyWithinMs = initResp.json?.result?.ready_within_ms;
  if (!sid || !challenge || !readyWithinMs) die("s.init failed");

  await new Promise((resolve) => setTimeout(resolve, Number(readyWithinMs) + 1000));

  const proof = signReadyProof(String(sid), String(challenge));
  const r = await callTool("s.ready", { proof }, { id: "2", session_id: sid });
  console.log(r.status, r.json || r.raw);
}

async function oldts() {
  const r = await callToolsList("1", { timestamp: nowSec(-600) });
  console.log(r.status, r.json || r.raw);
}

async function unknowncaller() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth({ callerId: "fake_mcp" }));
  signBody(body);
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
}

async function listfilter() {
  await callInitialize("0");
  await callInitialized();
  const r = await callToolsList("1");
  console.log(r.status, JSON.stringify(r.json || r.raw, null, 2));
}

async function quota() {
  await callInitialize("0");
  await callInitialized();
  const { sid } = await createReadySession();

  for (let i = 0; i < 20; i++) {
    const r = await callTool("list_allowed_directories", {}, { id: String(100 + i), session_id: sid });
    console.log(`call ${i + 1}:`, r.status, r.json || r.raw);
    if (r.status !== 200) break;
  }
}

async function session_mismatch() {
  await callInitialize("0");
  await callInitialized();

  const initResp = await callTool("s.init", {}, { id: "1" });
  const sid = initResp.json?.result?.session_id;
  const challenge = initResp.json?.result?.challenge;
  if (!sid || !challenge) die("s.init failed");

  const proof = signReadyProof(String(sid), String(challenge), "mcp1", PRIVATE_KEY);
  const readyResp = await callTool("s.ready", { proof }, { id: "2", session_id: sid });
  console.log("ready as mcp1:", readyResp.status, readyResp.json || readyResp.raw);
  
  if (!HIJACK_PRIVATE_KEY) die("HIJACK_PRIVATE_KEY_PATH is required for session_mismatch");

  const r = await callToolAsCaller(
    "list_allowed_directories",
    {},
    "mcp2",
    HIJACK_PRIVATE_KEY,
    { id: "3", session_id: sid }
  );

  console.log(r.status, r.json || r.raw);
}

// ── Attack 1 extensions: individual auth-field omission ───────────────────────
// Each test removes exactly one required auth field. S returns a distinct error
// code for each missing field, proving that all fields are validated before the
// signature step.

async function missingCallerId() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  delete body.auth.caller_id;
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 missing_caller_id");
}

async function missingTimestamp() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  delete body.auth.timestamp;
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 missing_timestamp");
}

async function missingNonce() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  delete body.auth.nonce;
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 missing_nonce");
}

async function missingSignature() {
  // makeAuth() sets signature:"" (falsy) — send without calling signBody
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 missing_signature");
}

// ── Attack 2 extension: future timestamp ──────────────────────────────────────
// The timestamp window rejects requests more than AUTH_TS_WINDOW_SEC seconds
// away from now in either direction. A future timestamp (+10 min) is caught by
// the same abs() window check as an old timestamp.

async function futureTs() {
  const r = await callToolsList("1", { timestamp: nowSec(+600) });
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 timestamp_out_of_window");
}

// ── Attack 3 extensions: post-signing field tampering ─────────────────────────
// The RSA-SHA256 signature is computed over the full canonical body. Changing
// any field — including the RPC method or auth sub-fields — after signing
// invalidates the signature. Both tests confirm bad_signature is returned.

async function tamperMethod() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  signBody(body);
  body.method = "tools/call"; // rewrite method after signing
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 bad_signature — method field is part of signed payload");
}

async function tamperAuth() {
  const body = jsonRpc("1", "tools/list", {}, makeAuth());
  signBody(body);
  body.auth.nonce = "tampered-nonce"; // mutate auth nonce after signing
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 bad_signature — auth fields are included in signed payload");
}

// ── Attack 4 extensions: session state machine boundaries ─────────────────────

// Sending a random session_id that was never created → unknown_session
async function unknownSession() {
  const r = await callTool("list_allowed_directories", {}, {
    id: "1",
    session_id: "00000000000000000000000000000000",
  });
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 unknown_session");
}

// Calling s.ready a second time on an already-ready session → bad_session_state
// (verifyReadyTransition requires state === 'new'; after the first s.ready the
// session moves to 'ready', so the second call is rejected)
async function doubleReady() {
  await callInitialize("0");
  await callInitialized();

  const initResp = await callTool("s.init", {}, { id: "1" });
  const sid = initResp.json?.result?.session_id;
  const challenge = initResp.json?.result?.challenge;
  if (!sid || !challenge) die("s.init failed");

  const proof = signReadyProof(String(sid), String(challenge));
  const r1 = await callTool("s.ready", { proof }, { id: "2", session_id: sid });
  console.log("first ready:", r1.status, r1.json || r1.raw);

  const proof2 = signReadyProof(String(sid), String(challenge));
  const r2 = await callTool("s.ready", { proof: proof2 }, { id: "3", session_id: sid });
  console.log("second ready:", r2.status, r2.json || r2.raw);
  console.log("Expected: first → 200, second → 403 bad_session_state");
}

// Calling a tool after s.init but before s.ready → bad_session_state
// (verifyToolCall requires state === 'ready'; 'new' state is not sufficient)
async function notReadySession() {
  await callInitialize("0");
  await callInitialized();

  const initResp = await callTool("s.init", {}, { id: "1" });
  const sid = initResp.json?.result?.session_id;
  if (!sid) die("s.init failed");

  // skip s.ready, jump straight to a tool call
  const r = await callTool("list_allowed_directories", {}, { id: "2", session_id: sid });
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 bad_session_state — session is new, not ready");
}

// ── Attack 5 extensions: ACL boundary tests ───────────────────────────────────

// write_file is not in TOOL_POLICIES → tool_not_allowed (same layer as read_file)
async function writeFileDenied() {
  await callInitialize("0");
  await callInitialized();
  const { sid } = await createReadySession();
  const r = await callTool(
    "write_file",
    { path: "/tmp/pwned.txt", content: "hacked" },
    { id: "4", session_id: sid }
  );
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 tool_not_allowed");
}

// Positive control: list_allowed_directories IS whitelisted → must succeed
// Confirms the ACL allows legitimate callers through, not just blocks attackers
async function allowedTool() {
  await callInitialize("0");
  await callInitialized();
  const { sid } = await createReadySession();
  const r = await callTool("list_allowed_directories", {}, { id: "4", session_id: sid });
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 200 — list_allowed_directories is whitelisted");
}

// Layer 1 — method allowlist: an unknown RPC method is rejected before any auth
// or session check runs, demonstrating the outermost defense layer
async function unknownMethod() {
  const body = { jsonrpc: "2.0", id: "1", method: "admin/deleteAll", params: {}, auth: makeAuth() };
  signBody(body);
  const r = await postJson(S_URL, body);
  console.log(r.status, r.json || r.raw);
  console.log("Expected: 403 not_allowed_method");
}

async function runAll() {
  const SLOW = process.env.SKIP_SLOW !== "false"; // slow tests skipped unless SKIP_SLOW=false
  const results = [];

  async function run(name, fn, { skip = false, slow = false } = {}) {
    console.log(`\n${"─".repeat(60)}`);
    console.log(`  [ ${name} ]`);
    console.log("─".repeat(60));
    if (skip) {
      console.log("  SKIPPED — prerequisite missing");
      results.push({ name, verdict: "skipped" });
      return;
    }
    if (slow && SLOW) {
      console.log("  SKIPPED — slow test (run with SKIP_SLOW=false to include)");
      results.push({ name, verdict: "skipped (slow)" });
      return;
    }
    try {
      await fn();
      results.push({ name, verdict: "ran" });
    } catch (e) {
      console.error("  ERROR:", e.message);
      results.push({ name, verdict: "error", msg: e.message });
    }
  }

  // ── Attack 1: Impersonation ────────────────────────────────────────────────
  await run("unknowncaller",     unknowncaller);
  await run("noauth",            noauth);
  await run("missing_caller_id", missingCallerId);
  await run("missing_timestamp", missingTimestamp);
  await run("missing_nonce",     missingNonce);
  await run("missing_signature", missingSignature);

  // ── Attack 2: Replay ──────────────────────────────────────────────────────
  await run("replay",   replay);
  await run("oldts",    oldts);
  await run("futurets", futureTs);

  // ── Attack 3: Tampering ───────────────────────────────────────────────────
  await run("badsig",        badsig);
  await run("tamper_method", tamperMethod);
  await run("tamper_auth",   tamperAuth);

  // ── Attack 4: Session Hijacking ───────────────────────────────────────────
  await run("bypass",            bypass);
  await run("session_mismatch",  session_mismatch, { skip: !HIJACK_PRIVATE_KEY });
  await run("badready",          badready);
  await run("readytimeout",      readytimeout,     { slow: true });
  await run("quota",             quota);
  await run("unknown_session",   unknownSession);
  await run("double_ready",      doubleReady);
  await run("not_ready_session", notReadySession);

  // ── Attack 5: Unauthorized Tool Access ────────────────────────────────────
  await run("acldeny",           acldeny);
  await run("listfilter",        listfilter);
  await run("write_file_denied", writeFileDenied);
  await run("allowed_tool",      allowedTool);
  await run("unknown_method",    unknownMethod);

  // ── Summary ───────────────────────────────────────────────────────────────
  const ran     = results.filter((r) => r.verdict === "ran").length;
  const errored = results.filter((r) => r.verdict === "error").length;
  const skipped = results.filter((r) => r.verdict.startsWith("skipped")).length;

  console.log(`\n${"═".repeat(60)}`);
  console.log("  ALL-TESTS SUMMARY");
  console.log("═".repeat(60));
  for (const r of results) {
    const icon  = r.verdict === "ran" ? "✓" : r.verdict === "error" ? "✗" : "–";
    const extra = r.verdict === "error" ? `  ← ${r.msg}` : "";
    console.log(`  ${icon}  ${r.name.padEnd(26)} ${r.verdict}${extra}`);
  }
  console.log("─".repeat(60));
  console.log(`  ${ran} ran   ${skipped} skipped   ${errored} errors`);
  console.log("═".repeat(60));
}

async function main() {
  const cmd = process.argv[2] || "all";

  console.log("╔════════════════════════════════════════════════════╗");
  console.log("║   Secure MCP Gateway — Protected Attack Tests      ║");
  console.log(`║   test: ${cmd}`.padEnd(53) + "║");
  console.log("╚════════════════════════════════════════════════════╝");

  switch (cmd) {
    case "all":  return runAll();
    case "demo": return demo();

    // ── Attack 1: Impersonation ──────────────────────────────────────────
    // S looks up the public key for the claimed caller_id and verifies the
    // RSA-SHA256 signature over the full request body. A missing auth block,
    // an unregistered caller_id, or any absent auth field is rejected first.
    case "unknowncaller":      return unknowncaller();      // unregistered caller_id          → 403 unknown_caller
    case "noauth":             return noauth();             // auth block absent entirely       → 403 missing_auth
    case "missing_caller_id":  return missingCallerId();    // caller_id field missing          → 403 missing_caller_id
    case "missing_timestamp":  return missingTimestamp();   // timestamp field missing          → 403 missing_timestamp
    case "missing_nonce":      return missingNonce();       // nonce field missing              → 403 missing_nonce
    case "missing_signature":  return missingSignature();   // signature field empty            → 403 missing_signature

    // ── Attack 2: Replay ─────────────────────────────────────────────────
    // Every request must carry a fresh timestamp (within AUTH_TS_WINDOW_SEC)
    // and a nonce that has not been seen before (tracked in nonceCache).
    // The timestamp window applies in both directions — past AND future.
    case "replay":   return replay();    // identical nonce reused          → 403 replay_nonce_reused
    case "oldts":    return oldts();     // timestamp too far in past        → 403 timestamp_out_of_window
    case "futurets": return futureTs();  // timestamp too far in future      → 403 timestamp_out_of_window

    // ── Attack 3: Tampering ──────────────────────────────────────────────
    // The signature covers the entire canonical request body. Any field
    // modified after signing — including the RPC method or auth sub-fields —
    // causes signature verification to fail.
    case "badsig":        return badsig();        // params changed post-signing      → 403 bad_signature
    case "tamper_method": return tamperMethod();  // method rewritten after signing   → 403 bad_signature
    case "tamper_auth":   return tamperAuth();    // auth nonce mutated after signing → 403 bad_signature

    // ── Attack 4: Session Hijacking ──────────────────────────────────────
    // S enforces a strict s.init → s.ready → tools/call state machine.
    // Sessions are cryptographically bound to the caller that created them;
    // cross-caller reuse, forged proofs, expired windows, and state skips
    // are all rejected.
    case "bypass":             return bypass();            // skip handshake entirely         → 403 missing_session_id
    case "session_mismatch":   return session_mismatch();  // reuse session as diff caller    → 403 session_caller_mismatch
    case "badready":           return badready();          // forge challenge-response        → 403 bad_ready_proof
    case "readytimeout":       return readytimeout();      // miss the ready window           → 403 ready_timeout
    case "quota":              return quota();             // exceed per-session op limit     → 403 session_ops_exhausted
    case "unknown_session":    return unknownSession();    // random session_id never created → 403 unknown_session
    case "double_ready":       return doubleReady();       // s.ready called twice            → 403 bad_session_state
    case "not_ready_session":  return notReadySession();   // tool call before s.ready done   → 403 bad_session_state

    // ── Attack 5: Unauthorized Tool Access ───────────────────────────────
    // Even with valid identity and a ready session, only tools listed in
    // TOOL_POLICIES with safe:true are forwarded. All others are blocked.
    // tools/list also filters the response so forbidden tools are not visible.
    // allowed_tool is a positive control confirming legitimate access works.
    case "acldeny":          return acldeny();          // read_file with valid session     → 403 tool_not_allowed
    case "listfilter":       return listfilter();       // tools/list hides non-safe tools  → 200 filtered list
    case "write_file_denied": return writeFileDenied(); // write_file blocked by ACL        → 403 tool_not_allowed
    case "allowed_tool":     return allowedTool();      // list_allowed_directories OK      → 200
    case "unknown_method":   return unknownMethod();    // unknown RPC method (Layer 1)     → 403 not_allowed_method

    // ── Attack 6: MITM ───────────────────────────────────────────────────
    // Covered by mitm_protected.js. TLS encrypts the channel so a proxy
    // cannot read or modify traffic; mTLS additionally authenticates the
    // client, preventing connection from an unknown party.

    default:
      die("Unknown command: " + cmd);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});