"use strict";

/**
 * Component-level tests against S.
 *
 * This file tests S directly.
 * It is useful for proving the gateway itself enforces:
 * - auth
 * - anti-replay
 * - tamper detection
 * - session workflow
 * - ACL
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");

const S_URL = process.env.S_URL || "http://127.0.0.1:4000/rpc";
const CALLER_ID = process.env.CALLER_ID || "mcp1";
const MCP1_PRIVATE_KEY_PATH = process.env.MCP1_PRIVATE_KEY_PATH || "";
const HIJACK_PRIVATE_KEY_PATH = process.env.HIJACK_PRIVATE_KEY_PATH || "";
const TLS_CA_PATH = process.env.TLS_CA_PATH || "";
const ENABLE_MTLS = process.env.ENABLE_MTLS === "true";
const TLS_CLIENT_CERT = process.env.TLS_CLIENT_CERT || "";
const TLS_CLIENT_KEY = process.env.TLS_CLIENT_KEY || "";
const SECRET_PATH = process.env.SECRET_PATH || path.join(__dirname, "workspace", "sandbox", "secret.txt");

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
  console.log("== initialize ==");
  console.log((await callInitialize("0")).json || (await callInitialize("0")).raw);

  console.log("== notifications/initialized ==");
  console.log((await callInitialized()).json || (await callInitialized()).raw);

  console.log("== tools/list ==");
  const listResp = await callToolsList("1");
  console.log(listResp.status, listResp.json || listResp.raw);

  const { sid } = await createReadySession();

  console.log("== allowed tool ==");
  const r1 = await callTool("list_allowed_directories", {}, { id: "4", session_id: sid });
  console.log(r1.status, r1.json || r1.raw);

  console.log("== denied tool ==");
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

async function main() {
  const cmd = process.argv[2] || "demo";

  switch (cmd) {
    case "demo": return demo();
    case "noauth": return noauth();
    case "badsig": return badsig();
    case "replay": return replay();
    case "bypass": return bypass();
    case "acldeny": return acldeny();
    case "badready": return badready();
    case "readytimeout": return readytimeout();
    case "oldts": return oldts();
    case "unknowncaller": return unknowncaller();
    case "listfilter": return listfilter();
    case "quota": return quota();
    case "session_mismatch": return session_mismatch();
    default:
      die("Unknown command: " + cmd);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});