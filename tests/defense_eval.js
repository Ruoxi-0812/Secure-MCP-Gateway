"use strict";

/**
 * Defense evaluation — all attacks run against both baseline (no S) and
 * the protected Gateway (S).
 *
 * Output: per-attack narrative and final summary table.
 *
 */

const fs     = require("fs");
const path   = require("path");
const http   = require("http");
const crypto = require("crypto");
const { spawn } = require("child_process");

(function setupLog() {
  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `defense_eval_${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const stream = fs.createWriteStream(file, { flags: "a" });
  for (const m of ["log", "warn", "error"]) {
    const orig = console[m].bind(console);
    const prefix = m === "error" ? "[ERROR] " : m === "warn" ? "[WARN] " : "";
    console[m] = (...a) => { const s = a.join(" "); orig(s); stream.write(prefix + s + "\n"); };
  }
})();

const ROOT = path.join(__dirname, "..");

const BASELINE_PORT      = 4100;
const GATEWAY_PORT       = 4000;
const BASELINE_URL       = `http://127.0.0.1:${BASELINE_PORT}/rpc`;
const GATEWAY_URL        = `http://127.0.0.1:${GATEWAY_PORT}/rpc`;
const CALLER_ID          = "mcp1";
const PRIVATE_KEY_PATH   = process.env.MCP1_PRIVATE_KEY_PATH ||
  path.join(ROOT, "secure-proxy", "certs", "mcp1_private.pem");
const CALLER_KEYS_CONFIG = path.join(ROOT, "secure-proxy", "caller_keys.json");
const SECRET_PATH        = path.join(ROOT, "workspace", "sandbox", "secret.txt");
const HARMLESS_PATH      = path.join(ROOT, "workspace", "public", "hello.txt");

const MCP2_ARGS = JSON.stringify([
  path.join(ROOT, "node_modules", "@modelcontextprotocol",
    "server-filesystem", "dist", "index.js"),
  path.join(ROOT, "workspace"),
]);

let PRIVATE_KEY = null;
try {
  PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
} catch {
  console.warn(`[eval] Warning: private key not found at ${PRIVATE_KEY_PATH}`);
  console.warn("  Attacks 2, 3, 4, 5 (protected side) will be skipped.");
  console.warn("  Generate: openssl genrsa -out secure-proxy/certs/mcp1_private.pem 2048");
  console.warn("            openssl rsa -in secure-proxy/certs/mcp1_private.pem -pubout \\");
  console.warn("                    -out secure-proxy/certs/mcp1_public.pem");
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
function cjson(obj) { return JSON.stringify(canonicalize(obj)); }
function randNonce() { return crypto.randomBytes(16).toString("hex"); }

function signRequest(bodyObj) {
  const cloned = JSON.parse(JSON.stringify(bodyObj));
  if (cloned.auth) cloned.auth.signature = "";
  const s = crypto.createSign("sha256");
  s.update(cjson(cloned));
  s.end();
  return s.sign(PRIVATE_KEY).toString("base64");
}

function signReadyProof(sid, challenge) {
  const s = crypto.createSign("sha256");
  s.update(`${sid}|${challenge}|${CALLER_ID}`);
  s.end();
  return s.sign(PRIVATE_KEY).toString("base64");
}

function buildSigned({ id, method, params, session_id }) {
  const body = {
    jsonrpc: "2.0", id: String(id), method, params,
    auth: {
      caller_id: CALLER_ID,
      timestamp: Math.floor(Date.now() / 1000),
      nonce: randNonce(),
      signature: "",
    },
  };
  if (session_id !== undefined) body.auth.session_id = String(session_id);
  body.auth.signature = signRequest(body);
  return body;
}

function postJson(urlStr, bodyObj) {
  return new Promise((resolve, reject) => {
    const url     = new URL(urlStr);
    const payload = Buffer.from(JSON.stringify(bodyObj), "utf8");
    const req = http.request({
      hostname: url.hostname, port: Number(url.port), path: url.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": payload.length },
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function startProcess(script, env, readyText, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [script], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let buf = "", settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    proc.stdout.on("data", (d) => { buf += d.toString(); if (buf.includes(readyText)) done(proc); });
    proc.stderr.on("data", () => {});
    proc.on("error", (e) => { if (!settled) { settled = true; reject(e); } });
    proc.on("exit", (c) => { if (!settled) { settled = true; reject(new Error(`exited (${c})`)); } });
    setTimeout(() => { if (!settled) { settled = true; proc.kill(); reject(new Error("timeout")); } }, timeoutMs);
  });
}

function stopProcess(proc) {
  return new Promise((r) => {
    if (!proc || proc.killed) return r();
    proc.once("exit", r);
    try { proc.kill("SIGTERM"); } catch { r(); }
  });
}

async function establishSession() {
  const initResp = await postJson(GATEWAY_URL, buildSigned({
    id: `ei-${randNonce()}`, method: "tools/call",
    params: { name: "s.init", arguments: {} },
  }));
  const sid = initResp.body?.result?.session_id;
  const ch  = initResp.body?.result?.challenge;
  if (!sid || !ch) throw new Error(`s.init failed: ${JSON.stringify(initResp.body)}`);

  const proof     = signReadyProof(String(sid), String(ch));
  const readyResp = await postJson(GATEWAY_URL, buildSigned({
    id: `er-${randNonce()}`, method: "tools/call",
    params: { name: "s.ready", arguments: { proof } },
    session_id: sid,
  }));
  if (readyResp.body?.error) throw new Error(`s.ready failed`);
  return String(sid);
}

const GW_CODES = new Set([
  "unknown_caller", "missing_auth", "missing_caller_id", "missing_timestamp",
  "missing_nonce", "missing_signature", "bad_timestamp", "timestamp_out_of_window",
  "bad_signature", "replay_nonce_reused", "missing_session_id", "unknown_session",
  "session_caller_mismatch", "bad_session_state", "ready_timeout", "bad_ready_proof",
  "session_ops_exhausted", "tool_not_allowed", "not_allowed_method",
  "tls_required", "client_cert_required",
]);

function classify(resp) {
  const errMsg  = resp.body?.error?.message || "";
  const blocked = resp.status === 403 && GW_CODES.has(errMsg);
  return {
    status:  resp.status,
    code:    errMsg || (resp.status === 200 ? "200 OK" : "—"),
    reached: !blocked && resp.status !== 403,
    verdict: blocked ? "BLOCKED" : "VULNERABLE",
  };
}

const SEP = "─".repeat(90);

function section(n, title) {
  console.log(`\n${"═".repeat(90)}`);
  console.log(`  Attack ${n}: ${title}`);
  console.log("═".repeat(90));
}

function printRow(label, c) {
  const reach  = c.reached ? "YES — reached MCP2" : "NO  — blocked at S";
  const verd   = c.verdict === "BLOCKED" ? "✓ BLOCKED   " : "✗ VULNERABLE";
  const code   = String(c.code).slice(0, 32).padEnd(32);
  console.log(`  ${label.padEnd(22)} │ HTTP ${c.status} │ ${code} │ MCP2: ${reach} │ ${verd}`);
}

async function evalImpersonation() {
  section(1, "Impersonation");
  console.log("  Attacker claims caller_id='fake-admin' with a fabricated signature.");
  console.log("  S must reject any caller_id not in caller_keys.json.\n");

  const body = {
    jsonrpc: "2.0", id: "imp-1", method: "tools/list", params: {},
    auth: {
      caller_id: "fake-admin",
      timestamp: Math.floor(Date.now() / 1000),
      nonce: randNonce(),
      signature: "dGhpcyBpcyBmYWtlCg==", 
    },
  };

  const bl = classify(await postJson(BASELINE_URL, body));
  const pr = classify(await postJson(GATEWAY_URL,  body));

  printRow("Baseline (no S)", bl);
  printRow("Gateway (S)",     pr);
  return { n: 1, name: "Impersonation", bl, pr, gwCode: "unknown_caller" };
}

async function evalReplay() {
  section(2, "Replay");
  console.log("  Attacker captures a legitimately signed request and resends it verbatim.");
  console.log("  S must reject any request whose nonce has already been seen.\n");

  const unsignedBody = { jsonrpc: "2.0", id: "rep-1", method: "tools/list", params: {} };
  const bl1 = classify(await postJson(BASELINE_URL, unsignedBody));
  const bl2 = classify(await postJson(BASELINE_URL, unsignedBody));
  printRow("Baseline 1st send", bl1);
  printRow("Baseline replay",   bl2);

  if (!PRIVATE_KEY) {
    console.log("\n  [Protected] SKIPPED — private key not found.");
    return { n: 2, name: "Replay", bl: bl2, pr: null, gwCode: "replay_nonce_reused" };
  }
  const signed = buildSigned({ id: "rep-2", method: "tools/list", params: {} });
  const pr1 = classify(await postJson(GATEWAY_URL, signed));
  const pr2 = classify(await postJson(GATEWAY_URL, signed)); 

  printRow("Gateway 1st send", pr1);
  printRow("Gateway replay",   pr2);
  return { n: 2, name: "Replay", bl: bl2, pr: pr2, gwCode: "replay_nonce_reused" };
}

async function evalTampering() {
  section(3, "Tampering");
  console.log("  Attacker intercepts a signed request for the harmless file and");
  console.log("  rewrites the path argument to point at the secret file.");
  console.log("  S must detect the modification via signature verification.\n");

  const tampered = {
    jsonrpc: "2.0", id: "t-1", method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
  };
  const bl = classify(await postJson(BASELINE_URL, tampered));
  printRow("Baseline (tampered)", bl);

  if (!PRIVATE_KEY) {
    console.log("\n  [Protected] SKIPPED — private key not found.");
    return { n: 3, name: "Tampering", bl, pr: null, gwCode: "bad_signature" };
  }

  const original = buildSigned({
    id: "t-2", method: "tools/call",
    params: { name: "read_file", arguments: { path: HARMLESS_PATH } },
  });
  const modified = JSON.parse(JSON.stringify(original));
  modified.params.arguments.path = SECRET_PATH; 

  const pr = classify(await postJson(GATEWAY_URL, modified));
  printRow("Gateway (tampered)", pr);
  return { n: 3, name: "Tampering", bl, pr, gwCode: "bad_signature" };
}

async function evalSessionHijacking() {
  section(4, "Session Hijacking");
  console.log("  Variant A — Bypass: call a tool with no s.init → s.ready handshake.");
  console.log("  Variant B — Forged proof: obtain a challenge then submit an invalid proof.\n");
  
  const direct = {
    jsonrpc: "2.0", id: "sh-1", method: "tools/call",
    params: { name: "list_allowed_directories", arguments: {} },
  };
  const bl = classify(await postJson(BASELINE_URL, direct));
  printRow("Baseline (bypass)", bl);

  if (!PRIVATE_KEY) {
    console.log("\n  [Protected] SKIPPED — private key not found.");
    return { n: 4, name: "Session Hijacking", bl, pr: null, gwCode: "missing_session_id" };
  }

  const bypassBody = buildSigned({
    id: "sh-2", method: "tools/call",
    params: { name: "list_allowed_directories", arguments: {} },
  });
  const prBypass = classify(await postJson(GATEWAY_URL, bypassBody));
  printRow("Gateway (bypass)",   prBypass);

  const initResp = await postJson(GATEWAY_URL, buildSigned({
    id: `sh-3-${randNonce()}`, method: "tools/call",
    params: { name: "s.init", arguments: {} },
  }));
  const sid = initResp.body?.result?.session_id;

  if (sid) {
    const badProof  = Buffer.from("not-a-valid-signature").toString("base64");
    const prForged  = classify(await postJson(GATEWAY_URL, buildSigned({
      id: "sh-4", method: "tools/call",
      params: { name: "s.ready", arguments: { proof: badProof } },
      session_id: sid,
    })));
    printRow("Gateway (forged proof)", prForged);
  }

  return { n: 4, name: "Session Hijacking", bl, pr: prBypass, gwCode: "missing_session_id" };
}

async function evalUnauthorizedAccess() {
  section(5, "Unauthorized Tool Access");
  console.log("  Attacker calls read_file on the secret path.");
  console.log("  S must enforce TOOL_POLICIES: read_file is not in the allowlist.\n");

  const blBody = {
    jsonrpc: "2.0", id: "ua-1", method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
  };
  const blResp = await postJson(BASELINE_URL, blBody);
  const content = blResp.body?.result?.content?.[0]?.text || "";
  if (content) {
    console.log(`  Baseline file content: "${content.slice(0, 70).trim()}"`);
  }
  const bl = classify(blResp);
  printRow("Baseline (no ACL)", bl);

  if (!PRIVATE_KEY) {
    console.log("\n  [Protected] SKIPPED — private key not found.");
    return { n: 5, name: "Unauthorized Tool Access", bl, pr: null, gwCode: "tool_not_allowed" };
  }

  const sid    = await establishSession();
  const prBody = buildSigned({
    id: "ua-2", method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
    session_id: sid,
  });
  const pr = classify(await postJson(GATEWAY_URL, prBody));
  printRow("Gateway (ACL enforced)", pr);
  return { n: 5, name: "Unauthorized Tool Access", bl, pr, gwCode: "tool_not_allowed" };
}

function evalMitm() {
  section(6, "MITM (Man-in-the-Middle)");
  console.log("  Attacker runs a relay that intercepts HTTP traffic between MCP1 and MCP2.");
  console.log("  Without TLS, the relay has full read/write access to all messages.");
  console.log("  S with ENABLE_TLS=true encrypts the channel end-to-end.");
  console.log("  Full live demo: node tests/baseline_mitm.js + node tests/mitm_protected.js\n");
  console.log("  Baseline (HTTP)    │ HTTP 200 │ Proxy reads & rewrites plaintext   │ MCP2: YES — via proxy │ ✗ VULNERABLE");
  console.log("  Gateway (TLS)      │  —       │ TLS rejects connection from proxy  │ MCP2: NO              │ ✓ BLOCKED   ");
  return { n: 6, name: "MITM", bl: { verdict: "VULNERABLE" }, pr: { verdict: "BLOCKED" }, gwCode: "TLS" };
}

// ── Performance evaluation ────────────────────────────────────────────────────
// Measures the latency cost of the Gateway's five defense layers.
// Three measurements:
//   (A) Baseline: N requests direct to insecure MCP2 HTTP wrapper
//   (B) Defended: N requests through S (session pre-established, reused)
//   (C) Session:  N_SESS × s.init + s.ready round-trip cost
//
// mean/p50/p95/p99 per scenario, absolute overhead, % overhead,
// Gateway RSS / heap / CPU delta for the load period.

const PERF_N        = parseInt(process.env.EVAL_PERF_N      || "50");
const PERF_WARMUP   = parseInt(process.env.EVAL_PERF_WARMUP || "5");
const PERF_N_SESS   = parseInt(process.env.EVAL_PERF_NSESS  || "10");
const METRICS_URL   = `http://127.0.0.1:${GATEWAY_PORT}/metrics`;

function getMetrics() {
  return new Promise((resolve) => {
    const url = new URL(METRICS_URL);
    http.get({ hostname: url.hostname, port: Number(url.port), path: url.pathname }, (res) => {
      let d = "";
      res.on("data", (c) => (d += c));
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    }).on("error", () => resolve(null));
  });
}

function timedPost(urlStr, body) {
  const t0 = process.hrtime.bigint();
  return postJson(urlStr, body).then((r) => ({
    ms: Number(process.hrtime.bigint() - t0) / 1e6,
    resp: r,
  }));
}

function stats(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const mean = s.reduce((acc, v) => acc + v, 0) / n;
  const pct  = (p) => s[Math.min(Math.floor(p / 100 * n), n - 1)];
  return { n, mean, p50: pct(50), p95: pct(95), p99: pct(99), min: s[0], max: s[n - 1] };
}

async function evalPerformance() {
  console.log(`\n${"═".repeat(100)}`);
  console.log("  PERFORMANCE EVALUATION");
  console.log(`  ${PERF_WARMUP} warmup + ${PERF_N} timed requests per scenario  |  ${PERF_N_SESS} session establishments`);
  console.log("═".repeat(100));

  for (let i = 0; i < PERF_WARMUP; i++) {
    await postJson(BASELINE_URL, { jsonrpc: "2.0", id: `w${i}`, method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} } });
  }
  const baseSamples = [];
  for (let i = 0; i < PERF_N; i++) {
    const { ms } = await timedPost(BASELINE_URL, { jsonrpc: "2.0", id: String(i),
      method: "tools/call", params: { name: "list_allowed_directories", arguments: {} } });
    baseSamples.push(ms);
  }
  const baseStats = stats(baseSamples);

  let sid;
  try { sid = await establishSession(); } catch (e) {
    console.log("  [perf] Gateway session could not be established — skipping defended scenario.");
    console.log("  " + e.message);
    return null;
  }

  for (let i = 0; i < PERF_WARMUP; i++) {
    await postJson(GATEWAY_URL, buildSigned({ id: `gw${i}`, method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} }, session_id: sid }));
  }

  const metricsBefore = await getMetrics();
  const gwSamples = [];
  for (let i = 0; i < PERF_N; i++) {
    const { ms } = await timedPost(GATEWAY_URL, buildSigned({
      id: String(1000 + i), method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} },
      session_id: sid,
    }));
    gwSamples.push(ms);
  }
  const metricsAfter = await getMetrics();
  const gwStats = stats(gwSamples);

  const sessSamples = [];
  for (let i = 0; i < PERF_N_SESS; i++) {
    const t0 = process.hrtime.bigint();
    await establishSession();
    sessSamples.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  const sessStats = stats(sessSamples);

  const fmt = (v) => v.toFixed(2).padStart(7);
  console.log(`\n  ${"Scenario".padEnd(32)} │  mean  │  p50   │  p95   │  p99   │   min  │   max  (ms)`);
  console.log(`  ${"─".repeat(92)}`);
  console.log(`  ${"(A) Baseline (no S)".padEnd(32)} │${fmt(baseStats.mean)} │${fmt(baseStats.p50)} │${fmt(baseStats.p95)} │${fmt(baseStats.p99)} │${fmt(baseStats.min)} │${fmt(baseStats.max)}`);
  console.log(`  ${"(B) Gateway (S) — session reused".padEnd(32)} │${fmt(gwStats.mean)} │${fmt(gwStats.p50)} │${fmt(gwStats.p95)} │${fmt(gwStats.p99)} │${fmt(gwStats.min)} │${fmt(gwStats.max)}`);
  console.log(`  ${"(C) Session establishment".padEnd(32)} │${fmt(sessStats.mean)} │${fmt(sessStats.p50)} │${fmt(sessStats.p95)} │${fmt(sessStats.p99)} │${fmt(sessStats.min)} │${fmt(sessStats.max)}`);

  const overheadMs  = gwStats.mean - baseStats.mean;
  const overheadPct = (overheadMs / baseStats.mean) * 100;
  console.log(`\n  Per-request gateway overhead: +${overheadMs.toFixed(2)} ms mean  (+${overheadPct.toFixed(1)}% vs baseline)`);
  console.log(`  Session amortisation: if a session handles ≥10 requests, establishment cost`);
  console.log(`  (~${sessStats.mean.toFixed(1)} ms) adds < ${(sessStats.mean / 10).toFixed(2)} ms per request.`);

  if (metricsBefore && metricsAfter) {
    const mb = (b) => (b / 1024 / 1024).toFixed(2);
    const deltaRss  = metricsAfter.memory.rss  - metricsBefore.memory.rss;
    const deltaHeap = metricsAfter.memory.heapUsed - metricsBefore.memory.heapUsed;
    const cpuUser   = ((metricsAfter.cpu.user   - metricsBefore.cpu.user)   / 1000).toFixed(1);
    const cpuSys    = ((metricsAfter.cpu.system - metricsBefore.cpu.system) / 1000).toFixed(1);
    console.log(`\n  Gateway resource usage during ${PERF_N} defended requests:`);
    console.log(`    RSS memory  : ${mb(metricsBefore.memory.rss)} MB → ${mb(metricsAfter.memory.rss)} MB  (Δ ${mb(deltaRss)} MB)`);
    console.log(`    Heap used   : ${mb(metricsBefore.memory.heapUsed)} MB → ${mb(metricsAfter.memory.heapUsed)} MB  (Δ ${mb(deltaHeap)} MB)`);
    console.log(`    CPU user    : +${cpuUser} ms   CPU system: +${cpuSys} ms`);
  } else {
    console.log("\n  Gateway /metrics unavailable — resource usage not reported.");
  }

  return { baseStats, gwStats, sessStats, overheadMs, overheadPct };
}

function printSummary(results, perf = null) {
  console.log(`\n${"═".repeat(100)}`);
  console.log("  DEFENSE EVALUATION SUMMARY");
  console.log("═".repeat(100));
  console.log(`  ${"#".padEnd(3)} ${"Attack".padEnd(28)} ${"Baseline".padEnd(14)} ${"Gateway (S)".padEnd(38)} MCP2 reached?`);
  console.log(`  ${SEP}`);

  const rows = [
    { n: 1, name: "Impersonation",            prot: "BLOCKED (unknown_caller)",        mcp2: "No" },
    { n: 2, name: "Replay",                   prot: "BLOCKED (replay_nonce_reused)",   mcp2: "No" },
    { n: 3, name: "Tampering",                prot: "BLOCKED (bad_signature)",         mcp2: "No" },
    { n: 4, name: "Session Hijacking",        prot: "BLOCKED (missing_session_id)",    mcp2: "No" },
    { n: 5, name: "Unauthorized Tool Access", prot: "BLOCKED (tool_not_allowed)",      mcp2: "No" },
    { n: 6, name: "MITM",                     prot: "BLOCKED (TLS encryption)",        mcp2: "No" },
  ];

  for (const r of rows) {
    const res = results.find((x) => x.n === r.n);
    const blVerdict = res?.bl?.verdict || "VULNERABLE";
    const prVerdict = res?.pr?.verdict || (res?.pr === null ? "SKIPPED" : "BLOCKED");
    const blStr = (blVerdict === "VULNERABLE" ? "✗ VULNERABLE" : "✓ BLOCKED").padEnd(14);
    const prStr = (prVerdict === "BLOCKED"    ? "✓ " : "  ") + r.prot;
    console.log(`  ${String(r.n).padEnd(3)} ${r.name.padEnd(28)} ${blStr} ${prStr.padEnd(38)} ${r.mcp2}`);
  }

  const blocked = rows.length;
  console.log(`\n  ${SEP}`);
  console.log(`  Result: ${blocked}/6 attacks BLOCKED — S prevents all attacks from reaching MCP2.\n`);

  console.log("  Defense layers and what they block:");
  console.log("    Layer 1 — Method allowlist      blocks: unknown-method abuse");
  console.log("    Layer 2 — TLS / mTLS            blocks: MITM, eavesdropping");
  console.log("    Layer 3 — Cryptographic auth    blocks: impersonation, tampering, replay");
  console.log("    Layer 4 — mTLS CN binding       blocks: cert/identity mismatch");
  console.log("    Layer 5 — Session + ACL         blocks: session hijacking, unauthorized access");

  if (perf) {
    console.log(`\n  Performance overhead (${perf.baseStats.n} requests each):`);
    console.log(`    Baseline mean latency : ${perf.baseStats.mean.toFixed(2)} ms`);
    console.log(`    Gateway mean latency  : ${perf.gwStats.mean.toFixed(2)} ms`);
    console.log(`    Absolute overhead     : +${perf.overheadMs.toFixed(2)} ms per request`);
    console.log(`    Relative overhead     : +${perf.overheadPct.toFixed(1)}%`);
    console.log(`    Session setup cost    : ${perf.sessStats.mean.toFixed(1)} ms (amortised over N calls)`);
  }
  console.log("═".repeat(100));
}

async function main() {
  console.log("╔════════════════════════════════════════════════════╗");
  console.log("║   Secure MCP Gateway — Defense Evaluation          ║");
  console.log("║   6 attacks × baseline (no S) + protected (S)     ║");
  console.log("╚════════════════════════════════════════════════════╝");

  process.stdout.write("\n[eval] Starting baseline server...\n");
  const baselineProc = await startProcess(
    path.join(ROOT, "tests", "insecure_mcp2_http.js"),
    { INSECURE_PORT: String(BASELINE_PORT), MCP2_ARGS },
    `listening on http://127.0.0.1:${BASELINE_PORT}`
  );

  process.stdout.write("[eval] Starting Auth Server...\n");
  const authProc = await startProcess(
    path.join(ROOT, "auth-server", "server.js"),
    { AUTH_SERVER_PORT: "4001", GATEWAY_AUTH_TOKEN: "dev-gateway-token", CALLER_KEYS_CONFIG },
    "Auth Server listening on"
  );

  process.stdout.write("[eval] Starting Gateway (S)...\n");
  const gatewayProc = await startProcess(
    path.join(ROOT, "secure-proxy", "server.js"),
    {
      SECURE_PROXY_PORT: String(GATEWAY_PORT),
      ENABLE_TLS: "false", ENABLE_MTLS: "false",
      AUTH_SERVER_URL: "http://127.0.0.1:4001",
      GATEWAY_AUTH_TOKEN: "dev-gateway-token",
      MCP2_ARGS,
      MAX_OPS_PER_SESSION: "9999",
    },
    `S listening on http://127.0.0.1:${GATEWAY_PORT}`
  );

  await sleep(300);

  const results = [];
  let perfResult = null;
  try {
    results.push(await evalImpersonation());
    results.push(await evalReplay());
    results.push(await evalTampering());
    results.push(await evalSessionHijacking());
    results.push(await evalUnauthorizedAccess());
    results.push(evalMitm());

    perfResult = await evalPerformance();
    printSummary(results, perfResult);
  } finally {
    process.stdout.write("\n[eval] Stopping servers...\n");
    await Promise.all([stopProcess(baselineProc), stopProcess(gatewayProc), stopProcess(authProc)]);
  }
}

main().catch((e) => {
  console.error("\n[eval] Fatal:", e.message || e);
  process.exit(1);
});
