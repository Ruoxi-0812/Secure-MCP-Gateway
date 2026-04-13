"use strict";

/**
 * Performance benchmark — Gateway overhead measurement.
 *
 * Three scenarios measured back-to-back with the same MCP2 backend:
 *
 *   1. Baseline latency        — N requests direct to insecure MCP2 (no S)
 *   2. Defended latency        — N requests through S → MCP2 (session reused)
 *   3. Session establishment   — N_SESSIONS × (s.init + s.ready) handshake
 *
 * Per-request statistics reported: mean, min, max, p50, p95, p99 (ms).
 * Gateway resource usage (RSS memory, CPU time) sampled before/after load.
 * Raw per-request latencies written to CSV for charting.
 *
 * Prerequisites — generate keys once before running:
 *   openssl genrsa -out secure-proxy/certs/mcp1_private.pem 2048
 *   openssl rsa -in secure-proxy/certs/mcp1_private.pem -pubout \
 *           -out secure-proxy/certs/mcp1_public.pem
 */

const fs     = require("fs");
const path   = require("path");
const http   = require("http");
const crypto = require("crypto");
const { spawn } = require("child_process");

// ── Logging ───────────────────────────────────────────────────────────────────
(function setupLog() {
  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `benchmark_${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const stream = fs.createWriteStream(file, { flags: "a" });
  for (const m of ["log", "warn", "error"]) {
    const orig = console[m].bind(console);
    const prefix = m === "error" ? "[ERROR] " : m === "warn" ? "[WARN] " : "";
    console[m] = (...a) => { const s = a.join(" "); orig(s); stream.write(prefix + s + "\n"); };
  }
})();

const ROOT = path.join(__dirname, "..");

const N_WARMUP   = parseInt(process.env.BENCH_WARMUP     || "10");
const N_REQUESTS = parseInt(process.env.BENCH_N          || "100");
const N_SESSIONS = parseInt(process.env.BENCH_N_SESSIONS || "20");

const BASELINE_PORT   = 4100;
const GATEWAY_PORT    = 4000;
const BASELINE_URL    = `http://127.0.0.1:${BASELINE_PORT}/rpc`;
const GATEWAY_URL     = `http://127.0.0.1:${GATEWAY_PORT}/rpc`;
const GATEWAY_METRICS = `http://127.0.0.1:${GATEWAY_PORT}/metrics`;

const CALLER_ID          = "mcp1";
const PRIVATE_KEY_PATH   = process.env.MCP1_PRIVATE_KEY_PATH ||
  path.join(ROOT, "secure-proxy", "certs", "mcp1_private.pem");
const CALLER_KEYS_CONFIG = path.join(ROOT, "secure-proxy", "caller_keys.json");
const CSV_OUT            = process.env.BENCH_CSV ||
  path.join(ROOT, "benchmark_results.csv");

const MCP2_ARGS = JSON.stringify([
  path.join(ROOT, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js"),
  path.join(ROOT, "workspace"),
]);

let PRIVATE_KEY;
try {
  PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
} catch {
  console.error(`[bench] Cannot read private key: ${PRIVATE_KEY_PATH}`);
  console.error("  Generate keys with:");
  console.error("    openssl genrsa -out secure-proxy/certs/mcp1_private.pem 2048");
  console.error("    openssl rsa -in secure-proxy/certs/mcp1_private.pem -pubout -out secure-proxy/certs/mcp1_public.pem");
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

function randNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function signRequest(bodyObj) {
  const cloned = JSON.parse(JSON.stringify(bodyObj));
  if (cloned.auth && typeof cloned.auth === "object") cloned.auth.signature = "";
  const signer = crypto.createSign("sha256");
  signer.update(canonicalJSONStringify(cloned));
  signer.end();
  return signer.sign(PRIVATE_KEY).toString("base64");
}

function signReadyProof(sid, challenge) {
  const signer = crypto.createSign("sha256");
  signer.update(`${sid}|${challenge}|${CALLER_ID}`);
  signer.end();
  return signer.sign(PRIVATE_KEY).toString("base64");
}

function buildSignedRequest({ id, method, params, session_id }) {
  const body = {
    jsonrpc: "2.0",
    id: String(id),
    method,
    params,
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
    const url = new URL(urlStr);
    const payload = Buffer.from(JSON.stringify(bodyObj), "utf8");
    const req = http.request({
      hostname: url.hostname,
      port: Number(url.port),
      path: url.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": payload.length },
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => { try { resolve(JSON.parse(data)); } catch { resolve(data); } });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function getJson(urlStr) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    http.get({ hostname: url.hostname, port: Number(url.port), path: url.pathname }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    }).on("error", () => resolve(null));
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

    let buf = "";
    let settled = false;

    const done = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    proc.stdout.on("data", (d) => {
      buf += d.toString("utf8");
      if (buf.includes(readyText)) done(proc);
    });
    proc.stderr.on("data", () => {});
    proc.on("error", (e) => { if (!settled) { settled = true; reject(e); } });
    proc.on("exit", (code) => {
      if (!settled) { settled = true; reject(new Error(`exited before ready (code=${code})`)); }
    });
    setTimeout(() => {
      if (!settled) { settled = true; proc.kill("SIGTERM"); reject(new Error("timeout waiting for process")); }
    }, timeoutMs);
  });
}

function stopProcess(proc) {
  return new Promise((resolve) => {
    if (!proc || proc.killed) return resolve();
    proc.once("exit", resolve);
    try { proc.kill("SIGTERM"); } catch { resolve(); }
  });
}

async function establishSession() {
  const initBody = buildSignedRequest({
    id: `bench-init-${randNonce()}`,
    method: "tools/call",
    params: { name: "s.init", arguments: {} },
  });
  const initResp = await postJson(GATEWAY_URL, initBody);
  const sid       = initResp?.result?.session_id;
  const challenge = initResp?.result?.challenge;
  if (!sid || !challenge) throw new Error(`s.init failed: ${JSON.stringify(initResp)}`);

  const proof     = signReadyProof(String(sid), String(challenge));
  const readyBody = buildSignedRequest({
    id: `bench-ready-${randNonce()}`,
    method: "tools/call",
    params: { name: "s.ready", arguments: { proof } },
    session_id: sid,
  });
  const readyResp = await postJson(GATEWAY_URL, readyBody);
  if (readyResp?.error) throw new Error(`s.ready failed: ${JSON.stringify(readyResp)}`);
  return String(sid);
}

function computeStats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const n      = sorted.length;
  const mean   = samples.reduce((s, v) => s + v, 0) / n;
  const pct    = (p) => sorted[Math.min(Math.floor(p / 100 * n), n - 1)];
  return {
    n,
    mean: mean.toFixed(3),
    min:  sorted[0].toFixed(3),
    max:  sorted[n - 1].toFixed(3),
    p50:  pct(50).toFixed(3),
    p95:  pct(95).toFixed(3),
    p99:  pct(99).toFixed(3),
  };
}

async function timedCall(fn) {
  const t0 = process.hrtime.bigint();
  await fn();
  return Number(process.hrtime.bigint() - t0) / 1e6; // → milliseconds
}

async function benchBaseline() {
  process.stdout.write(`\n[bench] Scenario 1 — Baseline latency (${N_WARMUP} warmup + ${N_REQUESTS} requests)\n`);

  for (let i = 0; i < N_WARMUP; i++) {
    await postJson(BASELINE_URL, {
      jsonrpc: "2.0", id: `w${i}`, method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} },
    });
  }

  const samples = [];
  for (let i = 0; i < N_REQUESTS; i++) {
    const ms = await timedCall(() => postJson(BASELINE_URL, {
      jsonrpc: "2.0", id: String(i), method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} },
    }));
    samples.push(ms);
    if ((i + 1) % 25 === 0) process.stdout.write(`  progress: ${i + 1}/${N_REQUESTS}\n`);
  }

  return { label: "baseline", samples };
}

async function benchDefended(sid) {
  process.stdout.write(`\n[bench] Scenario 2 — Defended latency (${N_WARMUP} warmup + ${N_REQUESTS} requests)\n`);

  for (let i = 0; i < N_WARMUP; i++) {
    await postJson(GATEWAY_URL, buildSignedRequest({
      id: `w${i}`, method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} },
      session_id: sid,
    }));
  }

  const samples = [];
  for (let i = 0; i < N_REQUESTS; i++) {
    const ms = await timedCall(() => postJson(GATEWAY_URL, buildSignedRequest({
      id: String(2000 + i), method: "tools/call",
      params: { name: "list_allowed_directories", arguments: {} },
      session_id: sid,
    })));
    samples.push(ms);
    if ((i + 1) % 25 === 0) process.stdout.write(`  progress: ${i + 1}/${N_REQUESTS}\n`);
  }

  return { label: "defended", samples };
}

async function benchSessionEstablishment() {
  process.stdout.write(`\n[bench] Scenario 3 — Session establishment (${N_SESSIONS} sessions)\n`);

  const samples = [];
  for (let i = 0; i < N_SESSIONS; i++) {
    const ms = await timedCall(() => establishSession());
    samples.push(ms);
    process.stdout.write(`  progress: ${i + 1}/${N_SESSIONS}\n`);
  }

  return { label: "session_establishment", samples };
}

function printTable(results) {
  const LINE = "─".repeat(78);
  console.log(`\n┌${LINE}┐`);
  console.log("│            Secure MCP Gateway — Performance Benchmark Results (ms)        │");
  console.log(`├${"─".repeat(26)}┬${"─".repeat(7)}┬${"─".repeat(7)}┬${"─".repeat(7)}┬${"─".repeat(7)}┬${"─".repeat(7)}┬${"─".repeat(8)}┤`);
  console.log("│ Scenario                 │  mean │   min │   max │   p50 │   p95 │    p99 │");
  console.log(`├${"─".repeat(26)}┼${"─".repeat(7)}┼${"─".repeat(7)}┼${"─".repeat(7)}┼${"─".repeat(7)}┼${"─".repeat(7)}┼${"─".repeat(8)}┤`);

  for (const { label, s } of results) {
    const name = label.padEnd(24);
    console.log(
      `│ ${name} │ ${String(s.mean).padStart(5)} │ ${String(s.min).padStart(5)} │ ` +
      `${String(s.max).padStart(5)} │ ${String(s.p50).padStart(5)} │ ` +
      `${String(s.p95).padStart(5)} │ ${String(s.p99).padStart(6)} │`
    );
  }

  console.log(`└${"─".repeat(26)}┴${"─".repeat(7)}┴${"─".repeat(7)}┴${"─".repeat(7)}┴${"─".repeat(7)}┴${"─".repeat(7)}┴${"─".repeat(8)}┘`);

  const b = results.find((r) => r.label === "baseline");
  const d = results.find((r) => r.label === "defended");
  if (b && d) {
    const overhead = (parseFloat(d.s.mean) - parseFloat(b.s.mean)).toFixed(3);
    const pct      = ((parseFloat(overhead) / parseFloat(b.s.mean)) * 100).toFixed(1);
    console.log(`\n  Gateway overhead: +${overhead} ms mean (+${pct}% relative to baseline)`);
  }
}

function printResourceUsage(before, after) {
  if (!before || !after) {
    console.log("\n  Gateway /metrics unavailable — skipping resource usage report.");
    return;
  }
  const mb  = (bytes) => (bytes / 1024 / 1024).toFixed(2);
  const us  = (micros) => (micros / 1000).toFixed(1);

  console.log("\n  Gateway resource usage (during benchmark load):");
  console.log(`    RSS memory  : ${mb(before.memory.rss)} MB → ${mb(after.memory.rss)} MB  (Δ ${mb(after.memory.rss - before.memory.rss)} MB)`);
  console.log(`    Heap used   : ${mb(before.memory.heapUsed)} MB → ${mb(after.memory.heapUsed)} MB  (Δ ${mb(after.memory.heapUsed - before.memory.heapUsed)} MB)`);
  console.log(`    CPU user    : ${us(after.cpu.user - before.cpu.user)} ms`);
  console.log(`    CPU system  : ${us(after.cpu.system - before.cpu.system)} ms`);
}

function writeCsv(results) {
  const lines = ["scenario,latency_ms"];
  for (const { label, samples } of results) {
    for (const ms of samples) lines.push(`${label},${ms.toFixed(3)}`);
  }
  fs.writeFileSync(CSV_OUT, lines.join("\n") + "\n");
  console.log(`\n  Raw data → ${CSV_OUT}`);
  console.log("  Plot with: pandas / matplotlib / Excel / R");
}

async function main() {
  console.log("╔════════════════════════════════════════════════════╗");
  console.log("║   Secure MCP Gateway — Benchmark                   ║");
  console.log(`║   requests: ${N_REQUESTS}   warmup: ${N_WARMUP}   sessions: ${N_SESSIONS}`.padEnd(53) + "║");
  console.log("╚════════════════════════════════════════════════════╝");

  process.stdout.write("\n[bench] Starting baseline server...\n");
  const baselineProc = await startProcess(
    path.join(ROOT, "tests", "insecure_mcp2_http.js"),
    { INSECURE_PORT: String(BASELINE_PORT), MCP2_ARGS },
    `listening on http://127.0.0.1:${BASELINE_PORT}`
  );
  process.stdout.write("[bench] Baseline server ready.\n");

  process.stdout.write("[bench] Starting Gateway (S)...\n");
  const gatewayProc = await startProcess(
    path.join(ROOT, "secure-proxy", "server.js"),
    {
      SECURE_PROXY_PORT:   String(GATEWAY_PORT),
      ENABLE_TLS:          "false",
      ENABLE_MTLS:         "false",
      CALLER_KEYS_CONFIG,
      MCP2_ARGS,
      MAX_OPS_PER_SESSION: "999999", 
    },
    `S listening on http://127.0.0.1:${GATEWAY_PORT}`
  );
  process.stdout.write("[bench] Gateway ready.\n");
  await sleep(300); 

  try {
    process.stdout.write("\n[bench] Establishing benchmark session...\n");
    const sid = await establishSession();
    process.stdout.write(`[bench] Session: ${sid}\n`);

    const metricsBefore = await getJson(GATEWAY_METRICS);

    const r1 = await benchBaseline();
    const r2 = await benchDefended(sid);
    const r3 = await benchSessionEstablishment();

    const metricsAfter = await getJson(GATEWAY_METRICS);

    const results = [
      { label: r1.label, s: computeStats(r1.samples), samples: r1.samples },
      { label: r2.label, s: computeStats(r2.samples), samples: r2.samples },
      { label: r3.label, s: computeStats(r3.samples), samples: r3.samples },
    ];

    printTable(results);
    printResourceUsage(metricsBefore, metricsAfter);
    writeCsv(results);

  } finally {
    process.stdout.write("\n[bench] Stopping servers...\n");
    await Promise.all([stopProcess(baselineProc), stopProcess(gatewayProc)]);
    process.stdout.write("[bench] Done.\n");
  }
}

main().catch((e) => {
  console.error("\n[bench] Fatal:", e.message || e);
  process.exit(1);
});
