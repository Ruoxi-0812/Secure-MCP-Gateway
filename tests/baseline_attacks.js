"use strict";

const fs   = require("fs");
const path = require("path");

// ── Logging setup ─────────────────────────────────────────────────────────────
// All console output is mirrored to logs/baseline_attacks_<timestamp>.log
const LOGS_DIR = path.join(__dirname, "..", "logs");
fs.mkdirSync(LOGS_DIR, { recursive: true });
const LOG_FILE = path.join(
  LOGS_DIR,
  `baseline_attacks_${new Date().toISOString().replace(/[:.]/g, "-")}.log`
);
const logStream = fs.createWriteStream(LOG_FILE, { flags: "a" });

const _log   = console.log.bind(console);
const _error = console.error.bind(console);
console.log   = (...args) => { const line = args.join(" "); _log(line);   logStream.write(line + "\n"); };
console.error = (...args) => { const line = args.join(" "); _error(line); logStream.write("[ERROR] " + line + "\n"); };
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Baseline attack tests — no Gateway (S) deployed.
 *
 * Target: MCP2 exposed directly over HTTP via insecure_mcp2_http.js.
 * All six attacks succeed here because there are no defences without S.
 *
 * ┌────┬──────────────────────────┬────────────────────────────────────────┐
 * │ #  │ Attack                   │ Baseline outcome (no S)                │
 * ├────┼──────────────────────────┼────────────────────────────────────────┤
 * │ 1  │ Impersonation            │ Fake auth block ignored — 200 OK       │
 * │ 2  │ Replay                   │ Same request accepted twice — 200 OK   │
 * │ 3  │ Tampering                │ MITM rewrites path — altered response  │
 * │ 4  │ No Session Enforcement   │ Tools callable without s.init/s.ready  │
 * │ 5  │ Unauthorized Tool Access │ read_file on secret succeeds freely    │
 * │ 6  │ MITM Visibility          │ Proxy reads plaintext traffic verbatim │
 * └────┴──────────────────────────┴────────────────────────────────────────┘
 *
 * Attacks 3 and 6 require the MITM proxy to be running first:
 *   node tests/baseline_mitm.js                    (visibility only)
 *   MITM_TAMPER=true node tests/baseline_mitm.js   (also tampers the path)
 */

const http = require("http");

const TARGET_URL = process.env.TARGET_URL || "http://127.0.0.1:4100/rpc";
const MITM_URL   = process.env.MITM_URL   || "http://127.0.0.1:4444/rpc";
const SECRET_PATH =
  process.env.SECRET_PATH ||
  path.join(__dirname, "..", "workspace", "sandbox", "secret.txt");
const HARMLESS_PATH =
  process.env.HARMLESS_PATH ||
  path.join(__dirname, "..", "workspace", "public", "hello.txt");

function parseUrl(u) {
  const url = new URL(u);
  return {
    hostname: url.hostname,
    port: url.port ? Number(url.port) : 80,
    path: url.pathname + (url.search || ""),
  };
}

function postJson(urlStr, bodyObj) {
  const { hostname, port, path } = parseUrl(urlStr);
  const payload = Buffer.from(JSON.stringify(bodyObj), "utf8");
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname,
        port,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": payload.length,
        },
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

// ── Attack 1: Impersonation ────────────────────────────────────────────────
// Without S, MCP2 accepts all requests regardless of who sent them.
// A caller can claim any identity — the auth block is forwarded but never
// verified, so a fabricated caller_id and invalid signature are ignored.
async function testImpersonation() {
  section(1, "Impersonation");
  console.log("  Sending request with fabricated caller_id and invalid signature.");

  const r = await postJson(TARGET_URL, {
    jsonrpc: "2.0",
    id: "imp-1",
    method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
    auth: {
      caller_id: "fake-admin",
      timestamp: 123,
      nonce: "reused",
      signature: "totally-fake",
    },
  });

  console.log("Result:", r.status, JSON.stringify(r.json || r.raw, null, 2));
  console.log("Expected: 200 — auth block ignored, secret returned.");
}

// ── Attack 2: Replay ───────────────────────────────────────────────────────
// Without S, there is no nonce cache or timestamp window check.
// The identical request can be sent any number of times and always succeeds.
async function testReplay() {
  section(2, "Replay");
  console.log("  Sending the exact same request twice without modification.");

  const body = {
    jsonrpc: "2.0",
    id: "rep-1",
    method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
  };

  const r1 = await postJson(TARGET_URL, body);
  const r2 = await postJson(TARGET_URL, body);
  console.log("First :", r1.status, r1.json || r1.raw);
  console.log("Replay:", r2.status, r2.json || r2.raw);
  console.log("Expected: both succeed — no nonce deduplication.");
}

// ── Attack 3: Tampering ────────────────────────────────────────────────────
// Without signature verification, an in-path proxy can freely modify any
// field of the request before forwarding it to MCP2.
// Here the MITM proxy rewrites the file path from the harmless file to the
// secret file, upgrading a benign request into a sensitive one.
async function testTampering() {
  section(3, "Tampering");
  console.log("  Sending harmless read request through MITM proxy (MITM_TAMPER=true required).");
  console.log("  The proxy silently rewrites the file path to point at the secret.");

  const r = await postJson(MITM_URL, {
    jsonrpc: "2.0",
    id: "tamper-1",
    method: "tools/call",
    params: { name: "read_file", arguments: { path: HARMLESS_PATH } },
  });

  console.log("Result:", r.status, JSON.stringify(r.json || r.raw, null, 2));
  console.log("Expected: response contains the secret file, not the harmless file.");
}

// ── Attack 4: No Session Enforcement ──────────────────────────────────────
// S enforces a s.init → s.ready → tools/call state machine before
// any tool can be invoked. Without S there is no session concept — any tool
// can be called directly without establishing a session first.
async function testSessionBypass() {
  section(4, "No Session Enforcement");
  console.log("  Calling list_allowed_directories with no s.init/s.ready handshake.");

  const r = await postJson(TARGET_URL, {
    jsonrpc: "2.0",
    id: "sess-1",
    method: "tools/call",
    params: { name: "list_allowed_directories", arguments: {} },
  });

  console.log("Result:", r.status, r.json || r.raw);
  console.log("Expected: 200 — no session state machine enforced.");
}

// ── Attack 5: Unauthorized Tool Access ────────────────────────────────────
// S enforces TOOL_POLICIES: only explicitly allowlisted tools are forwarded
// to MCP2. Without S there is no ACL — any tool, including sensitive
// filesystem operations like read_file, is accessible to any caller.
async function testUnauthorizedToolAccess() {
  section(5, "Unauthorized Tool Access");
  console.log("  Calling read_file on the secret path — no ACL enforcement in baseline.");

  const r = await postJson(TARGET_URL, {
    jsonrpc: "2.0",
    id: "acl-1",
    method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
  });

  console.log("Result:", r.status, JSON.stringify(r.json || r.raw, null, 2));
  console.log("Expected: 200 — secret content returned, no capability check.");
}

// ── Attack 6: MITM Visibility ──────────────────────────────────────────────
// Without TLS, all traffic is plaintext. A network-adjacent attacker can
// observe both requests and responses in full — including secrets returned
// by MCP2 — without modifying anything.
async function testMitmVisibility() {
  section(6, "MITM Visibility");
  console.log("  Routing request through MITM proxy without tampering.");
  console.log("  Check proxy console output — full plaintext request and response are logged.");

  const r = await postJson(MITM_URL, {
    jsonrpc: "2.0",
    id: "mitm-1",
    method: "tools/call",
    params: { name: "read_file", arguments: { path: SECRET_PATH } },
  });

  console.log("Result:", r.status, r.json || r.raw);
  console.log("Expected: 200 — proxy intercepted and logged the full exchange.");
}

function section(n, title) {
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  Attack ${n}: ${title}`);
  console.log("═".repeat(60));
}

async function main() {
  console.log("╔════════════════════════════════════════════════════╗");
  console.log("║   Secure MCP Gateway — Baseline Attacks            ║");
  console.log("║   6 attacks against unprotected MCP2 (no S)       ║");
  console.log("╚════════════════════════════════════════════════════╝");

  const mode = process.argv[2] || "all";
  if (mode === "impersonation" || mode === "all") await testImpersonation();
  if (mode === "replay"        || mode === "all") await testReplay();
  if (mode === "tampering"     || mode === "all") await testTampering();
  if (mode === "session"       || mode === "all") await testSessionBypass();
  if (mode === "acl"           || mode === "all") await testUnauthorizedToolAccess();
  if (mode === "mitm"          || mode === "all") await testMitmVisibility();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
