"use strict";

/**
 * Baseline attack tests before S.
 *
 * Demonstrates that, before S, the following are present:
 * - Impersonation: no caller verification
 * - Replay: same request accepted repeatedly
 * - Tampering: MITM can change request path
 * - No session control: sensitive tools callable directly
 * - MITM visibility: proxy can read/modify traffic
 */

const http = require("http");
const path = require("path");

const TARGET_URL = process.env.TARGET_URL || "http://127.0.0.1:4100/rpc";
const MITM_URL = process.env.MITM_URL || "http://127.0.0.1:4444/rpc";
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
          try {
            parsed = JSON.parse(data);
          } catch {}
          resolve({ status: res.statusCode, raw: data, json: parsed });
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function testImpersonation() {
  console.log("\n Baseline: Impersonation exists ");

  await postJson(TARGET_URL, {
    jsonrpc: "2.0",
    id: "warmup-1",
    method: "tools/list",
    params: {},
  });

  const body = {
    jsonrpc: "2.0",
    id: "imp-2",
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { path: SECRET_PATH },
    },
    auth: {
      caller_id: "fake-admin",
      timestamp: 123,
      nonce: "reused",
      signature: "totally-fake",
    },
  };

  const r = await postJson(TARGET_URL, body);
  console.log(r.status, JSON.stringify(r.json || r.raw, null, 2));
  console.log("Expected: baseline ignores the fake auth block entirely and still returns the file");
}

async function testReplay() {
  console.log("\n Baseline: Replay exists ");
  const body = {
    jsonrpc: "2.0",
    id: "rep-1",
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { path: SECRET_PATH },
    },
  };
  const r1 = await postJson(TARGET_URL, body);
  const r2 = await postJson(TARGET_URL, body);
  console.log("first:", r1.status, r1.json || r1.raw);
  console.log("second:", r2.status, r2.json || r2.raw);
}

async function testNoSessionControl() {
  console.log("\n Baseline: No session control ");
  const body = {
    jsonrpc: "2.0",
    id: "sess-1",
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { path: SECRET_PATH },
    },
  };
  const r = await postJson(TARGET_URL, body);
  console.log(r.status, r.json || r.raw);
}

async function testTamperingViaMitm() {
  console.log("\n Baseline: Tampering ");
  console.log("Run mitm_network_before_tls.js with MITM_TAMPER=true before this test");
  const body = {
    jsonrpc: "2.0",
    id: "tamper-1",
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { path: HARMLESS_PATH },
    },
  };
  const r = await postJson(MITM_URL, body);
  console.log(r.status, JSON.stringify(r.json || r.raw, null, 2));
  console.log("Expected: MITM changes harmless path into secret path, so the returned content should no longer be the harmless file");
}

async function main() {
  const mode = process.argv[2] || "all";
  if (mode === "impersonation" || mode === "all") await testImpersonation();
  if (mode === "replay" || mode === "all") await testReplay();
  if (mode === "session" || mode === "all") await testNoSessionControl();
  if (mode === "tampering" || mode === "all") await testTamperingViaMitm();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
