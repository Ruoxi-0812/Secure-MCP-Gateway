"use strict";

/**
 * MITM test with TLS-enabled S
 *
 * - start a fake HTTPS relay with an untrusted certificate
 * - show that a correctly configured client rejects it
 *
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

const PORT = Number(process.env.MITM_TLS_PORT || 4445);
const CERT_PATH = process.env.MITM_CERT_PATH || path.join(__dirname, "certs", "mitm.crt");
const KEY_PATH = process.env.MITM_KEY_PATH || path.join(__dirname, "certs", "mitm.key");
const CLIENT_SCRIPT = process.env.CLIENT_SCRIPT || path.join(__dirname, "client.js");
const TLS_CA_PATH = process.env.TLS_CA_PATH || path.join(__dirname, "certs", "ca.crt");
const CALLER_ID = process.env.CALLER_ID || "mcp1";
const MCP1_PRIVATE_KEY_PATH = process.env.MCP1_PRIVATE_KEY_PATH || path.join(__dirname, "certs", "mcp1_private.pem");

function ensureMitmCert() {
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) return;
  throw new Error(
    `Missing ${CERT_PATH} / ${KEY_PATH}. Create any self-signed cert for the MITM server.`
  );
}

function startFakeMitm() {
  ensureMitmCert();
  const server = https.createServer(
    {
      cert: fs.readFileSync(CERT_PATH),
      key: fs.readFileSync(KEY_PATH),
    },
    (req, res) => {
      console.log("received request unexpectedly");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, note: "If the client trusts this MITM cert, TLS verification is wrong" }));
    }
  );

  return new Promise((resolve) => {
    server.listen(PORT, () => {
      console.log(`fake HTTPS MITM listening on https://127.0.0.1:${PORT}/rpc`);
      resolve(server);
    });
  });
}

function runClientAgainstMitm() {
  return new Promise((resolve) => {
    const env = {
      ...process.env,
      S_URL: `https://127.0.0.1:${PORT}/rpc`,
      TLS_CA_PATH,
      CALLER_ID,
      MCP1_PRIVATE_KEY_PATH,
    };
    execFile(process.execPath, [CLIENT_SCRIPT, "demo"], { cwd: __dirname, env }, (error, stdout, stderr) => {
      resolve({ error, stdout, stderr });
    });
  });
}

async function main() {
  const server = await startFakeMitm();
  const result = await runClientAgainstMitm();
  console.log("client stdout");
  console.log(result.stdout.trim() || "(none)");
  console.log("client stderr");
  console.log(result.stderr.trim() || "(none)");
  if (result.error) {
    console.log("expected TLS failure");
    console.log(String(result.error.message || result.error));
  } else {
    console.log("Unexpected: client accepted the fake MITM TLS endpoint.");
    process.exitCode = 1;
  }
  server.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
