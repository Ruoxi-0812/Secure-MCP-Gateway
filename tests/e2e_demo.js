"use strict";

/**
 * End-to-end demo  
 *
 * - baseline: client -> MCP1 -> MCP2 succeeds
 * - defended: client -> MCP1 -> S -> MCP2 fails
 */

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const ROOT = path.join(__dirname, "..");
const LOG_FILE = path.join(ROOT, "malicious-mcp1", "logs", "app.log");

function runNode(script, env, inputObj) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [script], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d) => (stdout += d.toString("utf8")));
    proc.stderr.on("data", (d) => (stderr += d.toString("utf8")));
    proc.on("error", reject);
    proc.on("close", (code) => resolve({ code, stdout, stderr }));

    if (inputObj) {
      proc.stdin.write(JSON.stringify(inputObj));
    }
    proc.stdin.end();
  });
}

function clearLog() {
  fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
  fs.writeFileSync(LOG_FILE, "", "utf8");
}

function readLog() {
  return fs.existsSync(LOG_FILE) ? fs.readFileSync(LOG_FILE, "utf8") : "";
}

async function baseline() {
  clearLog();
  const req = {
    jsonrpc: "2.0",
    id: "1",
    method: "tools/call",
    params: {
      name: "log_ops.write_log",
      arguments: { message: "baseline attack trigger" },
    },
  };

  const result = await runNode(path.join(ROOT, "malicious-mcp1", "mcp1.js"), {
    DOWNSTREAM_MODE: "direct",
    MCP2_COMMAND: process.execPath,
    MCP2_ARGS: JSON.stringify([
      path.join(ROOT, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js"),
      path.join(ROOT, "workspace"),
    ]),
    SECRET_PATH: path.join(ROOT, "workspace", "sandbox", "secret.txt"),
  }, req);

  console.log("baseline stdout");
  console.log(result.stdout.trim());
  console.log("baseline stderr");
  console.log(result.stderr.trim() || "(none)");
  console.log("baseline log");
  console.log(readLog().trim() || "(empty)");
}

async function defended() {
  clearLog();
  const req = {
    jsonrpc: "2.0",
    id: "1",
    method: "tools/call",
    params: {
      name: "log_ops.write_log",
      arguments: { message: "defended attack trigger" },
    },
  };

  const result = await runNode(path.join(ROOT, "malicious-mcp1", "mcp1.js"), {
    DOWNSTREAM_MODE: "via_s",
    S_HOST: "127.0.0.1",
    S_PORT: "4000",
    S_PATH: "/rpc",
    S_USE_TLS: "false",
    CALLER_ID: "mcp1",
    MCP1_PRIVATE_KEY_PATH: path.join(ROOT, "secure-proxy", "certs", "mcp1_private.pem"),
    SECRET_PATH: path.join(ROOT, "workspace", "sandbox", "secret.txt"),
  }, req);

  console.log("defended stdout");
  console.log(result.stdout.trim());
  console.log("defended stderr");
  console.log(result.stderr.trim() || "(none)");
  console.log("defended log");
  console.log(readLog().trim() || "(empty)");
}

async function main() {
  const mode = process.argv[2] || "baseline";
  if (mode === "baseline") return baseline();
  if (mode === "defended") return defended();
  throw new Error(`Unknown mode: ${mode}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});