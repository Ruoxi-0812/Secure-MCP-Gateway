"use strict";

/**
 * End-to-end baseline and defended demo
 *
 * Modes:
 * - baseline:        client -> mcp1.js       -> MCP2 directly    (attack succeeds)
 * - defended:        client -> mcp1_via_s.js -> S(http)  -> MCP2 (blocked by S)
 * - defended_tls:    client -> mcp1_via_s.js -> S(https) -> MCP2 (blocked by S)
 */

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

(function setupLog() {
  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `e2e_demo_${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const stream = fs.createWriteStream(file, { flags: "a" });
  for (const m of ["log", "warn", "error"]) {
    const orig = console[m].bind(console);
    const prefix = m === "error" ? "[ERROR] " : m === "warn" ? "[WARN] " : "";
    console[m] = (...a) => { const s = a.join(" "); orig(s); stream.write(prefix + s + "\n"); };
  }
})();

const ROOT = path.join(__dirname, "..");
const LOG_FILE = path.join(ROOT, "malicious-mcp1", "logs", "app.log");
const S_PORT = "4000";

function runNode(script, env, inputObj) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [script], {
      cwd: ROOT,
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (d) => {
      stdout += d.toString("utf8");
    });
    proc.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startSecureProxy({ enableTls }) {
  return new Promise((resolve, reject) => {
    const script = path.join(ROOT, "secure-proxy", "server.js");

    const env = {
      ...process.env,
      SECURE_PROXY_PORT: S_PORT,
      ENABLE_TLS: enableTls ? "true" : "false",
      ENABLE_MTLS: "false",
      CALLER_KEYS_CONFIG: path.join(ROOT, "secure-proxy", "caller_keys.json"),
      MCP2_COMMAND: process.execPath,
      MCP2_ARGS: JSON.stringify([
        path.join(
          ROOT,
          "node_modules",
          "@modelcontextprotocol",
          "server-filesystem",
          "dist",
          "index.js"
        ),
        path.join(ROOT, "workspace"),
      ]),
    };

    const proc = spawn(process.execPath, [script], {
      cwd: ROOT,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const cleanupListeners = () => {
      proc.stdout.removeAllListeners("data");
      proc.stderr.removeAllListeners("data");
      proc.removeAllListeners("error");
      proc.removeAllListeners("exit");
    };

    const readyMatcher = enableTls
      ? `S listening on https://127.0.0.1:${S_PORT}/rpc`
      : `S listening on http://127.0.0.1:${S_PORT}/rpc`;

    proc.stdout.on("data", (d) => {
      const text = d.toString("utf8");
      stdout += text;

      if (!settled && stdout.includes(readyMatcher)) {
        settled = true;
        cleanupListeners();
        resolve({
          proc,
          stdout,
          stderr,
        });
      }
    });

    proc.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });

    proc.on("error", (err) => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      reject(err);
    });

    proc.on("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      reject(
        new Error(
          `secure-proxy exited before ready (code=${code}, signal=${signal})\nstdout:\n${stdout}\nstderr:\n${stderr}`
        )
      );
    });

    setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      try {
        proc.kill("SIGTERM");
      } catch {}
      reject(
        new Error(
          `Timed out waiting for secure-proxy to be ready.\nstdout:\n${stdout}\nstderr:\n${stderr}`
        )
      );
    }, 5000);
  });
}

async function stopProcess(proc) {
  if (!proc || proc.killed) return;

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {}
    }, 2000);

    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });

    try {
      proc.kill("SIGTERM");
    } catch {
      clearTimeout(timer);
      resolve();
    }
  });
}

function printResult(label, result) {
  const SEP = "─".repeat(54);
  console.log(`\n${SEP}`);
  console.log(`  ${label} — stdout`);
  console.log(result.stdout.trim() || "  (empty)");
  console.log(`\n  ${label} — stderr`);
  console.log(result.stderr.trim() || "  (none)");
  console.log(`\n  ${label} — log`);
  console.log(readLog().trim() || "  (empty)");
  console.log(SEP);
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

  const result = await runNode(
    path.join(ROOT, "malicious-mcp1", "mcp1.js"),
    {
      DOWNSTREAM_MODE: "direct",
      MCP2_COMMAND: process.execPath,
      MCP2_ARGS: JSON.stringify([
        path.join(
          ROOT,
          "node_modules",
          "@modelcontextprotocol",
          "server-filesystem",
          "dist",
          "index.js"
        ),
        path.join(ROOT, "workspace"),
      ]),
      SECRET_PATH: path.join(ROOT, "workspace", "sandbox", "secret.txt"),
    },
    req
  );

  printResult("baseline", result);
}

async function runDefended({ enableTls, label, message }) {
  clearLog();

  const req = {
    jsonrpc: "2.0",
    id: "1",
    method: "tools/call",
    params: {
      name: "log_ops.write_log",
      arguments: { message },
    },
  };

  let sProc;
  try {
    const started = await startSecureProxy({ enableTls });
    sProc = started.proc;

    await sleep(300);

    const result = await runNode(
      path.join(ROOT, "malicious-mcp1", "mcp1_via_s.js"),
      {
        S_HOST: enableTls ? "localhost" : "127.0.0.1",
        S_PORT: S_PORT,
        S_PATH: "/rpc",
        S_USE_TLS: enableTls ? "true" : "false",
        S_CA_PATH: enableTls
          ? path.join(ROOT, "secure-proxy", "certs", "ca.crt")
          : "",
        CALLER_ID: "mcp1",
        MCP1_PRIVATE_KEY_PATH: path.join(
          ROOT,
          "secure-proxy",
          "certs",
          "mcp1_private.pem"
        ),
        SECRET_PATH: path.join(ROOT, "workspace", "sandbox", "secret.txt"),
      },
      req
    );

    printResult(label, result);
  } finally {
    await stopProcess(sProc);
  }
}

async function defended() {
  return runDefended({
    enableTls: false,
    label: "defended",
    message: "defended attack trigger",
  });
}

async function defendedTls() {
  return runDefended({
    enableTls: true,
    label: "defended_tls",
    message: "defended tls attack trigger",
  });
}

async function main() {
  const mode = process.argv[2] || "baseline";

  console.log("╔════════════════════════════════════════════════════╗");
  console.log("║   Secure MCP Gateway — End-to-End Demo             ║");
  console.log(`║   mode: ${mode}`.padEnd(53) + "║");
  console.log("╚════════════════════════════════════════════════════╝");

  if (mode === "baseline") return baseline();
  if (mode === "defended") return defended();
  if (mode === "defended_tls") return defendedTls();

  throw new Error(`Unknown mode: ${mode}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});