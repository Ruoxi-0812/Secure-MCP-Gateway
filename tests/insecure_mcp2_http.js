"use strict";

/**
 * Insecure baseline wrapper around MCP2.
 *
 * Purpose:
 * - expose MCP2 over plain HTTP with no auth, no nonce, no session, no TLS
 * - make baseline attacks observable before adding S
 *
 * Upstream: HTTP POST /rpc
 * Downstream: spawn MCP2 once over stdio
 */

const express = require("express");
const { spawn } = require("child_process");
const readline = require("readline");
const path = require("path");
const http = require("http");

const PORT = Number(process.env.INSECURE_PORT || 4100);
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "256kb";
const DOWNSTREAM_TIMEOUT_MS = Number(process.env.DOWNSTREAM_TIMEOUT_MS || 15000);

const MCP2_COMMAND = process.env.MCP2_COMMAND || process.execPath;
const MCP2_ARGS = process.env.MCP2_ARGS
  ? JSON.parse(process.env.MCP2_ARGS)
  : [
      path.join(
        __dirname,
        "..",
        "node_modules",
        "@modelcontextprotocol",
        "server-filesystem",
        "dist",
        "index.js"
      ),
      path.join(__dirname, "..", "workspace"),
    ];

let child = null;
let rl = null;
const pending = new Map();
let initialized = false;

function startMcp2() {
  if (child) return;
  child = spawn(MCP2_COMMAND, MCP2_ARGS, {
    stdio: ["pipe", "pipe", "inherit"],
    env: { ...process.env, MCP_TRANSPORT: "stdio" },
  });

  rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const trimmed = String(line).trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      console.log("[insecure-mcp2-http] non-json downstream line:", trimmed);
      return;
    }
    if (msg.id !== undefined && msg.id !== null) {
      const key = String(msg.id);
      const waiter = pending.get(key);
      if (waiter) {
        clearTimeout(waiter.timer);
        pending.delete(key);
        waiter.resolve(msg);
      }
    } else {
      console.log("[insecure-mcp2-http] downstream notification:", JSON.stringify(msg));
    }
  });

  child.on("exit", (code, signal) => {
    console.error("[insecure-mcp2-http] downstream exited", { code, signal });
    for (const [id, waiter] of pending) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error("downstream exited"));
      pending.delete(id);
    }
    child = null;
    rl = null;
    initialized = false;
  });
}

function sendDownstream(msg, timeoutMs = DOWNSTREAM_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    startMcp2();
    const id = msg.id;
    if (id === undefined || id === null) {
      child.stdin.write(JSON.stringify(msg) + "\n");
      return resolve({ ok: true });
    }

    const key = String(id);
    const timer = setTimeout(() => {
      pending.delete(key);
      reject(new Error(`timeout waiting for downstream id=${key}`));
    }, timeoutMs);

    pending.set(key, { resolve, reject, timer });
    child.stdin.write(JSON.stringify(msg) + "\n");
  });
}

async function initializeIfNeeded() {
  if (initialized) return;
  await sendDownstream({
    jsonrpc: "2.0",
    id: "init",
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "insecure-wrapper", version: "1.0.0" },
    },
  });
  await sendDownstream({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
  initialized = true;
}

function stripForDownstream(body) {
  return {
    jsonrpc: body?.jsonrpc || "2.0",
    id: body?.id,
    method: body?.method,
    params: body?.params,
  };
}

const app = express();
app.use(express.json({ limit: JSON_BODY_LIMIT }));

app.post("/rpc", async (req, res) => {
  try {
    await initializeIfNeeded();
    const body = req.body;
    console.log("[insecure-mcp2-http] upstream request:", JSON.stringify(body));
    
    const downstreamBody = stripForDownstream(body);
    const response = await sendDownstream(downstreamBody);
    console.log("[insecure-mcp2-http] downstream response:", JSON.stringify(response));
    return res.status(200).json(response);
  } catch (e) {
    return res.status(502).json({
      jsonrpc: "2.0",
      id: req.body?.id ?? null,
      error: { code: 502, message: String(e.message || e) },
    });
  }
});

const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`[insecure-mcp2-http] listening on http://127.0.0.1:${PORT}/rpc`);
});
