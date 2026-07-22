# Secure MCP Gateway

## Overview

Secure MCP Gateway provides authenticated, integrity-protected, and policy-controlled tool invocation between MCP clients and servers.

```mermaid
flowchart LR
    Client["Clients"] --> Upstream["Upstream MCP Server"]
    Upstream -->|"MCP request"| Gateway["Secure MCP Gateway"]
    Gateway -->|"Authorized request"| Downstream["Downstream MCP Server"]

    classDef endpoint fill:#F8FAFC,stroke:#64748B,color:#0F172A;
    classDef gateway fill:#2563EB,stroke:#1D4ED8,color:#FFFFFF,stroke-width:2px;

    class Client,Upstream,Downstream endpoint;
    class Gateway gateway;
```

The gateway targets five MCP-level attack classes: **impersonation, replay,
request tampering, session hijacking, and unauthorized tool access**. **MITM
interception** is evaluated separately at the TLS transport layer.

## Security Design

Requests pass through five enforcement layers before reaching the MCP server:

| Layer | Mechanism | Purpose |
| --- | --- | --- |
| 1 | Method allowlist | Rejects unsupported JSON-RPC methods |
| 2 | TLS / mTLS | Protects traffic and authenticates clients |
| 3 | Signed requests | Verifies caller identity, timestamp, and nonce |
| 4 | Certificate binding | Binds the client certificate to `caller_id` |
| 5 | Session state and ACL | Enforces handshake state, HMAC, quotas, and tool permissions |

## Setup

Install **Node.js**, then install the project dependencies:

```bash
npm install
```

The included keys are for local experiments only.

## Running Experiments

```bash
# Quick end-to-end demonstration
node tests/e2e_demo.js

# Compare baseline and protected outcomes
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/defense_eval.js

# Measure processing and session-establishment latency
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/benchmark.js
```

## Expected Results

The validated protected suite reports:

```text
28 ran   0 skipped   0 errors
```

Reference results from one local benchmark run:

| Scenario | Mean | p95 |
| --- | ---: | ---: |
| Baseline processing | 0.398 ms | 0.557 ms |
| Defended processing | 0.377 ms | 0.582 ms |
| Session establishment | 6.560 ms | 10.623 ms |

Results vary by environment; rerun the experiments for current measurements.
