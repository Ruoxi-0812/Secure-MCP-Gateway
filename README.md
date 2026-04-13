# Secure MCP Gateway

## Overview

This project evaluates the security properties of a secure middleware (S) in a multi-MCP setting:
 
```
client → MCP1 → S → MCP2
```
 
- **MCP1** — a potentially malicious MCP that tries to steal data from downstream
- **S (Gateway)** — the secure middleware being evaluated; enforces 5 defence layers
- **MCP2** — a trusted filesystem MCP with access to sensitive files
 
We focus on common client-server attack vectors, including:

- impersonation
- replay attacks
- tampering
- session hijacking
- unauthorized access
- man-in-the-middle (MITM) attacks

---

## 5-Layer Security Design

Each request to S passes through five sequential defence layers before any tool is forwarded to MCP2.

| Layer | Mechanism | What it blocks |
|-------|-----------|----------------|
| 1 | **Method allowlist** | Unknown or disallowed JSON-RPC methods (`not_allowed_method`) |
| 2 | **TLS / mTLS** | Network eavesdropping, MITM; mTLS also rejects uncertified clients |
| 3 | **Cryptographic identity** | Impersonation, message tampering, replay — RSA-SHA256 signature over the full canonical request body; timestamp window + nonce cache |
| 4 | **mTLS CN binding** | Certificate/identity mismatch between TLS client cert and claimed `caller_id` |
| 5 | **Session state machine + ACL** | Session hijacking, skipped handshakes, forged proofs, unauthorised tool calls |


---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Generate RSA key pairs

Required for all protected tests, benchmark, and defense evaluation:

```bash
openssl genrsa -out secure-proxy/certs/mcp1_private.pem 2048
openssl rsa -in secure-proxy/certs/mcp1_private.pem -pubout \
        -out secure-proxy/certs/mcp1_public.pem
```

For the session hijack (`session_mismatch`) test only:

```bash
openssl genrsa -out secure-proxy/certs/mcp2_private.pem 2048
openssl rsa -in secure-proxy/certs/mcp2_private.pem -pubout \
        -out secure-proxy/certs/mcp2_public.pem
```

### 3. Register callers

`secure-proxy/caller_keys.json` maps each `caller_id` to its public key path.  
The Gateway hot-reloads this file at runtime — no restart required.

```json
{
  "mcp1": "./certs/mcp1_public.pem"
}
```

To add a second caller, add an entry and save the file; S picks it up immediately.

---

## Running the Experiments

### End-to-end demo

Shows the attack succeeding without S, then being blocked with S:

```bash
node tests/e2e_demo.js
```

### Baseline attacks (no S)

```bash
# Start the unprotected MCP2 HTTP wrapper first:
node tests/insecure_mcp2_http.js

# Run all 6 attacks:
node tests/baseline_attacks.js

# Run a specific attack:
node tests/baseline_attacks.js impersonation
node tests/baseline_attacks.js replay
node tests/baseline_attacks.js tampering
node tests/baseline_attacks.js session
node tests/baseline_attacks.js acl
node tests/baseline_attacks.js mitm
```

For attacks tampering and MITM visibility, start the MITM proxy first:

```bash
node tests/baseline_mitm.js                   
MITM_TAMPER=true node tests/baseline_mitm.js 
```

### Protected attacks (with S)

Start S first:

```bash
node secure-proxy/server.js
```

**Run all tests at once:**

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js
```

**Run a single test case:**

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js <test>
```

| Attack | Test case | Expected S response |
|--------|-----------|---------------------|
| **1 — Impersonation** | `unknowncaller` | 403 `unknown_caller` |
| | `noauth` | 403 `missing_auth` |
| | `missing_caller_id` | 403 `missing_caller_id` |
| | `missing_timestamp` | 403 `missing_timestamp` |
| | `missing_nonce` | 403 `missing_nonce` |
| | `missing_signature` | 403 `missing_signature` |
| **2 — Replay** | `replay` | 403 `replay_nonce_reused` |
| | `oldts` | 403 `timestamp_out_of_window` |
| | `futurets` | 403 `timestamp_out_of_window` |
| **3 — Tampering** | `badsig` | 403 `bad_signature` |
| | `tamper_method` | 403 `bad_signature` |
| | `tamper_auth` | 403 `bad_signature` |
| **4 — Session Hijacking** | `bypass` | 403 `missing_session_id` |
| | `session_mismatch` ¹ | 403 `session_caller_mismatch` |
| | `badready` | 403 `bad_ready_proof` |
| | `readytimeout` ² | 403 `ready_timeout` |
| | `quota` | 403 `session_ops_exhausted` |
| | `unknown_session` | 403 `unknown_session` |
| | `double_ready` | 403 `bad_session_state` |
| | `not_ready_session` | 403 `bad_session_state` |
| **5 — Unauthorized Tool Access** | `acldeny` | 403 `tool_not_allowed` |
| | `listfilter` | 200 (forbidden tools hidden) |
| | `write_file_denied` | 403 `tool_not_allowed` |
| | `allowed_tool` | 200 (positive control) |
| | `unknown_method` | 403 `not_allowed_method` |
| **6 — MITM** | see `mitm_protected.js` | TLS blocks interception |

**¹ `session_mismatch`** — requires a second caller registered in `caller_keys.json` and its private key passed via env:

```bash
# Add mcp2 to secure-proxy/caller_keys.json first:
# { "mcp1": "./certs/mcp1_public.pem", "mcp2": "./certs/mcp2_public.pem" }

MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  HIJACK_PRIVATE_KEY_PATH=secure-proxy/certs/mcp2_private.pem \
  node tests/protected_attacks.js
```

**² `readytimeout`** — skipped by default because it intentionally waits `READY_WINDOW_MS + 1 s` (default: 61 s):

```bash
SKIP_SLOW=false MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js
```

### MITM against TLS-enabled S

**Generate TLS certs:**

```bash
# Fake MITM cert — self-signed with a different CA so the client rejects it
openssl genrsa -out secure-proxy/certs/mitm.key 2048
openssl req -new -x509 -days 3650 -key secure-proxy/certs/mitm.key \
  -out secure-proxy/certs/mitm.crt -subj "//CN=fake-mitm"
```

**Start Gateway with TLS:**

```bash
ENABLE_TLS=true node secure-proxy/server.js
```

**Run the MITM test:**

```bash
CLIENT_SCRIPT=tests/protected_attacks.js \
  TLS_CA_PATH=secure-proxy/certs/ca.crt \
  MITM_CERT_PATH=secure-proxy/certs/mitm.crt \
  MITM_KEY_PATH=secure-proxy/certs/mitm.key \
  MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/mitm_protected.js
```

---

### Defense evaluation

Starts both servers automatically, runs all attacks against baseline and S, then measures latency overhead and resource usage:

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/defense_eval.js
```

Output includes:
- Per-attack verdict table: `✗ VULNERABLE` (baseline) vs `✓ BLOCKED` (S)
- Latency table: mean / p50 / p95 / p99 for baseline, defended, and session establishment
- Absolute and relative overhead (+X ms, +Y%)
- Gateway RSS memory, heap, and CPU delta

Tune the number of requests:

```bash
EVAL_PERF_N=100 EVAL_PERF_NSESS=20 \
  MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/defense_eval.js
```

### Performance benchmark

Runs 3 scenarios and writes raw per-request latencies to `benchmark_results.csv` for charting:

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/benchmark.js

# More requests:
BENCH_N=200 BENCH_N_SESSIONS=30 \
  MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/benchmark.js
```

---

## Topology Notes

This implementation models a single-hop trust boundary (`MCP1 → S → MCP2`).  
In a chain or mesh topology (`MCP1 → S₁ → MCP2 → S₂ → MCP3`), each downstream  
connection point can deploy its own Gateway instance with its own `caller_keys.json`  
and `TOOL_POLICIES`. The design composes: each S independently enforces its local  
policy without requiring a centralised coordinator.