# Secure MCP Gateway

## Overview

This project evaluates the security properties of a secure middleware (S) placed between two MCP processes:

```
client → MCP1 → S → MCP2
```

- **MCP1** — a potentially malicious MCP that tries to steal data from downstream
- **S (Gateway)** — the secure middleware being evaluated; enforces 5 defence layers
- **MCP2** — a trusted filesystem MCP with access to sensitive files

MCP1 and MCP2 communicate via **stdio + JSON-RPC** (local subprocess, no network port).  
MCP1 and S communicate via **HTTP/HTTPS + JSON-RPC** (application-layer network request).  
S and MCP2 communicate via **stdio + JSON-RPC** (S spawns MCP2 as a child process).

Six attack categories are evaluated by running adversarial requests against both the unprotected baseline and the Gateway-protected configuration, and comparing outcomes.

---

## Architecture

```
Baseline (no S):   MCP1 ──stdio──► MCP2          (no authentication, no ACL)

Defended (with S): MCP1 ──HTTP/HTTPS──► S ──stdio──► MCP2
                              │
                         5 defence layers
```

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

> **Note on process names.** MCP has no system-enforced unique identifier equivalent to Android package names or app IDs. Process names are trivially spoofable. S therefore does not rely on process names; all identity claims are verified through Layer 3 cryptographic signatures using pre-registered RSA public keys.

> **Trust assumption.** S itself is assumed to be a trusted component (analogous to how browsers trust their pre-installed CA store). Key material and policies must be protected at deployment time. This is an explicit scope boundary, not a limitation of the cryptographic mechanisms.

---

## Project Structure

```
.
├── malicious-mcp1/
│   ├── mcp1.js            # Attack-only: calls MCP2 directly via stdio (bypasses S)
│   └── mcp1_via_s.js      # Same malicious intent, but routed through S (blocked by ACL)
│
├── secure-proxy/
│   ├── server.js          # Gateway S — Express server implementing 5 defence layers
│   ├── caller_keys.json   # Caller-ID → public-key map; hot-reloaded at runtime
│   └── certs/             # RSA key pairs and TLS certificates
│
├── tests/
│   ├── baseline_attacks.js    # 6 attacks against unprotected MCP2 (all succeed)
│   ├── baseline_mitm.js       # MITM proxy for baseline attacks 3 and 6
│   ├── protected_attacks.js   # 25 test cases against S (all blocked)
│   ├── mitm_protected.js      # MITM attempt against TLS-enabled S (blocked)
│   ├── e2e_demo.js            # End-to-end baseline vs. defended narrative demo
│   ├── insecure_mcp2_http.js  # HTTP wrapper: exposes MCP2 with no auth (baseline target)
│   ├── benchmark.js           # Performance benchmark: latency + resource usage
│   └── defense_eval.js        # Combined security + performance evaluation report
│
└── workspace/
    ├── public/hello.txt   # Harmless file (used in tampering tests)
    └── sandbox/secret.txt # Sensitive file (attack target)
```

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

### 4. (Optional) Generate TLS certificates

Required only for `ENABLE_TLS=true` / `ENABLE_MTLS=true` modes and `mitm_protected.js`.  
See comments inside `secure-proxy/server.js` for the full `openssl` CA + cert commands.

---

## Running the Experiments

### End-to-end demo

Shows the attack succeeding without S, then being blocked with S:

```bash
node tests/e2e_demo.js
```

### Baseline attacks (no S — all 6 succeed)

```bash
# Start the unprotected MCP2 HTTP wrapper first:
node tests/insecure_mcp2_http.js &

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

For attacks 3 (tampering) and 6 (MITM visibility), start the MITM proxy first:

```bash
node tests/baseline_mitm.js                   # visibility only
MITM_TAMPER=true node tests/baseline_mitm.js  # also rewrites the file path
```

### Protected attacks (with S — all blocked)

Start S first:

```bash
node secure-proxy/server.js
```

**Run all 25 tests at once (default):**

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js
```

Prints a per-test result and a summary table at the end. Two tests have special conditions (see notes below).

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

**² `readytimeout`** — skipped by default because it intentionally waits `READY_WINDOW_MS + 1 s` (default: 61 s). Two ways to run it:

```bash
# Option A — include the 61 s wait as-is
SKIP_SLOW=false MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js

# Option B — shorten the ready window on the Gateway side (4 s total wait)
READY_WINDOW_MS=3000 node secure-proxy/server.js        # Terminal 1
SKIP_SLOW=false MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/protected_attacks.js                       # Terminal 2
```

### MITM against TLS-enabled S

Verifies that a fake HTTPS relay is rejected by the client because its certificate is not signed by the trusted CA. The expected outcome is a TLS error — that is the passing result.

**Step 1 — Generate TLS certs (one-time setup):**

```bash
# CA
openssl genrsa -out secure-proxy/certs/ca.key 2048
openssl req -new -x509 -days 3650 -key secure-proxy/certs/ca.key \
  -out secure-proxy/certs/ca.crt -subj "/CN=TestCA"

# Server cert signed by the CA
openssl genrsa -out secure-proxy/certs/server.key 2048
openssl req -new -key secure-proxy/certs/server.key \
  -out secure-proxy/certs/server.csr -subj "/CN=127.0.0.1"
openssl x509 -req -days 3650 \
  -in secure-proxy/certs/server.csr \
  -CA secure-proxy/certs/ca.crt -CAkey secure-proxy/certs/ca.key \
  -CAcreateserial -out secure-proxy/certs/server.crt \
  -extfile <(echo "subjectAltName=IP:127.0.0.1")

# Fake MITM cert — self-signed with a different CA so the client rejects it
openssl genrsa -out secure-proxy/certs/mitm.key 2048
openssl req -new -x509 -days 3650 -key secure-proxy/certs/mitm.key \
  -out secure-proxy/certs/mitm.crt -subj "//CN=fake-mitm"
```

**Step 2 — Start Gateway with TLS:**

```bash
ENABLE_TLS=true node secure-proxy/server.js
```

**Step 3 — Run the MITM test:**

```bash
CLIENT_SCRIPT=tests/protected_attacks.js \
  TLS_CA_PATH=secure-proxy/certs/ca.crt \
  MITM_CERT_PATH=secure-proxy/certs/mitm.crt \
  MITM_KEY_PATH=secure-proxy/certs/mitm.key \
  MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/mitm_protected.js
```

The test starts a fake HTTPS server with the untrusted `tests/certs/mitm.crt`, then runs the client against it. The client must reject the connection — if it does, the test reports "certificate correctly rejected".

---

### Defense evaluation (security + performance, single report)

Starts both servers automatically, runs all 6 attacks against baseline and S, then measures latency overhead and resource usage:

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

### Performance benchmark (detailed, with CSV output)

Runs 3 scenarios and writes raw per-request latencies to `benchmark_results.csv` for charting:

```bash
MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/benchmark.js

# More requests:
BENCH_N=200 BENCH_N_SESSIONS=30 \
  MCP1_PRIVATE_KEY_PATH=secure-proxy/certs/mcp1_private.pem \
  node tests/benchmark.js
```

Produces a results table (mean / min / max / p50 / p95 / p99) and a line:

```
Gateway overhead: +X.XXX ms mean (+Y.Y% relative to baseline)
```

Raw data in `benchmark_results.csv` can be plotted with pandas / matplotlib / Excel / R.

---

## Caller Identity Registration

Caller IDs and their public keys are declared in `secure-proxy/caller_keys.json`:

```json
{
  "mcp1": "./certs/mcp1_public.pem",
  "mcp_analytics": "./certs/analytics_public.pem"
}
```

S watches this file with `fs.watch` and reloads it automatically whenever it changes.  
If the file is malformed, S keeps the previous key set — existing callers are never locked out.

---

## Topology Notes

This implementation models a single-hop trust boundary (`MCP1 → S → MCP2`).  
In a chain or mesh topology (`MCP1 → S₁ → MCP2 → S₂ → MCP3`), each downstream  
connection point can deploy its own Gateway instance with its own `caller_keys.json`  
and `TOOL_POLICIES`. The design composes: each S independently enforces its local  
policy without requiring a centralised coordinator.

---

## Environment Variables

### Gateway (secure-proxy/server.js)

| Variable | Default | Description |
|----------|---------|-------------|
| `SECURE_PROXY_PORT` | `4000` | Port S listens on |
| `ENABLE_TLS` | `false` | Require TLS on incoming connections |
| `ENABLE_MTLS` | `false` | Require mTLS client certificate |
| `CALLER_KEYS_CONFIG` | `./caller_keys.json` | Path to caller-ID → public-key map |
| `AUTH_TS_WINDOW_SEC` | `60` | Max timestamp skew allowed (seconds) |
| `MAX_OPS_PER_SESSION` | `10` | Tool calls allowed per session |
| `MCP2_ARGS` | — | JSON array: MCP2 command + allowed dirs |

### Tests / benchmark

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP1_PRIVATE_KEY_PATH` | — | Path to MCP1's RSA private key |
| `S_URL` | `http://127.0.0.1:4000/rpc` | Gateway endpoint for protected tests |
| `BENCH_N` | `100` | Requests per benchmark scenario |
| `BENCH_WARMUP` | `10` | Warmup requests (excluded from stats) |
| `BENCH_N_SESSIONS` | `20` | Session establishments to time |
| `EVAL_PERF_N` | `50` | Requests per scenario in defense_eval |
| `EVAL_PERF_NSESS` | `10` | Session establishments in defense_eval |
