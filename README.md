# Secure MCP Gateway

## Overview

This project evaluates the security properties of a secure middleware (S) in a multi-MCP setting:

`client → MCP1 → S → MCP2`

- **MCP1**: a potentially malicious MCP that attempts to access downstream capabilities  
- **MCP2**: a trusted MCP exposing sensitive filesystem operations  
- **S**: a security middleware placed between two MCPs

We focus on common client-server attack vectors, including:

- impersonation  
- tampering  
- replay attacks  
- session hijacking  
- unauthorized access  
- man-in-the-middle (MITM) attacks  

All experiments are conducted by actively simulating adversarial requests and observing whether the middleware correctly enforces security policies.

## Architecture

Baseline:   client → MCP1 → MCP2  
Defended:   client → MCP1 → S → MCP2  

## Security Design

### Layer 1: Communication Security

- Impersonation protection using public key signatures  
- Replay protection using timestamp and nonce enforcement  
- Message integrity enforced through signature-bound requests  
- Session security via a session state machine  
- MITM protection using TLS / mTLS  

### Layer 2: Capability Security

- Authorization to control tool access  
- Least privilege by exposing only safe capabilities  
- Tool isolation to prevent access to sensitive operations  


## Project Structure

- secure-proxy/ — security middleware S  
- malicious-mcp1/ — malicious MCP1
- tests/ — baseline and defended tests
- workspace/ — demo files, including public and secret data


## Key Components

- secure-proxy/server.js — implementation of S  
- malicious-mcp1/mcp1.js — malicious MCP1  
- tests/baseline_attacks.js — baseline attacks before S
- tests/baseline_mitm.js — HTTP MITM tests before S  
- tests/client.js — security tests for S  
- tests/mitm_protected.js — MITM test with TLS-enabled S
- tests/e2e_demo.js — end-to-end baseline and defended demo  

## Setup

Install dependencies:
```bash
npm install
```

Generate keys:
```bash
openssl genrsa -out secure-proxy/certs/mcp1_private.pem 2048
openssl rsa -in secure-proxy/certs/mcp1_private.pem -pubout -out secure-proxy/certs/mcp1_public.pem
```

(Optional: for session hijack test)
```bash
openssl genrsa -out secure-proxy/certs/mcp2_private.pem 2048
openssl rsa -in secure-proxy/certs/mcp2_private.pem -pubout -out secure-proxy/certs/mcp2_public.pem
```