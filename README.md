# Secure MCP Gateway

## Overview

This project evaluates the security properties of a secure middleware (S) in a multi-MCP setting:

`client → MCP1 → S → MCP2`

- **MCP1**: a potentially malicious MCP that attempts to access downstream capabilities  
- **MCP2**: a trusted MCP exposing sensitive filesystem operations  
- **S**: a security middleware placed between two MCPs

We focus on common client-server attack vectors, including:

- impersonation  
- replay attacks 
- tampering  
- session hijacking 
- unauthorized access  
- man-in-the-middle (MITM) attacks  

All experiments are conducted by actively simulating adversarial requests and observing whether the middleware correctly enforces security policies.

## Architecture

Baseline:   client → MCP1 → MCP2  
Defended:   client → MCP1 → S → MCP2  

## Security Design

### Layer 1: Communication Security

- Authentication: public key signatures  
- Replay protection: timestamp and nonce  
- Integrity: signed requests  
- Session control: state machine enforcement  
- Secure channel: TLS / mTLS  
 
### Layer 2: Capability Security

- Authorization
- Least privilege  
- Tool isolation  


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
- tests/protected_attacks.js — security tests for S  
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