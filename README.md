# Project Agnes — Firewall for Autonomous AI Agents

> **Project Agnes** is a high-performance runtime security and enforcement firewall for autonomous AI agents. It intercepts, evaluates, and governs agent actions deterministically *before* they can interact with the host operating system, filesystems, networks, tools, MCP servers, or external APIs.

---

## Architecture Overview

Autonomous AI agents operate in unpredictable and semi-trusted environments. When an agent hallucinates, encounters prompt injection, or executes malicious/adversarial instructions, traditional security models fail because the agent usually holds legitimate execution tokens.

Project Agnes acts as a fail-closed intermediary mediation plane:

```
+----------------------------------------------------------------+
|               Untrusted Input / Web Content / Prompts           |
+----------------------------------------------------------------+
                               |
                               v
+----------------------------------------------------------------+
|                     Autonomous AI Agent                        |
+----------------------------------------------------------------+
                               |
                               | (Action Request)
                               v
+================================================================+
|                       PROJECT AGNES                            |
|  - Deterministic Policy Engine (Fail-Closed, Priority-Based)   |
|  - Kernel Boundary Interceptor (Linux openat2 RESOLVE_BENEATH) |
|  - Stateful Session Coordinator & Capability Tracker           |
|  - Structured JSON Telemetry & Audit Logger                    |
+================================================================+
                               |
          +--------------------+--------------------+
          | (Allow & Enforced)                      | (Deny / Blocked)
          v                                         v
+--------------------+                     +--------------------+
| OS / MCP / Tools   |                     | 403 Forbidden /    |
| Filesystem / APIs  |                     | Action Blocked     |
+--------------------+                     +--------------------+
```

---

## Core Security Principles

1. **Deterministic Enforcement Path**:
   Security decisions are strictly deterministic. There is **no LLM in the security decision loop**, eliminating probabilistic bypasses, hallucinated permissions, and second-order prompt injections.

2. **Kernel-Enforced Boundary Confinement**:
   Enforces physical boundary invariants using native Linux `openat2` syscalls with `RESOLVE_BENEATH`. This renders classic attack vectors like symlink escapes, path traversals (`../../`), and Time-Of-Check to Time-Of-Use (TOCTOU) file race conditions impossible at the OS kernel layer.

3. **Strict Fail-Closed Default-Deny**:
   Any action, tool invocation, or resource access not explicitly permitted by a high-priority policy rule is denied by default.

4. **Auditable & Observable**:
   Every request generates a cryptographically traceable, correlation-tagged JSON audit record detailing the requested action, matched policy ID, rule ID, decision reason, enforcement action, and observed execution result.

---

## Repository Structure

```
├── apps/
│   ├── agnes-core/       # Axum HTTP API gateway, state coordinator & enforcement dispatcher
│   └── mock-agent/       # Deterministic action generator for security experiments and tests
├── crates/
│   ├── common/           # Typed action schemas (ActionPayload, ActionRequest), decisions, and events
│   ├── policy/           # Deterministic policy evaluation engine (rule priorities, path normalization)
│   ├── enforcement/      # Runtime OS enforcement gate (Linux openat2 kernel confinement)
│   ├── state/            # Session coordinator, capability tracking, and audit event history
│   └── telemetry/        # Structured JSON logger and in-memory event sinks
├── infra/
│   ├── docker/           # Production container definitions for agnes-core and mock-agent
│   ├── postgres/         # PostgreSQL persistence schema for events, sessions, and policies
│   └── targets/          # Mock targets for network and HTTP testing
├── docs/                 # Threat models, experiment reports, and vulnerability findings
└── tests/                # Comprehensive integration, fuzzing, adversarial bypass, and regression tests
```

---

## Prerequisites

- **Rust**: `1.80+` (Edition 2021)
- **Cargo**: Included with Rust toolchain
- **Docker & Docker Compose**: Optional, for multi-container deployments and Postgres integration
- **Operating System**: Linux (required for `openat2` kernel boundary confinement; fallbacks for non-Linux platforms)

---

## Getting Started

### 1. Build and Run Tests

Run the full suite of unit tests, integration tests, fuzzing suites, and adversarial bypass regression tests:

```bash
cargo test
```

### 2. Run Locally

#### Start the Agnes Gateway:
```bash
cargo run -p agnes-core
```
By default, the gateway listens on `http://0.0.0.0:8080`.

#### Run the Mock Agent:
In a separate terminal:
```bash
cargo run -p mock-agent
```

### 3. Run with Docker Compose

Spin up the complete environment including PostgreSQL, the Agnes Core gateway, a test HTTP target server, and the mock agent:

```bash
docker compose up --build
```

---

## HTTP API Reference

### Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "UP",
  "version": "0.1.0",
  "component": "agnes-core"
}
```

---

### Register a Policy
```http
POST /v1/policies
Content-Type: application/json
```
**Payload:**
```json
{
  "id": "policy-sandbox-read",
  "name": "Allow Read Operations in Sandbox",
  "version": 1,
  "rules": [
    {
      "id": "rule-allow-sandbox",
      "description": "Allow reads inside /sandbox",
      "decision": "Allow",
      "agent_pattern": "*",
      "action_types": ["ReadFile"],
      "resource_pattern": "/sandbox/*",
      "priority": 10
    },
    {
      "id": "rule-deny-etc",
      "description": "Deny reads from /etc",
      "decision": "Deny",
      "agent_pattern": "*",
      "action_types": ["ReadFile"],
      "resource_pattern": "/etc/*",
      "priority": 100
    }
  ]
}
```

---

### Process an Agent Action Request
```http
POST /v1/action
Content-Type: application/json
```
**Payload (Read File):**
```json
{
  "correlation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "agent_id": "agent-001",
  "action_type": "ReadFile",
  "target_resource": "/sandbox/data.txt",
  "payload": {
    "type": "ReadFile",
    "path": "/sandbox/data.txt"
  },
  "timestamp": "2026-10-10T12:00:00Z"
}
```

**Response (Allowed):**
```json
{
  "correlation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "test_id": null,
  "decision": "Allow",
  "reason": "Matched ALLOW rule: rule-allow-sandbox",
  "matched_policy_id": "policy-sandbox-read",
  "enforcement_action": "PermitExecution",
  "observed_result": "AccessSuccess",
  "output": "Content of the file...",
  "error_message": null
}
```

---

### Query Security Events
```http
GET /v1/events
```
Returns a chronological audit log of all security events, evaluations, and enforcement decisions.

---

### Inspect Agent Session State
```http
GET /v1/state/{agent_id}
```
Returns cumulative session statistics, action counters, and tracked capabilities for the given agent.

---

## Adversarial Hardening & Verification

Project Agnes is tested against real-world adversarial evasion techniques:

- **Path Traversal Attacks**: Attempts using relative escapes (e.g. `/sandbox/../../etc/passwd`) are filtered via lexical normalization and blocked by kernel confinement.
- **Symlink Escapes**: Malicious symlinks pointing outside the allowed sandbox are trapped and rejected by Linux `RESOLVE_BENEATH`.
- **TOCTOU Races**: Multi-threaded symlink replacement attacks are defended against using file descriptors bound to root confinement boundaries.
- **Null-Byte Injections**: Null-byte and control character bypasses are proactively sanitized before policy inspection.

To run the adversarial security test suite:
```bash
cargo test -p agnes-tests --test adversarial_bypass_002
cargo test -p agnes-tests --test adversarial_filesystem_fuzzing
cargo test -p agnes-tests --test regression_filesystem_boundary
```

---

## License

This project is licensed under the [MIT License](LICENSE).
