# BLACK WALL — Autonomous AI Security Firewall

> "Next-generation runtime security and enforcement firewall for autonomous AI agents."

## Architecture & Boundary
```
UNTRUSTED INPUT / WEB CONTENT
            |
            v
       AUTONOMOUS AGENT
            |
            v
      BLACK WALL (Deterministic Policy & Enforcement Plane)
            |
            v
      TOOLS / MCP / APIs
            |
            v
FILES / PROCESSES / NETWORK / DATA / SERVICES
```

## Core Principles
1. **Deterministic Execution**: No LLM in the security enforcement decision path.
2. **Observable & Traceable**: Structured JSON audit trails for every request, decision, enforcement, and observed result.
3. **Fail-Closed**: Strict default-deny architecture.
4. **Enforced at Runtime**: Decisions must be physically verified; printing "DENIED" without blocking is not a firewall.

## Repository Layout
- `apps/blackwall-core`: Rust gateway, state coordinator, policy evaluator, telemetry emitter.
- `apps/mock-agent`: Deterministic security action generator for lab testing.
- `crates/common`: Typed action schemas, decision models, security event contracts.
- `crates/policy`: Deterministic policy evaluation engine.
- `crates/enforcement`: Runtime action interceptors and OS enforcement gates.
- `crates/state`: Agent session, capability accumulation, and action history engine.
- `crates/telemetry`: Structured JSON telemetry and event sinks.
- `tests/`: Integration, security (TEST 001, TEST 002), and adversarial bypass tests.
- `infra/`: Docker compose lab and PostgreSQL schemas.
- `research/`: Reference benchmarks (NVIDIA OpenShell, Cisco DefenseClaw, Check Point).
- `docs/`: Architecture diagrams, experiment logs, findings, and threat models.

## Running Tests
```bash
cargo test
```
