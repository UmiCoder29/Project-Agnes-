# Project Agnes — Firewall for Autonomous AI Agents

> **Status: work in progress (v0.1, pre-release).** Agnes is under active development and is **not production-ready**. Only filesystem reads are enforced end to end today, and the HTTP API has no authentication yet. See [What works today](#what-works-today), [What does not work yet](#what-does-not-work-yet) and [Roadmap](#roadmap).

**Project Agnes** is a runtime security firewall for autonomous AI agents, written in Rust. It sits between an agent and the host, evaluates every requested action against a deterministic policy, and enforces the decision before the action reaches the filesystem, network, tools, MCP servers or external APIs.

---

## What works today

| Capability | Status |
|---|---|
| **Deterministic policy engine**: priority-ordered rules, Deny beats Allow on ties, no LLM in the decision loop | Working |
| **Fail-closed default-deny**: no matching rule, resolution error, evaluation panic, or poisoned lock all result in Deny | Working |
| **Real-path policy evaluation**: paths are resolved once per request, following symlinks, *before* any rule is checked. Empty paths, null bytes, symlink loops, and leading/trailing whitespace are rejected | Working |
| **Kernel-confined file reads** (Linux): `openat2` with `RESOLVE_BENEATH`, plus a post-open check that the file actually opened is the exact file the policy approved | Working |
| **TOCTOU defence for reads**: a symlink or file swapped between the policy check and the open is detected and blocked | Working (see [limits](#guarantees-and-their-limits)) |
| **Structured audit events**: every request produces a correlation-tagged JSON event with decision, matched policy and rule, enforcement action and observed result | Working (in-memory and log output) |
| **HTTP gateway** (`agnes-core`): register policies, submit actions, query events and session state | Working (unauthenticated, see below) |

## What does not work yet

Being explicit about this is deliberate.

- **Only `ReadFile` is enforced end to end.** Other action types (`WriteFile`, `ExecuteProcess`, `NetworkConnect`, `HttpRequest`, `CallTool`, `CallMcpTool`, `ReadSecret`, ...) go through the policy engine and default-deny, but the enforcement step is a stub: an Allow returns "Execution permitted" without a real enforcement gate behind it. Real enforcement for these is planned in Milestone 2.
- **No authentication or agent identity.** `POST /v1/policies` and `POST /v1/action` are open. Anyone who can reach the gateway can register policies. **Do not expose the gateway to untrusted networks or to the agents it governs.** Planned in Milestone 3.
- **No mandatory interception.** Agents must route requests through Agnes; nothing forces them to yet. Planned in Milestone 4.
- **In-memory state only.** The PostgreSQL schema in `infra/postgres` is not wired into the gateway; events and sessions are lost on restart.
- **Linux only** for kernel confinement. Non-Linux platforms use a weaker fallback.
- **No hot-reload semantics, rate limiting, or reasoning layer** yet.

---

## Architecture

```
+----------------------------------------------------------------+
|               Untrusted input / web content / prompts          |
+----------------------------------------------------------------+
                               |
                               v
+----------------------------------------------------------------+
|                     Autonomous AI agent                        |
+----------------------------------------------------------------+
                               | (action request)
                               v
+================================================================+
|                       PROJECT AGNES                            |
|  1. Resolve real path once (symlinks followed, fail-closed)    |
|  2. Deterministic policy evaluation (default-deny)             |
|  3. Kernel-confined open (openat2 RESOLVE_BENEATH)             |
|  4. Post-open verification (opened file == approved file)      |
|  5. Structured audit event                                     |
+================================================================+
                               |
          +--------------------+--------------------+
          | Allow and verified                      | Deny / blocked
          v                                         v
+--------------------+                     +--------------------+
| Filesystem (today) |                     | 403 Forbidden /    |
| other targets (WIP)|                     | action blocked     |
+--------------------+                     +--------------------+
```

---

## Guarantees and their limits

Agnes aims to state exactly what it guarantees, not more.

| Threat | What Agnes does | Known limit |
|---|---|---|
| Path traversal (`../`) | Lexical normalisation plus `RESOLVE_BENEATH` | Linux only |
| Symlink escape, including chained symlinks | Policy is evaluated against the fully resolved real path; the kernel also confines the open | Rule patterns that point through symlinked directories are expanded during matching (a deliberate-decision item in Milestone 1) |
| Symlink swapped after the policy check (TOCTOU) | Post-open check compares the opened file (`/proc/self/fd`) to the exact approved path; any mismatch is blocked. Swapping the approved file itself, or a directory in its path, is also caught | In-place content changes to the approved file are out of scope; a deleted or renamed target fails closed |
| Whitespace / null-byte / control-character tricks | Rejected before policy evaluation (fail closed, not trimmed) | - |
| Duplicate path resolution drift | Each path is resolved exactly once per request and the same string is used by every later stage | - |
| Evaluation error, panic, or poisoned lock | Caught and converted to Deny | A poisoned policy lock denies everything until restart |

---

## Tests and proof

As of commit `8f28789` (run as a normal, non-root user):

```
agnes-policy            unit tests ............................  9 passed
adversarial_bypass_002  ......................................  4 passed
adversarial_filesystem_fuzzing ...............................  1 passed
regression_filesystem_boundary ...............................  24 passed
test_001_and_002  ............................................  2 passed
----------------------------------------------------------------------
TOTAL                                                           40 passed, 0 failed
```

Reproduce it yourself:

```bash
cargo test -p agnes-tests -p agnes-policy
```

`test_regression_014_permission_changes_after_policy` changes file permissions and must be run as a non-root user, because root ignores `chmod 000`.

### What the regression suite covers

| Tests | Threat |
|---|---|
| `REGRESSION-001`, `003`, `004`, `005`, `006`, `012`, `013` | Path traversal, nested traversal, alternate representations, relative and absolute paths outside the sandbox root |
| `REGRESSION-002`, `007`, `011`, `adversarial_bypass_002` | Symlink escapes, chained and multiple nested symlinks |
| `REGRESSION-008`, `009`, `010`, `014`, `015`, `018`, `019` | TOCTOU: symlink created after policy, directory rename, file replaced by symlink, permission change, concurrent race, approved file swapped for a symlink |
| `REGRESSION-016` | Whitespace in paths cannot make policy and enforcement disagree |
| `REGRESSION-017` (two tests) | A path is resolved exactly once per request, and stays atomic if the filesystem changes mid-evaluation |
| `REGRESSION-020`, `021`, `022` | Default-deny: zero matching rules, malformed policy config, evaluation panic |
| `adversarial_filesystem_fuzzing` | Fuzzed malformed, oversized, and unusual paths |

### How the tests are verified

- **Every fix ships with a regression test, and the tests are checked against the code *before* the fix.** For the symlink fix, the whitespace fix, single-resolution, the atomic mid-evaluation swap, the post-open TOCTOU check, and the evaluation-panic and lock-poison fixes, the new test was run against the pre-fix code and fails there.
- **Mutation-style checks.** When a first version of a test passed against both old and new code, it was rejected and rewritten (the single-resolution "atomic" test is the example), because a test that cannot fail proves nothing.
- **A bypass was found and closed during review.** An early version of the TOCTOU check re-resolved the approved path from disk, which let an attacker swap the approved file itself into a symlink to a denied file. It is fixed (REGRESSION-019) and the fallback is removed.
- **No test scaffolding in production builds.** Test-only counters and hooks are gated behind the `test-hooks` Cargo feature and do not exist in normal builds; trying to call them without the feature fails to compile.

Engineering rules for contributors are in [`skills.md`](skills.md). Threat models and experiment reports are in [`docs/`](docs/).

---

## Roadmap

| Milestone | Focus | Status |
|---|---|---|
| 1 | Core policy correctness (path resolution, TOCTOU, default-deny, rule precedence, fuzzing) | **In progress (prompts 1-4 of 14 complete)** |
| 2 | Enforcement completeness (writes, processes, network, tools, MCP) | Planned |
| 3 | Identity and authentication | Planned |
| 4 | Mandatory interception | Planned |
| 5 | Observability and traceability | Planned |
| 6 | Reasoning layer | Planned |

---

## Repository structure

```
├── apps/
│   ├── agnes-core/       # Axum HTTP gateway, state coordinator, enforcement dispatcher
│   └── mock-agent/       # Deterministic action generator for security experiments
├── crates/
│   ├── common/           # Typed action schemas, decisions, events
│   ├── policy/           # Policy engine, path resolution
│   ├── enforcement/      # Filesystem enforcement (Linux openat2 confinement)
│   ├── state/            # Session coordinator, audit event history
│   └── telemetry/        # JSON logger and in-memory event sinks
├── infra/                # Docker, Postgres schema (not yet wired in), mock targets
├── docs/                 # Threat models, experiment reports, findings
└── tests/                # Integration, fuzzing, adversarial and regression tests
```

## Prerequisites

- **Rust** 1.80 or newer (toolchains around 1.75 fail to build current dependencies)
- **Linux** for kernel boundary confinement
- Docker and Docker Compose (optional)

## Getting started

```bash
cargo test                 # run the test suite
cargo run -p agnes-core    # start the gateway on http://0.0.0.0:8080
cargo run -p mock-agent    # in a second terminal
docker compose up --build  # full environment with Postgres, a target server, and the mock agent
```

> The gateway has no authentication. Run it on localhost or an isolated network only.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check |
| `POST /v1/policies` | Register a policy (unauthenticated) |
| `POST /v1/action` | Submit an agent action for evaluation and enforcement |
| `GET /v1/events` | Chronological audit events |
| `GET /v1/state/{agent_id}` | Session statistics for an agent |

**Register a policy**

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

**Submit an action**

```json
{
  "correlation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "agent_id": "agent-001",
  "action_type": "ReadFile",
  "target_resource": "/sandbox/data.txt",
  "payload": { "type": "ReadFile", "path": "/sandbox/data.txt" },
  "timestamp": "2026-10-15T12:00:00Z"
}
```

A denied action returns HTTP `403` with `decision: "Deny"` and `observed_result: "BlockedByFirewall"`.

## License

MIT, see [LICENSE](LICENSE).
