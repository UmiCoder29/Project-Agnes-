# Project Agnes Firewall for Autonomous AI Agents

> **Status: work in progress (v0.1, pre-release).** Agnes is under active development and is **not production-ready**. Only filesystem reads are enforced end to end today, and the HTTP API has no authentication yet. See [What works today](#what-works-today), [What does not work yet](#what-does-not-work-yet), and the [Roadmap](#roadmap).

**Project Agnes** is a runtime security firewall for autonomous AI agents, written in Rust. It sits between an agent and the host, evaluates every requested action against a deterministic policy, and enforces the decision before the action reaches the filesystem, network, tools, MCP servers, or external APIs.

---

## Contents

- [What works today](#what-works-today)
- [What does not work yet](#what-does-not-work-yet)
- [Architecture](#architecture)
- [Guarantees and their limits](#guarantees-and-their-limits)
- [Tests and proof](#tests-and-proof)
- [Roadmap](#roadmap)
- [Repository structure](#repository-structure)
- [Getting started](#getting-started)
- [Configuration](#configuration)
- [HTTP API](#http-api)
- [License](#license)

---

## What works today

| Capability | Status |
|---|---|
| **Deterministic policy engine**: priority-ordered rules, Deny wins ties, no LLM in the decision loop | Working |
| **Fail-closed default-deny**: no matching rule, resolution error, evaluation panic, or poisoned lock all result in Deny | Working |
| **Rules with empty patterns match nothing**: an empty agent, action list, or resource pattern never means "match everything" | Working |
| **Real-path policy evaluation**: paths are resolved once per request, following symlinks, *before* any rule is checked. Empty paths, null bytes, symlink loops, and leading or trailing whitespace are rejected | Working |
| **Kernel-confined file reads** (Linux): `openat2` with `RESOLVE_BENEATH`, plus a post-open check that the file actually opened is the exact file the policy approved | Working |
| **TOCTOU defence for reads**: a symlink, file, or directory swapped between the policy check and the open is detected and blocked | Working (see [limits](#guarantees-and-their-limits)) |
| **Configurable sandbox roots**: the gateway reads `AGNES_SANDBOX_ROOTS` at startup and starts with no roots (all reads denied) if the setting is missing or invalid | Working |
| **Structured audit events**: every request produces a correlation-tagged JSON event with decision, matched policy and rule, enforcement action, and observed result | Working (in-memory and log output) |
| **HTTP gateway** (`agnes-core`): register policies, submit actions, query events and session state | Working (unauthenticated, see below) |

## What does not work yet

Being explicit about this is deliberate.

- **Only `ReadFile` is enforced end to end.** Other action types (`WriteFile`, `ExecuteProcess`, `NetworkConnect`, `HttpRequest`, `CallTool`, `CallMcpTool`, `ReadSecret`, and so on) go through the policy engine and default-deny, but the enforcement step is a stub: an Allow returns "Execution permitted" without a real enforcement gate behind it. Real enforcement is planned in Milestone 2.
- **No authentication or agent identity.** `POST /v1/policies` and `POST /v1/action` are open. Anyone who can reach the gateway can register policies. **Do not expose the gateway to untrusted networks or to the agents it governs.** Planned in Milestone 3.
- **No mandatory interception.** Agents must route requests through Agnes; nothing forces them to yet. Planned in Milestone 4.
- **In-memory state only.** The PostgreSQL schema in `infra/postgres` is not wired into the gateway. Events, sessions, and policies are lost on restart.
- **Linux only** for kernel confinement. Non-Linux platforms use a weaker fallback.
- **No hot-reload semantics, rate limiting, or reasoning layer** yet.
- **Rule patterns are still re-resolved on each evaluation**, and a pattern such as `/allowed/link/*` expands through symlinks during matching. Both are scheduled for the rule-precedence work in Milestone 1.

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

Agnes aims to state exactly what it guarantees, and no more.

| Threat | What Agnes does | Known limit |
|---|---|---|
| Path traversal (`../`) | Lexical normalisation plus `RESOLVE_BENEATH` | Linux only |
| Symlink escape, including chained symlinks and loops | Policy is evaluated against the fully resolved real path; loops fail closed; the kernel also confines the open | Rule patterns that point through symlinked directories are expanded during matching (to be settled in Milestone 1) |
| Symlink swapped after the policy check (TOCTOU) | The post-open check compares the opened file (`/proc/self/fd`) to the exact approved path. Any mismatch is blocked. Swapping the approved file itself, or a directory in its path, is also caught | In-place content changes to the approved file are out of scope; a deleted or renamed target fails closed |
| Whitespace, null-byte, and control-character tricks | Rejected before policy evaluation (fail closed, never trimmed) | - |
| Duplicate path resolution drift | Each path is resolved exactly once per request and the same string is used by every later stage | - |
| Rules with empty patterns | Match nothing | - |
| Evaluation error, panic, or poisoned lock | Caught and converted to Deny, including a poisoned sandbox-root lock in the enforcer | A poisoned policy lock denies everything until an operator calls `clear()`, which also removes all loaded policies |
| Missing or invalid sandbox-root configuration | The gateway registers no roots at all and every file read is denied | - |

---

## Tests and proof

As of commit `af59d04`, run as a normal (non-root) user:

```
agnes-policy                      unit tests ...........................  14 passed
agnes-enforcement                 unit tests ...........................   1 passed
agnes-core (gateway)              unit tests ...........................   2 passed
adversarial_bypass_002 ................................................   4 passed
adversarial_filesystem_fuzzing ........................................   1 passed
regression_filesystem_boundary ........................................  27 passed
test_001_and_002 ......................................................   2 passed
-------------------------------------------------------------------------------------
TOTAL                                                                     51 passed, 0 failed
```

Reproduce it:

```bash
cargo test --workspace
```

`test_regression_014_permission_changes_after_policy` changes file permissions and must run as a non-root user, because root ignores `chmod 000`.

To see the per-suite summary lines yourself:

```bash
cargo test --workspace 2>&1 | grep -E "Running|test result"
```

### What the regression suite covers

| Tests | Threat |
|---|---|
| `REGRESSION-001`, `003`, `004`, `005`, `006`, `012`, `013` | Path traversal, nested traversal, alternate representations, relative and absolute paths outside the sandbox root |
| `REGRESSION-002`, `007`, `011`, `025`, `adversarial_bypass_002` | Symlink escapes, chained and nested symlinks, symlink loops |
| `REGRESSION-008`, `009`, `010`, `014`, `015`, `018`, `019` | TOCTOU: symlink created after policy, directory rename, file replaced by symlink, permission change, concurrent race, approved file swapped for a symlink |
| `REGRESSION-016` | Whitespace in paths cannot make policy and enforcement disagree |
| `REGRESSION-017` (two tests) | A path is resolved exactly once per request, and stays atomic if the filesystem changes mid-evaluation |
| `REGRESSION-020`, `021`, `022` | Default-deny: zero matching rules, malformed policy config, evaluation panic |
| `REGRESSION-023`, `024` | A failed config load leaves existing policies untouched; empty patterns and invalid paths are denied |
| Gateway tests (`agnes-core`) | A read inside a configured sandbox root succeeds and returns the file contents; a read outside is blocked with no output; every invalid `AGNES_SANDBOX_ROOTS` value registers no roots |
| `adversarial_filesystem_fuzzing` | Fuzzed malformed, oversized, and unusual paths |

### How the tests are verified

Every fix ships with a regression test, and each test is checked by breaking the fix on purpose and confirming the test fails. A test that cannot fail proves nothing.

| Fix | How it was deliberately broken | Result |
|---|---|---|
| Real-path resolution (symlink escape) | Pre-fix code restored | New regression test fails |
| Whitespace mismatch (`REGRESSION-016`) | Trimming restored | Test fails |
| Single resolution per request (`REGRESSION-017`) | Duplicate resolution reintroduced in the rule matcher | Both tests fail (resolution count 4 instead of 1; mid-evaluation swap returns Deny instead of Allow) |
| Post-open TOCTOU check (`REGRESSION-018`) | Pre-fix enforcer restored | Test fails |
| Canonicalize-fallback bypass (`REGRESSION-019`) | Previous enforcer restored | Test fails with "approved file was replaced by symlink" |
| Default-deny for zero matching rules | Default branch flipped to Allow | `REGRESSION-020`, `024`, and the inline test fail |
| Poisoned policy lock | Deny branch flipped to Allow | Inline test fails on its first assertion |
| Empty-pattern rules | Old matching restored | Inline empty-pattern test fails |
| Enforcer lock handling | `.expect()` restored | Enforcer test panics |
| Path-resolution failure and symlink loops | Failure branch flipped to Allow | Loop test and invalid-path test fail |
| Sandbox-root config: all-or-nothing | Valid roots registered before a later entry fails | Config test fails |
| Sandbox-root config: absolute paths only | Relative-path check removed | Config test fails on the `.` case |

Other checks:

- **A first version of a test was rejected for passing against both old and new code.** The single-resolution "atomic" test was rewritten to repoint a symlink mid-evaluation, so it now fails against the old behaviour.
- **A bypass was found and closed during review.** An early version of the TOCTOU check re-resolved the approved path from disk, which let an attacker swap the approved file itself into a symlink to a denied file. That fallback is removed (`REGRESSION-019`).
- **No test scaffolding in production builds.** Test-only counters and hooks are gated behind the `test-hooks` Cargo feature. Calling them without the feature fails to compile.
- **No panics in non-test code.** A search of `apps/` and every crate finds no `unwrap`, `expect`, or `panic!` outside tests.

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
├── skills.md             # Engineering rules for every change
└── tests/                # Integration, fuzzing, adversarial, and regression tests
```

## Prerequisites

- **Rust 1.77 or newer** (declared as `rust-version` in `Cargo.toml`; 1.80+ recommended)
- **Linux** for kernel boundary confinement
- Docker and Docker Compose (optional)

## Getting started

```bash
cargo test --workspace                                      # run the test suite

AGNES_SANDBOX_ROOTS=/path/to/sandbox cargo run -p agnes-core   # start the gateway on http://0.0.0.0:8080
cargo run -p mock-agent                                     # in a second terminal
```

> The gateway has no authentication. Run it on localhost or an isolated network only.

### Docker Compose

```bash
docker compose up --build
```

The compose file mounts a volume at `/sandbox` but does not set `AGNES_SANDBOX_ROOTS` yet. Add this line under the `agnes-core` service's `environment:` block, or file reads will be denied:

```yaml
AGNES_SANDBOX_ROOTS: /sandbox
```

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `AGNES_SANDBOX_ROOTS` | Colon-separated list of absolute directories the gateway may read from | Unset: no roots, every file read is denied |

Validation is all-or-nothing. If any entry is empty (leading, trailing, or doubled colon), relative (`.`, `..`, `dir/sub`), missing, not a directory, or `/`, the gateway logs an error and registers **no** roots. It never defaults to `/` or the current directory.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check |
| `POST /v1/policies` | Register a policy (unauthenticated) |
| `POST /v1/action` | Submit an agent action for evaluation and enforcement |
| `GET /v1/events` | Chronological audit events |
| `GET /v1/state/{agent_id}` | Session statistics for an agent |

Enum values are upper snake case (`ALLOW`, `DENY`, `READ_FILE`).

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
      "decision": "ALLOW",
      "agent_pattern": "*",
      "action_types": ["READ_FILE"],
      "resource_pattern": "/sandbox/*",
      "priority": 10
    },
    {
      "id": "rule-deny-etc",
      "description": "Deny reads from /etc",
      "decision": "DENY",
      "agent_pattern": "*",
      "action_types": ["READ_FILE"],
      "resource_pattern": "/etc/*",
      "priority": 100
    }
  ]
}
```

A rule with an empty `agent_pattern`, an empty `action_types` list, or an empty `resource_pattern` matches nothing.

**Submit an action**

```json
{
  "correlation_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-10-16T12:00:00Z",
  "agent_id": "agent-001",
  "action_type": "READ_FILE",
  "target_resource": "/sandbox/data.txt",
  "payload": { "type": "READ_FILE", "details": { "path": "/sandbox/data.txt" } }
}
```

A denied or blocked action returns HTTP `403` with `decision: "DENY"` or `observed_result: "BLOCKED_BY_FIREWALL"`.

## License

MIT, see [LICENSE](LICENSE).
