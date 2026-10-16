# Project Agnes

A runtime firewall for autonomous AI agents, written in Rust.

> **Status: work in progress (v0.1, pre release).** Agnes is not production ready. Only filesystem reads are enforced end to end, and the HTTP gateway has no authentication yet. Read [What does not work yet](#what-does-not-work-yet) before running it anywhere.

Agnes sits between an agent and the host machine. Every action the agent requests is checked against a deterministic policy, and the decision is enforced before the action touches the filesystem, network, tools, or external APIs. No language model is involved in any decision.

## Contents

* [What works today](#what-works-today)
* [What does not work yet](#what-does-not-work-yet)
* [How a request is handled](#how-a-request-is-handled)
* [Rule precedence](#rule-precedence)
* [Guarantees and their limits](#guarantees-and-their-limits)
* [Tests and proof](#tests-and-proof)
* [Concepts used](#concepts-used)
* [Roadmap](#roadmap)
* [Repository layout](#repository-layout)
* [Getting started](#getting-started)
* [Configuration](#configuration)
* [HTTP API](#http-api)
* [License](#license)

## What works today

| Capability | Status |
|---|---|
| Deterministic policy engine with priority, specificity, and Deny wins ties | Working |
| Default deny: no matching rule, an evaluation error, a panic, or a poisoned lock all produce Deny | Working |
| Rules with an empty agent, action list, or resource pattern match nothing | Working |
| Real path resolution before any rule runs: symlinks followed, `..` removed, bad input rejected | Working |
| Rule patterns resolved once, when the policy is loaded, not on every request | Working |
| Atomic policy loading: one bad rule rejects the entire policy | Working |
| Kernel confined file reads on Linux using `openat2` with `RESOLVE_BENEATH` | Working |
| Check after opening that the file opened is exactly the file the policy approved | Working |
| Sandbox roots set through `AGNES_SANDBOX_ROOTS`, with no roots registered on any invalid value | Working |
| Structured audit events with a correlation id, decision, matched rule, and observed result | Working, in memory and in logs |
| HTTP gateway (`agnes-core`) for policies, actions, events, and session state | Working, unauthenticated |

## What does not work yet

Only `ReadFile` is enforced end to end. This list is deliberate, so nobody has to guess.

* **Other action types are not enforced.** `WriteFile`, `ExecuteProcess`, `NetworkConnect`, `HttpRequest`, `CallTool`, `CallMcpTool`, and `ReadSecret` go through the policy engine and default deny, but the enforcement step is a stub. An Allow returns "Execution permitted" and nothing is actually gated. Planned for Milestone 2.
* **No authentication.** `POST /v1/policies` and `POST /v1/action` are open. Anyone who can reach the gateway can register an allow everything policy. Run it on localhost or an isolated network only, and never expose it to the agents it governs. Planned for Milestone 3.
* **No mandatory interception.** An agent has to choose to send requests through Agnes. Nothing forces it. Planned for Milestone 4.
* **State is in memory.** Policies, events, and sessions are lost on restart. The PostgreSQL schema in `infra/postgres` is not connected.
* **Linux only** for kernel confinement. Other platforms use a weaker fallback.
* **A poisoned policy lock denies everything** until an operator calls `clear()`, and `clear()` also removes every loaded policy.
* **Patterns follow the filesystem as it was at load time.** A rule pattern is resolved when the policy is loaded. If a symlink in the pattern is later repointed, the rule stays bound to the original location. A pattern for a directory that does not exist yet is stored as written.
* **Trailing star patterns match by string prefix.** A pattern such as `/data*` also matches `/database/file`. Use `/data/*` for directory scope.
* **In place changes to an approved file are not detected.** The check after opening confirms which file was opened, not that its contents are unchanged.
* **No hot reload rules, rate limiting, case folding rules, or reasoning layer** yet.

## How a request is handled

```
Agent action request
        |
        v
1. Resolve the real path once (symlinks followed, bad input rejected)
        |
        v
2. Evaluate policy (priority, specificity, Deny wins ties, default deny)
        |
        v
3. Open the file with openat2 and RESOLVE_BENEATH inside a sandbox root
        |
        v
4. Compare the opened file (/proc/self/fd) with the approved path
        |
        v
5. Return the content, or block, and write an audit event
```

A failure at any step ends in a block with no file content returned.

## Rule precedence

When several rules match a request, the engine sorts them and takes the first one:

1. **Priority**, highest number first.
2. **Specificity**, when priorities are equal. An exact path beats a wildcard. A deeper directory beats a shallower one. A longer prefix beats a shorter one. A lone `*` is least specific.
3. **Decision**, when priority and specificity are equal. Deny beats Allow.
4. **Policy id, then rule id**, so the result is identical on every run.

One consequence to know about: at equal priority an exact path rule beats a wildcard rule whatever its decision. An exact Allow on `/data/report.txt` beats a Deny on `/data/*` if both have priority 10. Give the Deny a higher priority if that is not what you want.

## Guarantees and their limits

| Threat | What Agnes does | Known limit |
|---|---|---|
| Path traversal with `../` | Lexical cleanup plus `RESOLVE_BENEATH` | Linux only |
| Symlink escape, chained links, loops | Policy sees the fully resolved path. Loops fail closed. The kernel also confines the open | None known |
| Link swapped after the policy check | The opened file is compared with the approved path. A swapped link, a swapped approved file, and a swapped directory are all blocked | Content changes inside the approved file are out of scope |
| Spaces, null bytes, control characters in a path | Rejected before evaluation, never trimmed | None known |
| Policy and enforcement disagreeing about a path | Each path is resolved once and the same string is used by every later step | None known |
| A rule silently dropped because its pattern is bad | The whole policy is rejected, nothing is loaded, earlier policies stay in force, and the API returns 400 | None known |
| Rules with empty patterns | Match nothing | None known |
| Panic, error, or poisoned lock during evaluation | Caught and turned into Deny. A poisoned lock in the enforcer also becomes a controlled block | A poisoned policy lock needs `clear()` to recover |
| Missing or invalid sandbox root setting | No roots registered, every file read denied | None known |

## Tests and proof

As of commit `c086fde`, run as an unprivileged user:

```
agnes-policy unit tests ............................ 15 passed
agnes-enforcement unit tests ........................  1 passed
agnes-core gateway tests ............................  3 passed
adversarial_bypass_002 ..............................  4 passed
adversarial_filesystem_fuzzing ......................  1 passed
regression_filesystem_boundary ...................... 36 passed
test_001_and_002 ....................................  2 passed
--------------------------------------------------------------
TOTAL                                                62 passed, 0 failed
```

Reproduce it:

```bash
cargo test --workspace
cargo test --workspace 2>&1 | grep -E "Running|test result"
```

`test_regression_014_permission_changes_after_policy` changes file permissions, so it must run as a normal user. The root user ignores `chmod 000`.

### What the regression suite covers

| Tests | Threat |
|---|---|
| REGRESSION 001, 003, 004, 005, 006, 012, 013 | Path traversal, nested traversal, alternate spellings, paths outside the sandbox |
| REGRESSION 002, 007, 011, 025 and `adversarial_bypass_002` | Symlink escapes, chained and nested links, symlink loops |
| REGRESSION 008, 009, 010, 014, 015, 018, 019 | Races after the policy check: link created late, directory renamed, file replaced by a link, permission change, concurrent race, approved file swapped for a link |
| REGRESSION 016 | Spaces in a path cannot make policy and enforcement disagree |
| REGRESSION 017 (two tests) | A path is resolved exactly once, and stays consistent if the filesystem changes mid evaluation |
| REGRESSION 020, 021, 022 | Default deny: no matching rule, malformed policy file, panic during evaluation |
| REGRESSION 023, 024 | A failed policy load changes nothing. Empty patterns and invalid paths are denied |
| REGRESSION 026 | Precedence: deny inside allow, allow inside deny, equal conflicts, tie breaks |
| REGRESSION 027 | Rule patterns that go through symlinks are bound to the real location at load time |
| REGRESSION 028 and 029 (six tests) | Any rule with a bad pattern rejects the whole policy: leading space, trailing space, symlink loop, null byte, a bad last rule, and an earlier valid policy staying in force |
| Gateway tests | A read inside a sandbox root works, a read outside is blocked, every invalid `AGNES_SANDBOX_ROOTS` value registers nothing, and `POST /v1/policies` returns 400 for a bad policy and registers nothing |
| `adversarial_filesystem_fuzzing` | Malformed, oversized, and unusual paths |

### How the tests were checked

A test that cannot fail proves nothing. For each fix, the fix was broken on purpose and the test was confirmed to fail.

| Fix | How it was broken | What failed |
|---|---|---|
| Real path resolution | Code from before the fix restored | The new regression test |
| Spaces in paths (016) | Trimming restored | The test |
| One resolution per request (017) | Second resolution added to the rule matcher | Both tests: resolution count 4 instead of 1, and a mid evaluation swap returned Deny instead of Allow |
| Check after opening (018) | Previous enforcer restored | The test |
| Canonicalize fallback bypass (019) | Previous enforcer restored | The test, with "approved file was replaced by symlink" |
| Default deny for no match | Branch changed to Allow | 020, 024, and the inline test |
| Poisoned policy lock | Branch changed to Allow | The inline test, on its first assertion |
| Empty pattern rules | Old matching restored | The inline test |
| Enforcer lock handling | `.expect()` put back | The enforcer test panicked |
| Path resolution failure and loops | Branch changed to Allow | Loop test and invalid path test |
| Sandbox roots all or nothing | Valid roots registered before a later entry fails | The config test |
| Sandbox roots must be absolute | Absolute path check removed | The config test, on the `.` case |
| Specificity in the sort | Removed from the sort | Test 026 |
| Pattern resolved at load time | Resolution turned into a no op | Test 027 |
| Deny wins ties | Tie break reversed | Test 026 |
| Atomic policy load | Errors ignored, then bad rules dropped like the old behavior | Nine tests in each case |

Other checks that mattered:

* **A weak test was rejected.** The first version of the single resolution test passed on both old and new code, so it was rewritten to repoint a symlink during evaluation.
* **A bypass was found in review.** An early version of the post open check re resolved the approved path from disk. An attacker could replace the approved file with a link to a denied file and both sides resolved to the same place. The fallback was removed (REGRESSION 019).
* **A silent policy weakening was found in review.** A rule with an unresolvable pattern used to be dropped while the rest of the policy loaded. A Deny rule with a leading space in its pattern disappeared and a broad Allow let a secret file be read. The whole policy is now rejected (REGRESSION 028 and 029).
* **Test code stays out of production builds.** Counters and hooks used by tests sit behind the `test-hooks` Cargo feature. Calling them without the feature fails to compile.
* **No panics outside tests.** A search of `apps/` and every crate finds no `unwrap`, `expect`, or `panic!` in non test code.

The engineering rules every change must follow are in [`skills.md`](skills.md). Threat models and experiment reports are in [`docs/`](docs/).

## Concepts used

* **Default deny and failing closed.** Anything unknown, ambiguous, or broken becomes a denial, never a permission.
* **Canonicalization.** The path used for a decision is the real path on disk, after symlinks and `..` are resolved, so a clever spelling cannot change the outcome.
* **TOCTOU (time of check to time of use).** The gap between checking a file and opening it is the attack window. Agnes closes it by opening inside a kernel enforced boundary and then verifying what was actually opened.
* **`openat2` with `RESOLVE_BENEATH`.** A Linux system call that makes the kernel refuse any path that escapes a directory, including through symlinks.
* **`/proc/self/fd` verification.** After opening, the real path of the open file descriptor is read back and compared with the path the policy approved.
* **Deterministic rule ordering.** Priority, then specificity, then Deny before Allow, then ids. The same input always gives the same decision.
* **Atomic loading.** A policy is validated completely before any state changes, so a failure leaves nothing half applied.
* **Load time resolution.** Rule patterns are resolved once when the policy is loaded, which removes repeated resolution on every request.
* **Panic containment.** `catch_unwind` around evaluation, and recovery handling for poisoned locks, so internal failures become Deny.
* **Regression testing with mutation checks.** Every fix has a test, and the test is proven by breaking the fix.
* **Fuzzing.** Generated malformed and oversized paths are fed through the full path.
* **Feature gated test hooks.** Test only instrumentation uses thread local state behind a Cargo feature.
* **Structured audit events.** Each request carries a correlation id from request to decision to result.
* **Rust building blocks.** Axum for the gateway, Serde for policy and request JSON, Tokio for async, `thiserror` for typed errors, Tracing for logs.

## Roadmap

| Milestone | Focus | Status |
|---|---|---|
| 1 | Core policy correctness: path resolution, races, default deny, rule precedence, fuzzing | In progress, prompts 1 to 5 of 14 done |
| 2 | Enforcement for writes, processes, network, tools, and MCP | Planned |
| 3 | Identity and authentication | Planned |
| 4 | Mandatory interception | Planned |
| 5 | Observability and traceability | Planned |
| 6 | Reasoning layer | Planned |

## Repository layout

```
apps/
  agnes-core/     Axum HTTP gateway, state coordinator, enforcement dispatcher
  mock-agent/     Deterministic action generator for experiments
crates/
  common/         Typed actions, decisions, and events
  policy/         Policy engine, path resolution, rule model, load errors
  enforcement/    Filesystem enforcement with Linux openat2 confinement
  state/          Session coordinator and audit event history
  telemetry/      JSON logger and in memory event sinks
infra/            Docker files, Postgres schema (not connected), mock targets
docs/             Threat models, experiment reports, findings
skills.md         Engineering rules for every change
tests/            Integration, fuzzing, adversarial, and regression tests
```

## Getting started

Requirements: Rust 1.77 or newer (1.80 or newer recommended), Linux for kernel confinement, and optionally Docker with Docker Compose.

```bash
cargo test --workspace

AGNES_SANDBOX_ROOTS=/path/to/sandbox cargo run -p agnes-core
cargo run -p mock-agent
```

The gateway listens on `http://0.0.0.0:8080`. It has no authentication, so keep it on localhost or an isolated network.

With Docker:

```bash
docker compose up --build
```

The `agnes-core` service needs `AGNES_SANDBOX_ROOTS` set, for example `AGNES_SANDBOX_ROOTS: /sandbox` in its `environment` block. Without it, every file read is denied.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `AGNES_SANDBOX_ROOTS` | Colon separated list of absolute directories the gateway may read from | Unset, so no roots and every file read is denied |

Validation is all or nothing. If any entry is empty (a leading, trailing, or doubled colon), relative (`.`, `..`, `dir/sub`), missing, not a directory, or `/`, the gateway logs an error and registers no roots at all. It never falls back to `/` or the current directory.

## HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check |
| `POST /v1/policies` | Register a policy. Returns 201, or 400 if any rule is invalid |
| `POST /v1/action` | Submit an agent action for evaluation and enforcement |
| `GET /v1/events` | Audit events in order |
| `GET /v1/state/{agent_id}` | Session statistics for an agent |

Enum values are upper snake case, for example `ALLOW`, `DENY`, and `READ_FILE`.

Register a policy:

```json
{
  "id": "policy-sandbox-read",
  "name": "Allow reads inside the sandbox",
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
      "id": "rule-deny-private",
      "description": "Deny reads inside /sandbox/private",
      "decision": "DENY",
      "agent_pattern": "*",
      "action_types": ["READ_FILE"],
      "resource_pattern": "/sandbox/private/*",
      "priority": 10
    }
  ]
}
```

Here both rules have priority 10, so the deeper `/sandbox/private/*` rule wins for files inside it.

A rule with an empty `agent_pattern`, an empty `action_types` list, or an empty `resource_pattern` is not a catch all. An empty pattern is rejected when the policy loads. If any pattern cannot be resolved, the response is `400` and nothing from that policy is loaded:

```json
{
  "error": "Failed to register policy",
  "details": "Failed to load policy 'p1': rule 'r2' has invalid or unresolvable pattern: ...",
  "policy_id": "p1",
  "rule_id": "r2",
  "reason": "..."
}
```

Submit an action:

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

A denied or blocked action returns HTTP `403` with `decision` set to `DENY` or `observed_result` set to `BLOCKED_BY_FIREWALL`.

## License

MIT. See [LICENSE](LICENSE).
