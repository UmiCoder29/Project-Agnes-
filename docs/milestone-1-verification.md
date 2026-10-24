# Milestone 1 Verification Report: Core Policy Correctness

Status: gate for closing Milestone 1. All checks below were run and recorded.

Code state verified: commit `6500619` (all production code). Later commits (`6d07906`, `faa1b7d`, `db48dfc`) changed only the mutation script.

## 1. Test results

Run as a normal user on Linux with `cargo test --workspace`:

| Suite | Passed |
|---|---|
| agnes-core (gateway) | 17 |
| agnes-enforcement | 12 |
| agnes-policy | 37 |
| adversarial_bypass_002 | 4 |
| adversarial_filesystem_fuzzing | 8 |
| regression_action_types_and_consistency | 10 |
| regression_event_resolved_path_logging | 5 |
| regression_filesystem_boundary | 45 |
| regression_policy_reload | 3 |
| regression_relative_path_policy | 5 |
| test_001_and_002 | 2 |
| **Total** | **148 passed, 0 failed** |

`test_regression_014_permission_changes_after_policy` needs a normal user because root ignores `chmod 000`.

### Release build check

Test only hooks live behind the `test-hooks` Cargo feature. Checked on a release build:

* `test-hooks` in the agnes-core feature tree (normal edges): 0 occurrences
* hook symbols (`resolution_hook`, `resolution_count`) in `target/release/agnes-core`: 0 occurrences
* control: the binary contains 10604 symbols, so the symbol search was meaningful

### Minimum Rust version

`rust-version = "1.77"` is declared (`RwLock::clear_poison` needs 1.77). Not verified on a 1.77 toolchain, because none was available. The tests were run on the toolchain installed on the development machine.

## 2. Vulnerabilities fixed

| # | What was wrong | How it could be exploited | Fixed in | Guarded by |
|---|---|---|---|---|
| 1 | Policy judged the raw path, not the real path | A symlink inside an allowed folder pointing to a denied folder was allowed | `969adc1`, `ed2497f` | `adversarial_bypass_002`, symlink regression tests, REGRESSION 002, 007, 011 |
| 2 | Policy trimmed spaces from a path, enforcement opened the untrimmed string | A trailing space made policy and enforcement look at different files | `6cf57e5` | REGRESSION 016 |
| 3 | Rule matcher re-resolved the path a second time | A symlink changed between two resolutions gave a different answer inside one request | `60d22c9`, `2f37937` | REGRESSION 017 (two tests) |
| 4 | Test hooks and counters compiled into the production library | Test only code reachable in release builds | `2f37937` | Hooks gated by the `test-hooks` feature, compile failure without it |
| 5 | Gap between policy check and file open | A symlink swapped after the check let a denied file be opened | `30ac24e` | REGRESSION 008, 009, 010, 014, 015, 018 |
| 6 | Post open check re-resolved the approved path from disk | Swapping the approved file itself for a link to a denied file passed the check | `2f20bd4` | REGRESSION 019 |
| 7 | No default deny audit; panics and poisoned locks escaped | An evaluation panic or a poisoned lock could end in a crash or an unchecked result | `8f28789`, `2e1b7d7` | REGRESSION 020, 021, 022 and policy unit tests |
| 8 | Empty rule patterns matched everything | A rule with an empty pattern acted as a catch all | `2e1b7d7` | REGRESSION 024 and policy unit tests |
| 9 | A failed policy load changed state; a bad rule could be dropped | A Deny rule with an unresolvable pattern was silently dropped while a broad Allow loaded | `2e1b7d7`, `c086fde` (the dropped rule was introduced by `7f98b41` and fixed by `c086fde`) | REGRESSION 023, 028, 029 |
| 10 | Rule precedence was undefined for ties | Equal priority rules gave unstable or unsafe results | `7f98b41` | REGRESSION 026, 027 and precedence unit tests |
| 11 | Sandbox roots were never configured; unvalidated config | Reads blocked, or a root set to `/` | `3a5a82b`, `af59d04` | gateway root tests |
| 12 | No handling of case and Unicode folding filesystems | A Deny rule bypassed by respelling on a folding filesystem | `67cff64`, `98d2f05` | seven simulated filesystem tests, REGRESSION 031 |
| 13 | Slash and dot variants not pinned by tests | A Deny dodged by `//` or `./` in a path | `beba1cb` | REGRESSION 030 |
| 14 | Relative paths resolved against the working directory | The policy approved one file and the enforcer opened another | `d568dd7`, `dd5d322` | `regression_relative_path_policy` (5 tests), REGRESSION 032 |
| 15 | Policies could only be added; duplicate ids stacked | An updated policy left the old Allow in force; a reload window failed open | `619adcd` | `regression_policy_reload` (3 tests) |
| 16 | Unknown or inconsistent requests; non file rule patterns rejected | A request claiming one action but carrying another payload; no rule could target URLs or hosts | `3bb7348` | `regression_action_types_and_consistency` (10 tests) |
| 17 | Events logged the raw path, not the evaluated path | An audit log that did not show what the decision was based on | `e127144` (`269606a` later restored it after an accidental test mutation was committed in `64e2bc5`) | `regression_event_resolved_path_logging`, gateway event tests |
| 18 | Generated input never exercised the path logic | Unknown panics, hangs, or an Allow for a path whose real location is denied | `38cad11`, `a917e02` | `adversarial_filesystem_fuzzing` (8 tests) |
| 19 | Overclaiming documentation and dead code | Docs said the kernel eliminated the race that only the post open check closes | `6500619` | docs corrected, dead code removed |

## 3. Default deny map

Every decision path and what it does:

| Path | Result | Proof |
|---|---|---|
| No rule matched | Deny (`default-fail-closed`) | REGRESSION 020, all 14 action types test |
| Relative request path | Deny (`fail-closed-relative-path`) | `regression_relative_path_policy`, gateway 403 test |
| Request action type or target disagrees with payload | Deny (`fail-closed-request-mismatch`) | consistency tests, gateway 403 test |
| Path cannot be resolved (null byte, loop, empty, whitespace) | Deny (`fail-closed-path-resolution`) | resolver unit tests, fuzz properties 2 and 3 |
| Evaluation panic | Deny | REGRESSION 022 |
| Poisoned policy lock | Deny | policy unit tests |
| Rule with an empty pattern | Matches nothing | REGRESSION 024, fuzz property 5 |
| Bad rule in a policy | Whole policy rejected, nothing loaded, HTTP 400 | REGRESSION 028, 029, gateway 400 test |
| Duplicate policy id | Rejected, HTTP 409 | `regression_policy_reload`, gateway 409 test |
| Failed replace | Old set stays in force | `regression_policy_reload` |
| Unknown action or payload type | HTTP 4xx, never Allow | gateway tests |
| No sandbox roots configured | Every file read blocked | gateway root tests |
| Sandbox root on a folding or unprobeable filesystem | No roots registered | simulated filesystem tests |
| Opened file differs from approved path | Blocked | REGRESSION 018, 019 |
| Kernel reports a path escape (`EXDEV`) | Blocked | boundary tests |

## 4. Mutation checks

`scripts/mutation-check.sh` applies 14 deliberate breakages to a temporary copy of the repository, never the working tree. For each one it requires a passing baseline, a clean compile, and the named test to fail. Result of the run on a real toolchain:

| # | Mutation | Test that caught it |
|---|---|---|
| 1 | Symlinks no longer followed | `test_regression_symlink_inside_allowed_pointing_to_denied_evaluated_against_denied_policy_and_rejected` |
| 2 | Post open check removed | `test_regression_018_toctou_symlink_swap_between_policy_and_enforcement` |
| 3 | Default deny returns Allow | `test_regression_020_zero_matching_rules_resolves_to_deny` |
| 4 | Priority order flipped | `test_rule_precedence_priority_override_beats_specificity_and_decision` |
| 5 | Specificity ignored | `test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority` |
| 6 | Allow wins ties | `test_rule_precedence_deny_beats_allow_at_equal_priority_and_specificity` |
| 7 | Relative path accepted | `test_relative_request_path_denied_under_different_cwds` |
| 8 | Request mismatch check skipped | `test_request_consistency_action_type_mismatch_fails_on_old_code` |
| 9 | Null byte check removed | `test_matches_target_null_byte_rejection_and_agent_matching` |
| 10 | Policy replacement in two steps | `test_failed_replace_leaves_old_set_fully_in_effect_and_duplicate_rejected` |
| 11 | Duplicate policy id accepted | `test_replace_policies_rejects_duplicate_ids_within_new_set` |
| 12 | Non path patterns resolved as paths | `test_policy_mixing_file_and_http_rules_loads_and_evaluates` |
| 13 | Folding probe always passes | `test_simulated_fs_writable_case_folding_rejected_and_probe_removed` |
| 14 | Gateway event drops the resolved path | `test_process_action_emits_security_event_with_resolved_path_and_rule_id` |

```
Caught:            14 / 14
Not Caught:        0
Broken Mutations:  0
Timed Out:         0
Baseline Failures: 0
Self-Test:         PASSED
```

The self test runs one mutation against a deliberately wrong test name and confirms the script reports it as not caught, so the script can fail.

## 5. Established facts and where they are proven

| Fact | Proven by |
|---|---|
| Rule order: priority, specificity, Deny wins ties, then ids | REGRESSION 026, mutations 4 to 6 |
| Policies load atomically, a bad rule rejects the whole policy | REGRESSION 023, 028, 029, fuzz property 6 |
| Duplicate ids rejected, `replace_policies` swaps the set under one lock | `regression_policy_reload`, mutations 10 and 11 |
| Rule patterns resolved once at load time | REGRESSION 027 |
| Request paths must be absolute | `regression_relative_path_policy`, mutation 7 |
| Paths compared byte for byte, roots probed for folding | REGRESSION 031, mutation 13 |
| Sandbox roots come from `AGNES_SANDBOX_ROOTS`, none means no reads | gateway root tests |
| Opened file compared with approved path, no canonicalize fallback | REGRESSION 018, 019, mutation 2 |
| Requests must agree with their payload | consistency tests, mutation 8 |
| Pattern kinds per action type, no mixing | `regression_action_types_and_consistency`, mutation 12 |
| Only ReadFile is enforced, other Allows say "enforcement not implemented" | gateway stub honesty test |
| Events carry raw and resolved resource, policy id, rule id | event logging tests, mutation 14 |
| Enforcement and policy share one normalizer | equivalence test in `filesystem.rs` |

## 6. Warnings

* `cargo build --workspace`: 0 warnings
* `cargo clippy --workspace`: 1 warning, in test only code: `clippy::new_without_default` on `SecurityTestHarness::new` in `tests/src/lib.rs` (suggests a `Default` implementation). No production code has warnings. Left unfixed on purpose, since this milestone only reports warnings.

## 7. Docker

`docker-compose.yml` sets `AGNES_SANDBOX_ROOTS: "/sandbox"` on the `agnes-core` service, next to the volume mounted at `/sandbox`.

## 8. Limits moving to Milestone 2

| Limit | Why it was not fixed here |
|---|---|
| Deny rules for URLs, hosts, executables, and secrets match exact text only. Spelling variants (host case, default port, trailing dot, doubled slashes) can bypass a Deny | Needs per action type normalization, which belongs with real enforcement |
| Only ReadFile is enforced. Other Allows report "allowed by policy" with nothing gated | Enforcement for other channels is the subject of Milestone 2 |
| The folding probe covers the sandbox root only. Directories with per directory case folding and filesystems mounted below the root are not probed | Needs a per directory check at open time |
| Read only roots are probed partially, from existing filenames | Rejecting them would make most read only roots unusable |
| Policies cannot be removed or replaced through the gateway. `replace_policies` is an engine API | An authenticated admin endpoint comes with Milestone 3 |
| Gateway endpoints are unauthenticated | Milestone 3 |
| Agents are not forced through Agnes | Milestone 4 |
| State is in memory only | Persistence belongs with the observability work in Milestone 5 |
| Kernel confinement is Linux only | Other platforms use a weaker fallback |
| Content changes inside an approved file are not detected | Out of scope for path based enforcement |
| The test harness in `tests/src/lib.rs` mirrors the gateway request handling. The gateway's own paths are covered by tests in `apps/agnes-core` | Harness is kept for fast integration tests |

## 9. Sign off checklist

* All 148 tests pass as a normal user.
* Mutation gate: 14 of 14 caught, self test passed.
* Release build check and warning counts recorded above. The 1.77 toolchain run is marked not verified.
* `git diff` on production files shows no leftover mutation.
* README refreshed from this report.
