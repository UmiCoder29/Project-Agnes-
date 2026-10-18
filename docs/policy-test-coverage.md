# Policy Test Coverage and Branch Audit Report

## 1. Audit Methodology & Tooling Verification

An audit of test coverage across [`crates/policy/src/model.rs`](../crates/policy/src/model.rs) and [`crates/policy/src/engine.rs`](../crates/policy/src/engine.rs) was conducted.

The active toolchain was probed for coverage binaries:
- `cargo llvm-cov --version`: `error: no such command: llvm-cov`
- `cargo tarpaulin --version`: `error: no such command: tarpaulin`

Because automated cargo coverage subcommands are not installed in the execution environment, this audit was conducted manually: line-by-line inspection of all conditionals (`if`, `else if`, `else`), match expressions, loop constructs, error-propagation paths (`?`), and sorting closures in `model.rs` and `engine.rs`. Every unit test was validated via mutation testing (breaking the target behavior and proving test failure).

---

## 2. Branch and Match Arm Audit: `crates/policy/src/model.rs`

| Function / Component | Branch / Match Arm / Conditional | Covered? | Covering Unit Test(s) | Notes / Uncovered Reason |
| :--- | :--- | :--- | :--- | :--- |
| `resolve_resource_pattern` | `pattern.is_empty()` | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Rejects empty pattern as `InvalidInput` |
| `resolve_resource_pattern` | `pattern == "*"` | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Preserves global wildcard verbatim |
| `resolve_resource_pattern` | `pattern.contains('\0')` | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Rejects null bytes as `InvalidInput` |
| `resolve_resource_pattern` | `strip_suffix("/*")` / `clean_prefix.is_empty()` | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Normalizes root wildcards `/*` and `//*` |
| `resolve_resource_pattern` | `strip_suffix("/*")` / `clean_prefix` non-empty | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Resolves canonical parent directory |
| `resolve_resource_pattern` | `strip_suffix('*')` / `prefix.is_empty()` | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Maps `*` to global wildcard |
| `resolve_resource_pattern` | `strip_suffix('*')` / `prefix` non-empty | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Resolves parent prefix through symlinks |
| `resolve_resource_pattern` | Exact path fallback | Yes | `test_rule_specificity_ordering` | Canonicalizes exact path |
| `PolicyRule::specificity` | `self.resource_pattern == "*"` | Yes | `test_rule_specificity_ordering` | Returns `{ is_exact: false, component_count: 0, prefix_len: 0 }` |
| `PolicyRule::specificity` | `strip_suffix("/*")` prefix pattern | Yes | `test_rule_specificity_ordering` | Component count of normal segments and prefix character length |
| `PolicyRule::specificity` | `strip_suffix('*')` prefix pattern | Yes | `test_rule_specificity_ordering` | Component count of normal segments without trailing slash |
| `PolicyRule::specificity` | Exact match pattern | Yes | `test_rule_specificity_ordering` | `{ is_exact: true, component_count, prefix_len }` |
| `PolicyRule::pattern_kind` | `self.action_types.is_empty()` with `/` prefix | Yes | `test_pattern_kind_derivation_from_empty_action_types_and_mixed` | Derives `FilesystemPath` |
| `PolicyRule::pattern_kind` | `self.action_types.is_empty()` without `/` prefix | Yes | `test_pattern_kind_derivation_from_empty_action_types_and_mixed` | Derives `LiteralString` |
| `PolicyRule::pattern_kind` | Mixed action types (`has_fs && has_lit`) | Yes | `test_pattern_kind_derivation_from_empty_action_types_and_mixed` | Rejects mixed filesystem and non-filesystem rules |
| `PolicyRule::pattern_kind` | Pure filesystem action types (`has_fs`) | Yes | `test_pattern_kind_derivation_from_empty_action_types_and_mixed` | Returns `FilesystemPath` |
| `PolicyRule::pattern_kind` | Pure non-filesystem action types (`has_lit`) | Yes | `test_pattern_kind_derivation_from_empty_action_types_and_mixed` | Returns `LiteralString` |
| `PolicyRule::resolve_pattern` | `PatternKind::FilesystemPath` arm | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Validates and resolves path pattern |
| `PolicyRule::resolve_pattern` | `PatternKind::LiteralString` / `is_empty()` | Yes | `test_literal_string_pattern_validation` | Rejects empty literal string pattern |
| `PolicyRule::resolve_pattern` | `PatternKind::LiteralString` / `contains('\0')` | Yes | `test_literal_string_pattern_validation` | Rejects null bytes in literal pattern |
| `PolicyRule::resolve_pattern` | `PatternKind::LiteralString` / valid string | Yes | `test_literal_string_pattern_validation` | Accepts valid literal string |
| `PolicyRule::matches` | `resolve_request_target` -> `Ok(Some(path))` | Yes | `engine::tests::test_audit_zero_matching_rules_resolves_to_deny` | Resolves path target |
| `PolicyRule::matches` | `resolve_request_target` -> `Ok(None)` | Yes | `engine::tests::test_security_event_records_rule_id_and_none_resolved_for_non_path_action` | Passes non-path target |
| `PolicyRule::matches` | `resolve_request_target` -> `Err(_)` | Yes | `engine::tests::test_audit_unresolvable_paths_resolve_to_deny` | Fails closed on path resolution failure |
| `PolicyRule::matches_target` | `self.agent_pattern.is_empty()` | Yes | `engine::tests::test_audit_empty_rule_patterns_do_not_match_and_resolve_to_deny` | Empty agent pattern matches nothing |
| `PolicyRule::matches_target` | `self.agent_pattern != "*" && != request.agent_id` | Yes | `test_matches_target_null_byte_rejection_and_agent_matching` | Specific agent pattern mismatch |
| `PolicyRule::matches_target` | `self.agent_pattern` matching agent or `*` | Yes | `test_matches_target_null_byte_rejection_and_agent_matching` | Agent match succeeds |
| `PolicyRule::matches_target` | `self.action_types.is_empty()` | Yes | `test_matches_target_action_types_empty_list_matches_nothing` | Empty action types matches nothing |
| `PolicyRule::matches_target` | `!self.action_types.contains(&request.action_type)` | Yes | `test_matches_target_action_types_read_file_does_not_match_write_file`, `test_matches_target_action_types_multiple_matches_each_and_no_other` | Single and multi-action type mismatches reject |
| `PolicyRule::matches_target` | Action type mismatch with matching resource pattern | Yes | `test_matches_target_action_types_matching_independent_of_resource_pattern_for_non_matching_action` | Action type filtering is strictly independent of resource pattern |
| `PolicyRule::matches_target` | `target.contains('\0')` | Yes | `test_matches_target_null_byte_rejection_and_agent_matching` | Target null byte rejects fail-closed |
| `PolicyRule::matches_target` | `self.resource_pattern.is_empty()` | Yes | `engine::tests::test_audit_empty_rule_patterns_do_not_match_and_resolve_to_deny` | Empty resource pattern matches nothing |
| `PolicyRule::matches_resource` | `self.resource_pattern.is_empty()` | Yes | `engine::tests::test_audit_empty_rule_patterns_do_not_match_and_resolve_to_deny` | Fails closed on empty pattern |
| `PolicyRule::matches_resource` | `PatternKind::LiteralString` / `*` wildcard | Yes | `test_matches_resource_literal_string_variants` | Matches any literal resource |
| `PolicyRule::matches_resource` | `PatternKind::LiteralString` / `prefix*` wildcard | Yes | `test_matches_resource_literal_string_variants` | Prefix match for literal string |
| `PolicyRule::matches_resource` | `PatternKind::LiteralString` / exact match | Yes | `test_matches_resource_literal_string_variants` | Exact match for literal string |
| `PolicyRule::matches_resource` | `PatternKind::FilesystemPath` / `*` wildcard | Yes | `test_resolve_resource_pattern_root_and_prefix_star` | Wildcard filesystem match |
| `PolicyRule::matches_resource` | `PatternKind::FilesystemPath` / `prefix/*` matching child | Yes | `test_matches_resource_filesystem_prefix_boundary_leak_protection` | Matches directory children and subpaths |
| `PolicyRule::matches_resource` | `PatternKind::FilesystemPath` / `prefix/*` sibling boundary check | Yes | `test_matches_resource_filesystem_prefix_boundary_leak_protection` | Prevents boundary leak (e.g. `/sandbox/data/*` rejects `/sandbox/data_leak.txt`) |
| `PolicyRule::matches_resource` | `PatternKind::FilesystemPath` / `prefix*` without slash | Yes | `test_matches_resource_filesystem_prefix_boundary_leak_protection` | Matches shared string prefix across files |
| `PolicyRule::matches_resource` | `PatternKind::FilesystemPath` / exact match | Yes | `engine::tests::test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority` | Matches exact path |
| `Policy::validate_and_resolve_patterns` | `rule.resolve_pattern()` error | Yes | `engine::tests::test_replace_policies_atomic_rejection_on_invalid_rule_preserves_old_set` | Atomically rejects entire policy on bad rule |
| `Policy::from_json` | `serde_json::from_str` syntax error | Yes | `engine::tests::test_audit_policy_config_parsing_failure_at_startup` | Returns `SerializationError` |
| `Policy::from_json` | Valid JSON with invalid pattern | Yes | `engine::tests::test_audit_policy_config_parsing_failure_at_startup` | Rejects via `validate_and_resolve_patterns` |

---

## 3. Branch and Match Arm Audit: `crates/policy/src/engine.rs`

| Function / Component | Branch / Match Arm / Conditional | Covered? | Covering Unit Test(s) | Notes / Uncovered Reason |
| :--- | :--- | :--- | :--- | :--- |
| `PolicyEngine::add_policy` | Pre-validation error (`validate_and_resolve_patterns`) | Yes | `test_replace_policies_atomic_rejection_on_invalid_rule_preserves_old_set` | Atomic rejection before state modification |
| `PolicyEngine::add_policy` | Storage write lock normal / poisoned | Yes | `test_add_policy_rejects_duplicate_id`, `test_audit_policy_lock_poisoning_and_clear_recovery` | Lock poisoning recovery recovers underlying data |
| `PolicyEngine::add_policy` | Duplicate policy ID check (`guard.iter().any`) | Yes | `test_add_policy_rejects_duplicate_id` | Rejects duplicate policy ID with `DuplicatePolicyId` |
| `PolicyEngine::replace_policies` | Duplicate policy ID in replacement set | Yes | `test_replace_policies_rejects_duplicate_ids_within_new_set` | Pre-checks candidate set before touching lock |
| `PolicyEngine::replace_policies` | Pre-validation error in replacement set | Yes | `test_replace_policies_atomic_rejection_on_invalid_rule_preserves_old_set` | Leaves existing active policy set 100% in effect |
| `PolicyEngine::replace_policies` | Successful atomic swap under write lock | Yes | `test_replace_policies_atomic_rejection_on_invalid_rule_preserves_old_set` | Replaces full set and clears lock poison |
| `PolicyEngine::clear` | Write lock normal / poisoned | Yes | `test_audit_policy_lock_poisoning_and_clear_recovery` | Clears policies and clears poison flag |
| `PolicyEngine::load_policy_from_json` | Parsing / resolution error | Yes | `test_audit_non_atomic_config_load_preserves_existing_policies` | Preserves existing policies on error |
| `PolicyEngine::evaluate` | `catch_unwind` -> `Ok(response)` | Yes | Standard evaluation tests | Normal evaluation path |
| `PolicyEngine::evaluate` | `catch_unwind` -> `Err(panic_payload)` | Yes | `test_audit_policy_evaluation_panic_resolves_to_deny` | Fails closed to `Decision::Deny` (`fail-closed-evaluation-panic`) |
| `PolicyEngine::evaluate_internal` | Request consistency check (`action_type` or `target` mismatch) | Yes | `test_audit_malformed_request_unknown_action_type_never_allowed`, `main::tests::test_process_action_request_mismatch_denied_pre_resolution_and_recorded` | Denies pre-resolution (`fail-closed-request-mismatch`) |
| `PolicyEngine::evaluate_internal` | Relative path check (`is_path_resource` && `!p.is_absolute()`) | Yes | `regression_relative_path_policy`, `main::tests::test_process_action_relative_path_denied_pre_resolution_and_recorded` | Denies pre-resolution (`fail-closed-relative-path`) |
| `PolicyEngine::evaluate_internal` | Path resolution -> `Ok(Some(path))` | Yes | `test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority` | Canonical path resolution recorded |
| `PolicyEngine::evaluate_internal` | Path resolution -> `Ok(None)` | Yes | `regression_event_resolved_path_logging` | Literal target passed without resolution |
| `PolicyEngine::evaluate_internal` | Path resolution -> `Err(err)` | Yes | `test_audit_symlink_loop_resolves_to_deny`, `main::tests::test_process_action_resolution_failure_symlink_loop_denied_and_recorded` | Symlink loops / unresolvable paths fail closed to Deny |
| `PolicyEngine::evaluate_internal` | Read lock poisoned | Yes | `test_audit_policy_lock_poisoning_and_clear_recovery` | Storage lock poisoning fails closed to Deny |
| `PolicyEngine::evaluate_internal` | `matching_rules.is_empty()` | Yes | `test_audit_zero_matching_rules_resolves_to_deny`, `main::tests::test_process_action_default_deny_when_unmatched_and_recorded` | Default fail-closed Deny (`default-fail-closed`) |
| `PolicyEngine::evaluate_internal` | Precedence Stage 1: Priority DESC | Yes | `test_rule_precedence_priority_override_beats_specificity_and_decision` | Priority overrides specificity and decision |
| `PolicyEngine::evaluate_internal` | Precedence Stage 2a: Exact vs Wildcard | Yes | `test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority` | Exact paths beat wildcard at equal priority |
| `PolicyEngine::evaluate_internal` | Precedence Stage 2b: Component Depth | Yes | `test_rule_precedence_specificity_component_depth_beats_shallower` | Deeper path components beat shallower |
| `PolicyEngine::evaluate_internal` | Precedence Stage 2c: Prefix Length | Yes | `test_rule_precedence_specificity_prefix_len_breaks_tie` | Longer prefix character length breaks tie |
| `PolicyEngine::evaluate_internal` | Precedence Stage 3: Deny beats Allow | Yes | `test_rule_precedence_deny_beats_allow_at_equal_priority_and_specificity` | Deny beats Allow at equal priority & specificity |
| `PolicyEngine::evaluate_internal` | Precedence Stage 4: Policy ID tie-breaker | Yes | `test_rule_precedence_policy_id_tie_breaker` | Lexicographical policy ID tie-breaker |
| `PolicyEngine::evaluate_internal` | Precedence Stage 5: Rule ID tie-breaker | Yes | `test_rule_precedence_rule_id_tie_breaker` | Lexicographical rule ID tie-breaker |
| `PolicyEngine::evaluate_internal` | Precedence selection: `matching_rules.first().copied()` -> `Some` | Yes | All rule matching tests | Chooses highest-precedence rule |
| `PolicyEngine::evaluate_internal` | Precedence selection: `matching_rules.first().copied()` -> `None` | **Deliberately Uncovered** | None | **Deliberately Uncovered**: Unreachable in normal execution. `matching_rules.is_empty()` returns early before sorting, and in-memory `sort_by` preserves vector length. Retained as defensive fail-closed fallback to satisfy Rule 1 (never panic, fail closed). |

---

## 4. Real Gateway Code vs. Test Harness Verification

The test harness in `tests/src/lib.rs` mirrors the gateway request handling. To eliminate the risk of gateway logic drifting from harness testing, direct tests against the real production gateway function (`process_action` in `apps/agnes-core/src/main.rs`) were implemented for every key decision path:

1. **Explicit Deny Rule & Security Event Recording:**
   - Test: `test_process_action_explicit_deny_rule_and_recorded`
   - Covers: Rejection of request matching a Deny rule, enforcement result `BlockRequest`, and emission of `SecurityEvent` with `policy_id`, `rule_id`, and canonical `resolved_resource`.
2. **Default Deny for Unmatched Request & Security Event Recording:**
   - Test: `test_process_action_default_deny_when_unmatched_and_recorded`
   - Covers: Default fail-closed Deny when zero rules match, recording `policy_id: "default-fail-closed"`, `rule_id: None`, and resolved path.
3. **Relative Path Pre-Resolution Rejection & Security Event Recording:**
   - Test: `test_process_action_relative_path_denied_pre_resolution_and_recorded`
   - Covers: Immediate rejection of relative path prior to filesystem traversal, recording `policy_id: "fail-closed-relative-path"` and `resolved_resource: None`.
4. **Request Header / Payload Mismatch Pre-Resolution Rejection & Security Event Recording:**
   - Test: `test_process_action_request_mismatch_denied_pre_resolution_and_recorded`
   - Covers: Immediate rejection when header `target_resource` disagrees with inner payload target, recording `policy_id: "fail-closed-request-mismatch"` and `resolved_resource: None`.
5. **Path Resolution Failure (Symlink Loop) Rejection & Security Event Recording:**
   - Test: `test_process_action_resolution_failure_symlink_loop_denied_and_recorded`
   - Covers: Rejection when path resolution encounters an infinite symlink cycle, recording `policy_id: "fail-closed-path-resolution"` and `resolved_resource: None`.
