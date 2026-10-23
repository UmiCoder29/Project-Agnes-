#!/usr/bin/env bash
set -euo pipefail

# Project Agnes - Automated Mutation Verification Gate
# Creates a temporary git worktree copy, validates each baseline test on unmutated code,
# verifies project compiles after mutation (rejecting compile failures as BROKEN MUTATION),
# runs the regression test, verifies test failure ("<test_name> ... FAILED" and "1 failed"),
# and runs a self-test proving the harness correctly reports NOT caught on mismatched tests.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKTREE_DIR="$(mktemp -d /tmp/agnes_mutation_gate.XXXXXX)"
rmdir "${WORKTREE_DIR}"
LOG_DIR="$(mktemp -d /tmp/agnes_mutation_logs.XXXXXX)"
TMP_TARGET_DIR="$(mktemp -d /tmp/agnes_mutation_target.XXXXXX)"

cleanup() {
    echo "Cleaning up worktree at ${WORKTREE_DIR}..."
    git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
    rm -rf "${WORKTREE_DIR}" "${LOG_DIR}" "${TMP_TARGET_DIR}"
}
trap cleanup EXIT INT TERM

echo "Creating temporary git worktree at ${WORKTREE_DIR}..."
git -C "${REPO_ROOT}" worktree add "${WORKTREE_DIR}" HEAD --detach

# Export CARGO_TARGET_DIR to temporary target directory unless overridden
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    export CARGO_TARGET_DIR="${TMP_TARGET_DIR}"
fi
echo "Using CARGO_TARGET_DIR: ${CARGO_TARGET_DIR}"
echo "Using LOG_DIR: ${LOG_DIR}"

TOTAL_MUTATIONS=0
CAUGHT_MUTATIONS=0
NOT_CAUGHT_MUTATIONS=0
BROKEN_MUTATIONS=0
BASELINE_FAILURES=0

run_mutation() {
    local num="$1"
    local name="$2"
    local test_pkg="$3"
    local test_kind="$4"    # "--test", "--lib", or "--bin"
    local test_target="$5"  # test target name, or empty for --lib
    local test_name="$6"
    local python_mutator="$7"

    TOTAL_MUTATIONS=$((TOTAL_MUTATIONS + 1))
    echo "======================================================================"
    echo "Mutation ${num}: ${name}"
    
    # Reset worktree state to HEAD
    git -C "${WORKTREE_DIR}" reset --hard HEAD >/dev/null 2>&1
    git -C "${WORKTREE_DIR}" clean -fd >/dev/null 2>&1

    # Build cargo test argument list
    local cargo_args=("--package" "${test_pkg}")
    if [ "${test_kind}" = "--test" ]; then
        cargo_args+=("--test" "${test_target}")
    elif [ "${test_kind}" = "--bin" ]; then
        cargo_args+=("--bin" "${test_target}")
    elif [ "${test_kind}" = "--lib" ]; then
        cargo_args+=("--lib")
    fi

    # 1. Baseline: Run the named test on the UNMUTATED worktree
    local baseline_log="${LOG_DIR}/mutation_${num}_baseline.log"
    echo "  [1/3] Running baseline test: ${test_name} on unmutated code..."
    set +e
    (cd "${WORKTREE_DIR}" && cargo test "${cargo_args[@]}" -- "${test_name}" >"${baseline_log}" 2>&1)
    local baseline_status=$?
    set -e

    if [ ${baseline_status} -ne 0 ] || ! grep -q "${test_name} \.\.\. ok" "${baseline_log}" || ! grep -q "1 passed; 0 failed" "${baseline_log}"; then
        echo "  RESULT: BASELINE FAILURE! Test ${test_name} failed or did not run exactly 1 passing test."
        echo "  Log: ${baseline_log}"
        BASELINE_FAILURES=$((BASELINE_FAILURES + 1))
        return
    fi
    echo "  Baseline passed (1 passed; 0 failed). Log: ${baseline_log}"

    # 2. Apply mutation via python
    echo "  [2/3] Applying mutation..."
    python3 -c "${python_mutator}" "${WORKTREE_DIR}"

    # Verify project still compiles (cargo test --no-run)
    local compile_log="${LOG_DIR}/mutation_${num}_compile.log"
    set +e
    (cd "${WORKTREE_DIR}" && cargo test "${cargo_args[@]}" --no-run >"${compile_log}" 2>&1)
    local compile_status=$?
    set -e

    if [ ${compile_status} -ne 0 ]; then
        echo "  RESULT: BROKEN MUTATION! Project failed to compile with mutation applied."
        echo "  Log: ${compile_log}"
        BROKEN_MUTATIONS=$((BROKEN_MUTATIONS + 1))
        return
    fi

    # 3. Run the named test and verify failure
    local test_log="${LOG_DIR}/mutation_${num}_test.log"
    echo "  [3/3] Running regression test against mutated code..."
    set +e
    (cd "${WORKTREE_DIR}" && cargo test "${cargo_args[@]}" -- "${test_name}" >"${test_log}" 2>&1)
    local test_status=$?
    set -e

    # Requirement: count as caught ONLY when output contains exact test name with FAILED and "1 failed"
    if grep -E -q "${test_name} \.\.\. FAILED" "${test_log}" && grep -q "1 failed" "${test_log}"; then
        echo "  RESULT: PASS (Mutation was caught by ${test_name}; test failed as expected)"
        echo "  Log: ${test_log}"
        CAUGHT_MUTATIONS=$((CAUGHT_MUTATIONS + 1))
    else
        echo "  RESULT: FAIL (Mutation was NOT caught! Test ${test_name} passed or did not fail as expected)"
        echo "  Log: ${test_log}"
        NOT_CAUGHT_MUTATIONS=$((NOT_CAUGHT_MUTATIONS + 1))
    fi
}

echo "Starting Mutation Verification Suite..."

# Mutation 1: Symlinks no longer followed in path resolution
run_mutation 1 \
    "Symlinks no longer followed in path resolution" \
    "agnes-tests" "--test" "adversarial_bypass_002" \
    "test_regression_symlink_inside_allowed_pointing_to_denied_evaluated_against_denied_policy_and_rejected" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/path.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "resolve_real_path(&request.target_resource).map(Some)"
new = "Ok(Some(PathBuf::from(&request.target_resource)))"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 2: Post-open check removed
run_mutation 2 \
    "Post-open check removed" \
    "agnes-tests" "--test" "regression_filesystem_boundary" \
    "test_regression_018_toctou_symlink_swap_between_policy_and_enforcement" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/enforcement/src/filesystem.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "if opened_path != expected_path {"
new = "if false && opened_path != expected_path {"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 3: Default deny branch returns Allow
run_mutation 3 \
    "Default deny branch returns Allow" \
    "agnes-tests" "--test" "regression_filesystem_boundary" \
    "test_regression_020_zero_matching_rules_resolves_to_deny" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = """            return PolicyDecisionResponse {
                decision: Decision::Deny,
                reason: DecisionReason {
                    policy_id: "default-fail-closed".to_string(),"""
new = """            return PolicyDecisionResponse {
                decision: Decision::Allow,
                reason: DecisionReason {
                    policy_id: "default-fail-closed".to_string(),"""
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 4: Priority order flipped (lowest first)
run_mutation 4 \
    "Priority order flipped (lowest first)" \
    "agnes-policy" "--lib" "" \
    "test_rule_precedence_priority_override_beats_specificity_and_decision" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "r_b.priority\n                .cmp(&r_a.priority)"
new = "r_a.priority\n                .cmp(&r_b.priority)"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 5: Specificity ignored
run_mutation 5 \
    "Specificity ignored in rule comparison" \
    "agnes-policy" "--lib" "" \
    "test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = ".then_with(|| r_b.specificity().cmp(&r_a.specificity()))"
new = ".then_with(|| std::cmp::Ordering::Equal)"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 6: Deny no longer wins ties
run_mutation 6 \
    "Deny no longer wins ties (Allow wins ties)" \
    "agnes-policy" "--lib" "" \
    "test_rule_precedence_deny_beats_allow_at_equal_priority_and_specificity" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = """                    match (r_a.decision, r_b.decision) {
                        (Decision::Deny, Decision::Allow) => std::cmp::Ordering::Less,
                        (Decision::Allow, Decision::Deny) => std::cmp::Ordering::Greater,
                        _ => std::cmp::Ordering::Equal,
                    }"""
new = """                    match (r_a.decision, r_b.decision) {
                        (Decision::Deny, Decision::Allow) => std::cmp::Ordering::Greater,
                        (Decision::Allow, Decision::Deny) => std::cmp::Ordering::Less,
                        _ => std::cmp::Ordering::Equal,
                    }"""
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 7: Relative path accepted
run_mutation 7 \
    "Relative path accepted without deny" \
    "agnes-tests" "--test" "regression_relative_path_policy" \
    "test_relative_request_path_denied_under_different_cwds" \
    '
import sys, os
w = sys.argv[1]
rel_path1 = "crates/policy/src/engine.rs"
full_path1 = os.path.join(w, rel_path1)
c1 = open(full_path1).read()
old1 = """        if is_path_resource(request.action_type) {
            let p = Path::new(&request.target_resource);
            if !p.is_absolute() {"""
new1 = """        if false && is_path_resource(request.action_type) {
            let p = Path::new(&request.target_resource);
            if !p.is_absolute() {"""
assert old1 in c1, f"target string 1 not found in {rel_path1}"
line_no1 = c1[:c1.index(old1)].count("\n") + 1
print(f"  Applied mutation at {rel_path1}:{line_no1}")
open(full_path1, "w").write(c1.replace(old1, new1, 1))

rel_path2 = "crates/policy/src/path.rs"
full_path2 = os.path.join(w, rel_path2)
c2 = open(full_path2).read()
old2 = "if !Path::new(&request.target_resource).is_absolute() {"
new2 = "if false {"
assert old2 in c2, f"target string 2 not found in {rel_path2}"
line_no2 = c2[:c2.index(old2)].count("\n") + 1
print(f"  Applied mutation at {rel_path2}:{line_no2}")
c2 = c2.replace(old2, new2, 1)

old3 = "if !Path::new(raw_path).is_absolute() {"
new3 = "if false {"
assert old3 in c2, f"target string 3 not found in {rel_path2}"
line_no3 = c2[:c2.index(old3)].count("\n") + 1
print(f"  Applied mutation at {rel_path2}:{line_no3}")
open(full_path2, "w").write(c2.replace(old3, new3, 1))
'

# Mutation 8: Request mismatch check skipped
run_mutation 8 \
    "Request mismatch check skipped" \
    "agnes-tests" "--test" "regression_action_types_and_consistency" \
    "test_request_consistency_action_type_mismatch_fails_on_old_code" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "if request.action_type != expected_action_type || request.target_resource != expected_target {"
new = "if false && (request.action_type != expected_action_type || request.target_resource != expected_target) {"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 9: Null byte check removed from path and rule matching
run_mutation 9 \
    "Null byte check removed from path and rule matching" \
    "agnes-policy" "--lib" "" \
    "test_matches_target_null_byte_rejection_and_agent_matching" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/model.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "if target.contains(\x27\\0\x27) {"
new = "if false && target.contains(\x27\\0\x27) {"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 10: Policy replacement done in non-atomic two steps (clears state before validation)
run_mutation 10 \
    "Policy replacement done in non-atomic two steps (clears state before validation)" \
    "agnes-tests" "--test" "regression_policy_reload" \
    "test_failed_replace_leaves_old_set_fully_in_effect_and_duplicate_rejected" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = """        // 2. Validate and resolve every rule pattern across every policy BEFORE touching state
        for policy in &mut new_policies {
            policy.validate_and_resolve_patterns()?;
        }

        // 3. Atomically swap the entire policy set under ONE write lock acquisition
        let mut guard = match self.policies.write() {"""
new = """        // Non-atomic mutation: clear state before validation
        let mut guard = match self.policies.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clear();
        for policy in &mut new_policies {
            policy.validate_and_resolve_patterns()?;
        }
        let mut guard = match self.policies.write() {"""
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 11: Duplicate policy id accepted
run_mutation 11 \
    "Duplicate policy id accepted" \
    "agnes-policy" "--lib" "" \
    "test_replace_policies_rejects_duplicate_ids_within_new_set" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/engine.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "if !seen_ids.insert(&policy.id) {"
new = "if false && !seen_ids.insert(&policy.id) {"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 12: Non path patterns resolved as paths
run_mutation 12 \
    "Non path patterns resolved as paths" \
    "agnes-tests" "--test" "regression_action_types_and_consistency" \
    "test_policy_mixing_file_and_http_rules_loads_and_evaluates" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/policy/src/model.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "            Ok(PatternKind::LiteralString)"
new = "            Ok(PatternKind::FilesystemPath)"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 13: Folding probe always passes
run_mutation 13 \
    "Folding probe always passes (reports NoFolding)" \
    "agnes-enforcement" "--lib" "" \
    "test_simulated_fs_writable_case_folding_rejected_and_probe_removed" \
    '
import sys, os
w = sys.argv[1]
rel_path = "crates/enforcement/src/filesystem.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "pub fn detect_filesystem_folding_with_fs(root: &Path, fs: &dyn FoldingFsLookup) -> Result<(), String> {"
new = "pub fn detect_filesystem_folding_with_fs(_root: &Path, _fs: &dyn FoldingFsLookup) -> Result<(), String> { return Ok(()); } fn _unused_detect_filesystem_folding_with_fs(root: &Path, fs: &dyn FoldingFsLookup) -> Result<(), String> {"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

# Mutation 14: Gateway event drops the resolved path
run_mutation 14 \
    "Gateway event drops the resolved path" \
    "agnes-core" "--bin" "agnes-core" \
    "test_process_action_emits_security_event_with_resolved_path_and_rule_id" \
    '
import sys, os
w = sys.argv[1]
rel_path = "apps/agnes-core/src/main.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "decision_resp.resolved_resource.clone(),"
new = "None,"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
'

echo "======================================================================"
echo "Self-Test: Verifying harness reports NOT caught on deliberately mismatched test name"
echo "======================================================================"

SELF_TEST_PASSED=false
# Reset worktree state to HEAD
git -C "${WORKTREE_DIR}" reset --hard HEAD >/dev/null 2>&1
git -C "${WORKTREE_DIR}" clean -fd >/dev/null 2>&1

# Apply Mutation 14 mutator
python3 -c '
import sys, os
w = sys.argv[1]
rel_path = "apps/agnes-core/src/main.rs"
full_path = os.path.join(w, rel_path)
c = open(full_path).read()
old = "decision_resp.resolved_resource.clone(),"
new = "None,"
assert old in c, f"target string not found in {rel_path}"
line_no = c[:c.index(old)].count("\n") + 1
print(f"  Applied self-test mutation at {rel_path}:{line_no}")
open(full_path, "w").write(c.replace(old, new, 1))
' "${WORKTREE_DIR}"

# Run with deliberately wrong test name
DELIBERATELY_WRONG_TEST="test_nonexistent_wrong_test_name_proves_harness_can_fail"
self_test_log="${LOG_DIR}/self_test_deliberate_failure.log"
set +e
(cd "${WORKTREE_DIR}" && cargo test --package "agnes-core" --bin "agnes-core" -- "${DELIBERATELY_WRONG_TEST}" >"${self_test_log}" 2>&1)
set -e

if grep -E -q "${DELIBERATELY_WRONG_TEST} \.\.\. FAILED" "${self_test_log}" && grep -q "1 failed" "${self_test_log}"; then
    echo "SELF-TEST FAILED: Script falsely reported wrong test name as CAUGHT!"
    SELF_TEST_PASSED=false
else
    echo "SELF-TEST PASSED: Script confirmed that wrong test name reports NOT caught."
    echo "Log: ${self_test_log}"
    SELF_TEST_PASSED=true
fi

echo "======================================================================"
echo "Mutation Verification Summary:"
echo "  Caught:            ${CAUGHT_MUTATIONS} / ${TOTAL_MUTATIONS}"
echo "  Not Caught:        ${NOT_CAUGHT_MUTATIONS}"
echo "  Broken Mutations:  ${BROKEN_MUTATIONS}"
echo "  Baseline Failures: ${BASELINE_FAILURES}"
echo "  Self-Test:         $(if [ "${SELF_TEST_PASSED}" = true ]; then echo "PASSED"; else echo "FAILED"; fi)"
echo "======================================================================"

if [ "${CAUGHT_MUTATIONS}" -eq "${TOTAL_MUTATIONS}" ] && \
   [ "${NOT_CAUGHT_MUTATIONS}" -eq 0 ] && \
   [ "${BROKEN_MUTATIONS}" -eq 0 ] && \
   [ "${BASELINE_FAILURES}" -eq 0 ] && \
   [ "${SELF_TEST_PASSED}" = true ]; then
    echo "ALL 14 MUTATIONS CAUGHT. SELF-TEST PASSED. Milestone 1 security tests verified."
    exit 0
else
    echo "ERROR: Mutation gate verification failed!"
    exit 1
fi
