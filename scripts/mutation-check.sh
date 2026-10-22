#!/usr/bin/env bash
set -euo pipefail

# Project Agnes - Automated Mutation Verification Gate
# Creates a temporary git worktree copy, applies each mutation, runs the target regression test,
# verifies that the test FAILS (proving the test pins the security invariant), and removes the copy.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKTREE_DIR="$(mktemp -d /tmp/agnes_mutation_gate.XXXXXX)"

cleanup() {
    echo "Cleaning up worktree at ${WORKTREE_DIR}..."
    git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
    rm -rf "${WORKTREE_DIR}"
}
trap cleanup EXIT INT TERM

echo "Creating temporary git worktree at ${WORKTREE_DIR}..."
git -C "${REPO_ROOT}" worktree add "${WORKTREE_DIR}" HEAD --detach

# Export CARGO_TARGET_DIR to reuse dependencies build cache
export CARGO_TARGET_DIR="${REPO_ROOT}/target"

TOTAL_MUTATIONS=0
CAUGHT_MUTATIONS=0

run_mutation() {
    local num="$1"
    local name="$2"
    local test_pkg="$3"
    local test_target="$4"
    local test_name="$5"
    local python_mutator="$6"

    TOTAL_MUTATIONS=$((TOTAL_MUTATIONS + 1))
    echo "----------------------------------------------------------------------"
    echo "Mutation ${num}: ${name}"
    
    # Reset worktree state to HEAD
    git -C "${WORKTREE_DIR}" reset --hard HEAD >/dev/null
    git -C "${WORKTREE_DIR}" clean -fd >/dev/null

    # Apply mutation via python
    python3 -c "${python_mutator}" "${WORKTREE_DIR}"

    # Run the test expected to catch the mutation
    set +e
    if [ -n "${test_pkg}" ] && [ -n "${test_target}" ]; then
        (cd "${WORKTREE_DIR}" && cargo test --package "${test_pkg}" --test "${test_target}" -- "${test_name}" >/dev/null 2>&1)
    elif [ -n "${test_pkg}" ]; then
        (cd "${WORKTREE_DIR}" && cargo test --package "${test_pkg}" -- "${test_name}" >/dev/null 2>&1)
    else
        (cd "${WORKTREE_DIR}" && cargo test --test "${test_target}" -- "${test_name}" >/dev/null 2>&1)
    fi
    local status=$?
    set -e

    if [ ${status} -ne 0 ]; then
        echo "RESULT: PASS (Mutation was caught by ${test_name}; test failed as expected)"
        CAUGHT_MUTATIONS=$((CAUGHT_MUTATIONS + 1))
    else
        echo "RESULT: FAIL (Mutation was NOT caught! Test ${test_name} passed unexpectedly)"
    fi
}

echo "Starting Mutation Verification Suite..."

# Mutation 1: Symlinks no longer followed in path resolution
run_mutation 1 \
    "Symlinks no longer followed in path resolution" \
    "agnes-tests" "adversarial_bypass_002" "test_regression_symlink_inside_allowed_pointing_to_denied_evaluated_against_denied_policy_and_rejected" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/path.rs")
c = open(f).read()
old = "resolve_real_path(&request.target_resource).map(Some)"
new = "Ok(Some(PathBuf::from(&request.target_resource)))"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 2: Post-open check removed
run_mutation 2 \
    "Post-open check removed" \
    "agnes-tests" "regression_filesystem_boundary" "test_regression_018_toctou_symlink_swap_between_policy_and_enforcement" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/enforcement/src/filesystem.rs")
c = open(f).read()
old = "if opened_path != expected_path {"
new = "if false && opened_path != expected_path {"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 3: Default deny branch returns Allow
run_mutation 3 \
    "Default deny branch returns Allow" \
    "agnes-tests" "regression_filesystem_boundary" "test_regression_020_zero_matching_rules_resolves_to_deny" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = """            return PolicyDecisionResponse {
                decision: Decision::Deny,
                reason: DecisionReason {
                    policy_id: "default-fail-closed".to_string(),"""
new = """            return PolicyDecisionResponse {
                decision: Decision::Allow,
                reason: DecisionReason {
                    policy_id: "default-fail-closed".to_string(),"""
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 4: Priority order flipped (lowest first)
run_mutation 4 \
    "Priority order flipped (lowest first)" \
    "agnes-policy" "" "test_rule_precedence_priority_override_beats_specificity_and_decision" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = "r_b.priority\n                .cmp(&r_a.priority)"
new = "r_a.priority\n                .cmp(&r_b.priority)"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 5: Specificity ignored
run_mutation 5 \
    "Specificity ignored in rule comparison" \
    "agnes-policy" "" "test_exact_path_beats_wildcard_regardless_of_decision_at_equal_priority" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = ".then_with(|| r_b.specificity().cmp(&r_a.specificity()))"
new = ".then_with(|| std::cmp::Ordering::Equal)"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 6: Deny no longer wins ties
run_mutation 6 \
    "Deny no longer wins ties (Allow wins ties)" \
    "agnes-policy" "" "test_rule_precedence_deny_beats_allow_at_equal_priority_and_specificity" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
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
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 7: Relative path accepted
run_mutation 7 \
    "Relative path accepted without deny" \
    "agnes-tests" "regression_relative_path_policy" "test_relative_request_path_denied_under_different_cwds" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = """        if is_path_resource(request.action_type) {
            let p = Path::new(&request.target_resource);
            if !p.is_absolute() {"""
new = """        if false && is_path_resource(request.action_type) {
            let p = Path::new(&request.target_resource);
            if !p.is_absolute() {"""
assert old in c, "target string 1 not found"
open(f, "w").write(c.replace(old, new, 1))

f2 = os.path.join(w, "crates/policy/src/path.rs")
c2 = open(f2).read()
old2 = "if !Path::new(&request.target_resource).is_absolute() {"
new2 = "if false {"
assert old2 in c2, "target string 2 not found"
c2 = c2.replace(old2, new2, 1)

old3 = "if !Path::new(raw_path).is_absolute() {"
new3 = "if false {"
assert old3 in c2, "target string 3 not found"
open(f2, "w").write(c2.replace(old3, new3, 1))
'

# Mutation 8: Request mismatch check skipped
run_mutation 8 \
    "Request mismatch check skipped" \
    "agnes-tests" "regression_action_types_and_consistency" "test_request_consistency_action_type_mismatch_fails_on_old_code" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = "if request.action_type != expected_action_type || request.target_resource != expected_target {"
new = "if false && (request.action_type != expected_action_type || request.target_resource != expected_target) {"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 9: Null byte check removed
run_mutation 9 \
    "Null byte check removed from path and pattern resolution" \
    "agnes-tests" "regression_filesystem_boundary" "test_regression_029_null_byte_pattern_rejects_whole_policy_and_denies" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/model.rs")
c = open(f).read()
old = "if pattern.contains(\x27\\0\x27) {"
new = "if false && pattern.contains(\x27\\0\x27) {"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 10: Policy replacement done in two steps (clear then add)
run_mutation 10 \
    "Policy replacement done in non-atomic two steps" \
    "agnes-tests" "regression_policy_reload" "test_failed_replace_leaves_old_set_fully_in_effect_and_duplicate_rejected" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = """        *guard = new_policies;
        self.policies.clear_poison();"""
new = """        self.clear();
        for p in new_policies {
            let _ = self.add_policy(p.clone());
        }"""
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 11: Duplicate policy id accepted
run_mutation 11 \
    "Duplicate policy id accepted" \
    "agnes-policy" "" "test_replace_policies_rejects_duplicate_ids_within_new_set" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/engine.rs")
c = open(f).read()
old = "if !seen_ids.insert(&policy.id) {"
new = "if false && !seen_ids.insert(&policy.id) {"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 12: Non path patterns resolved as paths
run_mutation 12 \
    "Non path patterns resolved as paths" \
    "agnes-tests" "regression_action_types_and_consistency" "test_policy_mixing_file_and_http_rules_loads_and_evaluates" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/policy/src/model.rs")
c = open(f).read()
old = "            Ok(PatternKind::LiteralString)"
new = "            Ok(PatternKind::FilesystemPath)"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 13: Folding probe always passes
run_mutation 13 \
    "Folding probe always passes (reports NoFolding)" \
    "agnes-enforcement" "" "test_simulated_fs_writable_case_folding_rejected_and_probe_removed" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "crates/enforcement/src/filesystem.rs")
c = open(f).read()
old = "pub fn detect_filesystem_folding_with_fs(root: &Path, fs: &dyn FoldingFsLookup) -> Result<(), String> {"
new = "pub fn detect_filesystem_folding_with_fs(_root: &Path, _fs: &dyn FoldingFsLookup) -> Result<(), String> {\n    return Ok(());\n}"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

# Mutation 14: Gateway event drops the resolved path
run_mutation 14 \
    "Gateway event drops the resolved path" \
    "agnes-core" "" "test_process_action_records_resolved_path_for_symlink" \
    '
import sys, os
w = sys.argv[1]
f = os.path.join(w, "apps/agnes-core/src/main.rs")
c = open(f).read()
old = "decision_resp.resolved_resource.clone(),"
new = "None,"
assert old in c, "target string not found"
open(f, "w").write(c.replace(old, new, 1))
'

echo "======================================================================"
echo "Mutation Check Summary: ${CAUGHT_MUTATIONS} / ${TOTAL_MUTATIONS} mutations caught"
if [ "${CAUGHT_MUTATIONS}" -eq "${TOTAL_MUTATIONS}" ]; then
    echo "ALL MUTATIONS CAUGHT. Milestone 1 security tests verified."
    exit 0
else
    echo "ERROR: Some mutations were not caught!"
    exit 1
fi
