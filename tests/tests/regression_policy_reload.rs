use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

use agnes_common::{ActionPayload, ActionRequest, ActionType, Decision};
use agnes_policy::{Policy, PolicyEngine, PolicyLoadError, PolicyRule};

/// Creates Policy Set A:
/// - Policy "policy-a-allow": Allow "<root>/*" (priority 10)
/// - Policy "policy-a-deny": Deny "<root>/secret/*" (priority 20)
fn create_set_a(root: &Path) -> Vec<Policy> {
    let allow_rule = PolicyRule {
        id: "rule-a-allow-all".to_string(),
        description: "Allow all in root for Set A".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", root.display()),
        priority: 10,
    };
    let deny_rule = PolicyRule {
        id: "rule-a-deny-secret".to_string(),
        description: "Deny secret in root for Set A".to_string(),
        decision: Decision::Deny,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/secret/*", root.display()),
        priority: 20,
    };

    vec![
        Policy::new("policy-a-allow", "Set A Allow Policy", 1).with_rule(allow_rule),
        Policy::new("policy-a-deny", "Set A Deny Policy", 2).with_rule(deny_rule),
    ]
}

/// Creates Policy Set B:
/// - Policy "policy-b-allow": Allow "<root>/*" (priority 10)
/// - Policy "policy-b-deny": Deny "<root>/secret/*" (priority 20)
fn create_set_b(root: &Path) -> Vec<Policy> {
    let allow_rule = PolicyRule {
        id: "rule-b-allow-all".to_string(),
        description: "Allow all in root for Set B".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", root.display()),
        priority: 10,
    };
    let deny_rule = PolicyRule {
        id: "rule-b-deny-secret".to_string(),
        description: "Deny secret in root for Set B".to_string(),
        decision: Decision::Deny,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/secret/*", root.display()),
        priority: 20,
    };

    vec![
        Policy::new("policy-b-allow", "Set B Allow Policy", 1).with_rule(allow_rule),
        Policy::new("policy-b-deny", "Set B Deny Policy", 2).with_rule(deny_rule),
    ]
}

struct TestEnv {
    _temp: tempfile::TempDir,
    root: PathBuf,
    secret_file: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempdir().unwrap();
        let root = temp.path().join("sandbox_root");
        let secret_dir = root.join("secret");
        fs::create_dir_all(&secret_dir).unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let secret_file = canonical_root.join("secret").join("canary.txt");
        fs::write(&secret_file, "CONFIDENTIAL_CANARY").unwrap();

        Self {
            _temp: temp,
            root: canonical_root,
            secret_file,
        }
    }
}

/// Requirement 4: Concurrency regression test.
///
/// Runs N evaluator threads continuously evaluating a path that Set A and Set B both deny
/// ("<root>/secret/*"). Concurrently, a reloader thread alternates between Set A and Set B
/// via `replace_policies` many times.
///
/// Every evaluation MUST be Deny and MUST originate from exactly one of the two complete sets
/// ("policy-a-deny" or "policy-b-deny"). No evaluator can ever observe an intermediate state,
/// a mixed set, or a fail-open Allow decision.
#[test]
fn test_concurrent_policy_replacement_never_observes_partial_state() {
    let env = TestEnv::new();
    let engine = Arc::new(PolicyEngine::new());

    // Initially load Set A
    engine.replace_policies(create_set_a(&env.root)).unwrap();

    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_evaluations = Arc::new(AtomicUsize::new(0));
    let allow_observations = Arc::new(AtomicUsize::new(0));
    let invalid_policy_observations = Arc::new(AtomicUsize::new(0));

    let num_evaluators = 8;
    let mut handles = Vec::new();

    // Spawn evaluator threads
    for thread_idx in 0..num_evaluators {
        let engine_clone = Arc::clone(&engine);
        let stop_clone = Arc::clone(&stop_flag);
        let total_clone = Arc::clone(&total_evaluations);
        let allow_clone = Arc::clone(&allow_observations);
        let invalid_clone = Arc::clone(&invalid_policy_observations);
        let secret_path_str = env.secret_file.to_str().unwrap().to_string();

        let handle = thread::spawn(move || {
            let req = ActionRequest::new(
                format!("agent-{:03}", thread_idx),
                ActionPayload::ReadFile {
                    path: secret_path_str,
                },
            );

            while !stop_clone.load(Ordering::Relaxed) {
                let decision = engine_clone.evaluate(&req);
                total_clone.fetch_add(1, Ordering::Relaxed);

                if decision.decision == Decision::Allow {
                    allow_clone.fetch_add(1, Ordering::SeqCst);
                }

                // Decision MUST come from either complete Set A (policy-a-deny) or complete Set B (policy-b-deny)
                if decision.matched_policy_id != "policy-a-deny"
                    && decision.matched_policy_id != "policy-b-deny"
                {
                    invalid_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    // Reloader thread alternates between Set A and Set B
    let reloads = 100;
    for i in 0..reloads {
        if i % 2 == 0 {
            engine.replace_policies(create_set_b(&env.root)).unwrap();
        } else {
            engine.replace_policies(create_set_a(&env.root)).unwrap();
        }
        thread::yield_now();
    }

    // Stop evaluator threads
    stop_flag.store(true, Ordering::SeqCst);
    for handle in handles {
        handle.join().unwrap();
    }

    let total = total_evaluations.load(Ordering::SeqCst);
    let allows = allow_observations.load(Ordering::SeqCst);
    let invalid = invalid_policy_observations.load(Ordering::SeqCst);

    assert!(
        total >= 1000,
        "Expected at least 1000 evaluations across threads, got {}",
        total
    );
    assert_eq!(
        allows, 0,
        "FAIL-OPEN VIOLATION: Observed {} Allow decisions during atomic reload!",
        allows
    );
    assert_eq!(
        invalid, 0,
        "PARTIAL/MIXED STATE: Observed {} evaluations not matching Set A or Set B deny!",
        invalid
    );
}

/// Requirement 4 (Legacy Failure Demonstration):
/// Shows that the OLD approach (clear() followed by add_policy() calls one at a time,
/// with Allow policy loaded first) exposes a race condition where evaluators observe Allow
/// for a path that is supposed to be denied.
#[test]
fn test_legacy_clear_then_add_permits_fail_open_window() {
    let env = TestEnv::new();
    let engine = Arc::new(PolicyEngine::new());

    // Initially load Set A
    let set_a = create_set_a(&env.root);
    for policy in set_a {
        engine.add_policy(policy).unwrap();
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let total_evaluations = Arc::new(AtomicUsize::new(0));
    let allow_observations = Arc::new(AtomicUsize::new(0));

    let num_evaluators = 8;
    let mut handles = Vec::new();

    // Spawn evaluator threads
    for thread_idx in 0..num_evaluators {
        let engine_clone = Arc::clone(&engine);
        let stop_clone = Arc::clone(&stop_flag);
        let total_clone = Arc::clone(&total_evaluations);
        let allow_clone = Arc::clone(&allow_observations);
        let secret_path_str = env.secret_file.to_str().unwrap().to_string();

        let handle = thread::spawn(move || {
            let req = ActionRequest::new(
                format!("agent-{:03}", thread_idx),
                ActionPayload::ReadFile {
                    path: secret_path_str,
                },
            );

            while !stop_clone.load(Ordering::Relaxed) {
                let decision = engine_clone.evaluate(&req);
                total_clone.fetch_add(1, Ordering::Relaxed);

                if decision.decision == Decision::Allow {
                    allow_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    // Reloader thread simulates the OLD non-atomic approach:
    // clear() then add_policy(allow) then add_policy(deny)
    for _ in 0..50 {
        let set_b = create_set_b(&env.root);
        engine.clear();
        // Allow policy is loaded first -> WINDOW OF VULNERABILITY
        engine.add_policy(set_b[0].clone()).unwrap();
        // Brief yield to expose the race window to evaluators
        thread::yield_now();
        engine.add_policy(set_b[1].clone()).unwrap();

        let set_a = create_set_a(&env.root);
        engine.clear();
        engine.add_policy(set_a[0].clone()).unwrap();
        thread::yield_now();
        engine.add_policy(set_a[1].clone()).unwrap();
    }

    stop_flag.store(true, Ordering::SeqCst);
    for handle in handles {
        handle.join().unwrap();
    }

    let allows = allow_observations.load(Ordering::SeqCst);
    assert!(
        allows > 0,
        "The old clear-then-add approach MUST produce at least one Allow observation (got 0)"
    );
}

/// Requirement 5: Test that a failed replace leaves the old set fully in effect and keeps denying,
/// and that duplicate IDs within the new set are rejected.
#[test]
fn test_failed_replace_leaves_old_set_fully_in_effect_and_duplicate_rejected() {
    let env = TestEnv::new();
    let engine = PolicyEngine::new();

    // Load initial Set A
    engine.replace_policies(create_set_a(&env.root)).unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: env.secret_file.to_str().unwrap().to_string(),
        },
    );

    // Initial state: Set A is active and denies secret path
    let initial_decision = engine.evaluate(&req);
    assert_eq!(initial_decision.decision, Decision::Deny);
    assert_eq!(initial_decision.matched_policy_id, "policy-a-deny");

    // 1. Attempt replace with a candidate set containing an invalid rule pattern (null byte)
    let mut bad_set = create_set_b(&env.root);
    bad_set.push(
        Policy::new("policy-invalid", "Invalid Rule Policy", 99).with_rule(PolicyRule {
            id: "rule-null".to_string(),
            description: "Invalid null byte rule".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/invalid/\0path".to_string(),
            priority: 100,
        }),
    );

    let res_invalid = engine.replace_policies(bad_set);
    assert!(res_invalid.is_err(), "Must reject replacement containing invalid rule pattern");

    // Old Set A must remain 100% in effect
    let post_err_decision = engine.evaluate(&req);
    assert_eq!(
        post_err_decision.decision,
        Decision::Deny,
        "Failed replacement must leave old set active and denying"
    );
    assert_eq!(
        post_err_decision.matched_policy_id,
        "policy-a-deny",
        "Must still match Set A's deny policy"
    );

    // 2. Attempt replace with duplicate policy IDs within the new set
    let dup_policy1 = Policy::new("policy-dup", "Dup 1", 1).with_rule(PolicyRule {
        id: "r1".to_string(),
        description: "Rule 1".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: "*".to_string(),
        priority: 10,
    });
    let dup_policy2 = Policy::new("policy-dup", "Dup 2", 2).with_rule(PolicyRule {
        id: "r2".to_string(),
        description: "Rule 2".to_string(),
        decision: Decision::Deny,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: "*".to_string(),
        priority: 20,
    });

    let res_dup = engine.replace_policies(vec![dup_policy1, dup_policy2]);
    match res_dup {
        Err(PolicyLoadError::DuplicatePolicyId { policy_id }) => {
            assert_eq!(policy_id, "policy-dup");
        }
        other => panic!("Expected DuplicatePolicyId error, got {:?}", other),
    }

    // Old Set A still remains 100% in effect
    let post_dup_decision = engine.evaluate(&req);
    assert_eq!(post_dup_decision.decision, Decision::Deny);
    assert_eq!(post_dup_decision.matched_policy_id, "policy-a-deny");
}
