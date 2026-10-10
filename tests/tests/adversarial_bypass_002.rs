use agnes_common::{ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult};
use agnes_policy::{Policy, PolicyRule};
use agnes_tests::SecurityTestHarness;
use std::fs;
use tempfile::tempdir;

const TEST_SECRET_TRAVERSAL: &str = "AGNES_TEST_SECRET_TRAVERSAL_sk99999";
const TEST_SECRET_SYMLINK: &str = "AGNES_TEST_SECRET_SYMLINK_pass123";

#[test]
fn test_bypass_attempt_001_path_traversal() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let allowed_dir = temp_dir.path().join("allowed");
    let forbidden_dir = temp_dir.path().join("forbidden");
    fs::create_dir_all(&allowed_dir).expect("Failed to create allowed dir");
    fs::create_dir_all(&forbidden_dir).expect("Failed to create forbidden dir");

    let forbidden_secret_file = forbidden_dir.join("secret.txt");
    fs::write(&forbidden_secret_file, TEST_SECRET_TRAVERSAL).expect("Failed to write secret");

    let allowed_pattern = format!("{}/*", allowed_dir.to_str().unwrap());
    harness.fs_enforcer.register_sandbox_root(&allowed_dir);

    // Policy allows reading from allowed_dir
    let policy = Policy::new("policy-fs-boundary", "Filesystem Sandbox Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox-only".to_string(),
            description: "Allow agent-001 to read allowed directory".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_pattern,
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    // Adversarial Attempt: Path traversal payload attempting to escape allowed directory
    let traversal_payload = format!("{}/../forbidden/secret.txt", allowed_dir.to_str().unwrap());

    let request = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: traversal_payload.clone(),
        },
    ).with_test_id("BYPASS-002-TRAVERSAL");

    let report = harness.execute_request(request);

    println!("\n=== BYPASS ATTEMPT 1: PATH TRAVERSAL REPORT ===");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // HARDENING VERIFICATION:
    // 1. Observed result must NOT be AccessSuccess
    assert_ne!(
        report.observed_result,
        ObservedResult::AccessSuccess,
        "SECURITY FAILURE: Path traversal succeeded in accessing forbidden target!"
    );
    // 2. Secret marker must never be leaked
    assert!(
        !report.logs.contains(TEST_SECRET_TRAVERSAL),
        "SECURITY FAILURE: Secret marker leaked in logs!"
    );
    // 3. Must be blocked by firewall (either policy deny or kernel resolve beneath block)
    assert_eq!(
        report.observed_result,
        ObservedResult::BlockedByFirewall,
        "Security boundary must physically block traversal"
    );
}

#[test]
fn test_bypass_attempt_002_symlink_escape() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let allowed_dir = temp_dir.path().join("allowed");
    let forbidden_dir = temp_dir.path().join("forbidden");
    fs::create_dir_all(&allowed_dir).expect("Failed to create allowed dir");
    fs::create_dir_all(&forbidden_dir).expect("Failed to create forbidden dir");

    let forbidden_secret_file = forbidden_dir.join("secret.txt");
    fs::write(&forbidden_secret_file, TEST_SECRET_SYMLINK).expect("Failed to write secret");

    // Create a symlink inside allowed_dir pointing to forbidden file
    let symlink_in_allowed = allowed_dir.join("link_to_secret.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&forbidden_secret_file, &symlink_in_allowed).expect("Failed to create symlink");

    let allowed_pattern = format!("{}/*", allowed_dir.to_str().unwrap());
    harness.fs_enforcer.register_sandbox_root(&allowed_dir);

    let policy = Policy::new("policy-fs-boundary", "Filesystem Sandbox Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox-only".to_string(),
            description: "Allow agent-001 to read allowed directory".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_pattern,
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    let request = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: symlink_in_allowed.to_str().unwrap().to_string(),
        },
    ).with_test_id("BYPASS-002-SYMLINK");

    let report = harness.execute_request(request);

    println!("\n=== BYPASS ATTEMPT 2: SYMLINK ESCAPE REPORT ===");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // HARDENING VERIFICATION:
    // 1. Observed result must NOT be AccessSuccess
    assert_ne!(
        report.observed_result,
        ObservedResult::AccessSuccess,
        "SECURITY FAILURE: Symlink escape succeeded in accessing forbidden target!"
    );
    // 2. Secret marker must never be leaked
    assert!(
        !report.logs.contains(TEST_SECRET_SYMLINK),
        "SECURITY FAILURE: Symlink secret marker leaked in logs!"
    );
    // 3. Must be blocked by firewall
    assert_eq!(
        report.observed_result,
        ObservedResult::BlockedByFirewall,
        "Security boundary must physically block symlink escape"
    );
}

// REGRESSION: A symlink inside an allowed directory that points into a denied directory
// must be evaluated against the denied directory's policy and rejected (Decision::Deny).
#[test]
fn test_regression_symlink_inside_allowed_pointing_to_denied_evaluated_against_denied_policy_and_rejected() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let sandbox_root = temp_dir.path();
    let allowed_dir = sandbox_root.join("allowed_zone");
    let denied_dir = sandbox_root.join("denied_zone");
    fs::create_dir_all(&allowed_dir).expect("Failed to create allowed dir");
    fs::create_dir_all(&denied_dir).expect("Failed to create denied dir");

    let denied_file = denied_dir.join("protected_record.txt");
    fs::write(&denied_file, "RESTRICTED_DATA_INTERNAL_USE_ONLY").expect("Failed to write denied file");

    let symlink_in_allowed = allowed_dir.join("relative_leak_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../denied_zone/protected_record.txt", &symlink_in_allowed)
        .expect("Failed to create relative symlink");

    // Both directories are under the enclosing root
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Register Policy with:
    // 1. Explicit DENY rule on denied_zone/* (Priority 100)
    // 2. Explicit ALLOW rule on allowed_zone/* (Priority 10)
    let policy = Policy::new("policy-symlink-bypass-prevention", "Symlink Bypass Test Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-deny-sensitive-dir".to_string(),
            description: "Explicitly deny all access to denied_zone".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", denied_dir.display()),
            priority: 100,
        })
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox-dir".to_string(),
            description: "Allow reading inside allowed_zone".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", allowed_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    // Action request targets the symlink located inside allowed directory
    let request = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: symlink_in_allowed.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-SYMLINK-BYPASS-001");

    let report = harness.execute_request(request);

    println!("\n=== REGRESSION REPORT: SYMLINK TO DENIED DIRECTORY ===");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // CRITICAL ASSERTIONS:
    // The policy evaluation must resolve the REAL path (following the symlink to denied_zone)
    // before the policy decision is made, rejecting the access via rule-deny-sensitive-dir.
    assert_eq!(
        report.decision,
        Decision::Deny,
        "SECURITY BYPASS DETECTED: Symlink pointing into denied directory was not rejected by policy!"
    );
    assert_eq!(
        report.policy,
        "policy-symlink-bypass-prevention",
        "Must match the policy containing the deny rule"
    );
    assert_eq!(
        report.enforcement,
        EnforcementAction::BlockRequest,
        "Enforcement must block request upon policy denial"
    );
    assert_eq!(
        report.observed_result,
        ObservedResult::BlockedByFirewall,
        "Observed result must be BlockedByFirewall"
    );
    assert!(
        !report.logs.contains("RESTRICTED_DATA_INTERNAL_USE_ONLY"),
        "Protected data must never be leaked in logs"
    );
}
