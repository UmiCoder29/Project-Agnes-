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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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

// REGRESSION: Nested/chained symlinks (symlink -> symlink -> denied path)
// must be evaluated against the denied path's policy and rejected (Decision::Deny).
#[test]
fn test_regression_nested_chained_symlinks_pointing_to_denied_path_evaluated_against_denied_policy_and_rejected() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let sandbox_root = temp_dir.path();
    let allowed_dir = sandbox_root.join("allowed_zone");
    let denied_dir = sandbox_root.join("denied_zone");
    fs::create_dir_all(&allowed_dir).expect("Failed to create allowed dir");
    fs::create_dir_all(&denied_dir).expect("Failed to create denied dir");

    let denied_file = denied_dir.join("protected_chained_record.txt");
    fs::write(&denied_file, "RESTRICTED_DATA_CHAINED_SYMLINK").expect("Failed to write denied file");

    // Chained symlink: hop 1 points to hop 2, which points to the denied path
    let hop2_symlink = allowed_dir.join("intermediate_hop.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../denied_zone/protected_chained_record.txt", &hop2_symlink)
        .expect("Failed to create intermediate symlink hop");

    let hop1_symlink = allowed_dir.join("chained_entrypoint.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("intermediate_hop.txt", &hop1_symlink)
        .expect("Failed to create chained entrypoint symlink");

    // Both directories are under the enclosing root
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Register Policy with:
    // 1. Explicit DENY rule on denied_zone/* (Priority 100) for ReadFile, WriteFile, ReadSecret
    // 2. Explicit ALLOW rule on allowed_zone/* (Priority 10) for ReadFile, WriteFile, ReadSecret
    let policy = Policy::new("policy-chained-symlink-prevention", "Chained Symlink Bypass Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-deny-sensitive-dir".to_string(),
            description: "Explicitly deny all access to denied_zone".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile, ActionType::WriteFile, ActionType::ReadSecret],
            resource_pattern: format!("{}/*", denied_dir.display()),
            priority: 100,
        })
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox-dir".to_string(),
            description: "Allow access inside allowed_zone".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile, ActionType::WriteFile, ActionType::ReadSecret],
            resource_pattern: format!("{}/*", allowed_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy).unwrap();

    // 1. Verify ReadFile with chained symlink: must resolve to denied file and Deny
    let read_req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: hop1_symlink.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-CHAINED-READ-001");

    let report = harness.execute_request(read_req);
    assert_eq!(
        report.decision,
        Decision::Deny,
        "SECURITY BYPASS: Chained symlink read was not rejected by policy!"
    );
    assert_eq!(
        report.observed_result,
        ObservedResult::BlockedByFirewall,
        "Chained symlink read must be blocked by firewall"
    );
    assert!(
        !report.logs.contains("RESTRICTED_DATA_CHAINED_SYMLINK"),
        "Protected data must never be leaked"
    );

    // 2. Verify ReadSecret with chained symlink path: must resolve to denied file and Deny
    let secret_hop2 = allowed_dir.join("intermediate_secret_hop.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../denied_zone/protected_chained_record.txt", &secret_hop2)
        .expect("Failed to create intermediate secret symlink");

    let secret_hop1 = allowed_dir.join("chained_secret_entrypoint.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("intermediate_secret_hop.txt", &secret_hop1)
        .expect("Failed to create chained secret entrypoint");

    let secret_req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: secret_hop1.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-CHAINED-SECRET-001");

    let secret_decision = harness.policy_engine.evaluate(&secret_req);
    assert_eq!(
        secret_decision.decision,
        Decision::Deny,
        "SECURITY BYPASS: ReadSecret path with chained symlink was not evaluated against denied policy and rejected!"
    );

    // 3. Verify WriteFile stub path with chained symlink: must resolve to denied file and Deny
    let write_hop2 = allowed_dir.join("intermediate_write_hop.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../denied_zone/new_write_target.txt", &write_hop2)
        .expect("Failed to create intermediate write symlink");

    let write_hop1 = allowed_dir.join("chained_write_entrypoint.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("intermediate_write_hop.txt", &write_hop1)
        .expect("Failed to create chained write entrypoint");

    let write_req = ActionRequest::new(
        "agent-001",
        ActionPayload::WriteFile {
            path: write_hop1.to_str().unwrap().to_string(),
            content: "UNAUTHORIZED_WRITE".to_string(),
        },
    ).with_test_id("REGRESSION-CHAINED-WRITE-001");

    let write_decision = harness.policy_engine.evaluate(&write_req);
    assert_eq!(
        write_decision.decision,
        Decision::Deny,
        "SECURITY BYPASS: WriteFile path with chained symlink was not evaluated against denied policy and rejected!"
    );
}

