use blackwall_common::{ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult};
use blackwall_policy::{Policy, PolicyRule};
use blackwall_tests::SecurityTestHarness;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_001_allowed_file_read() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let allowed_dir = temp_dir.path().join("allowed");
    fs::create_dir_all(&allowed_dir).expect("Failed to create allowed dir");

    let allowed_file_path = allowed_dir.join("file.txt");
    fs::write(&allowed_file_path, "WORKSPACE_OK: PERMITTED CONTENT").expect("Failed to write test file");

    let allowed_path_str = allowed_file_path.to_str().unwrap().to_string();
    let allowed_pattern = format!("{}/*", allowed_dir.to_str().unwrap());

    // Register Policy
    let policy = Policy::new("policy-fs-001", "Filesystem Access Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-workspace".to_string(),
            description: "Allow agent-001 to read allowed directory".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_pattern,
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    // Build Request
    let request = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: allowed_path_str.clone(),
        },
    ).with_test_id("TEST-001");

    // Execute through Black Wall
    let report = harness.execute_request(request);

    println!("\n=== TEST 001 AUDIT RECORD ===");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // Assertions
    assert_eq!(report.test_id, "TEST-001");
    assert_eq!(report.decision, Decision::Allow, "TEST 001 must produce ALLOW");
    assert_eq!(report.enforcement, EnforcementAction::PermitExecution);
    assert_eq!(report.observed_result, ObservedResult::AccessSuccess, "TEST 001 must succeed in accessing the file");
}

#[test]
fn test_002_forbidden_file_read() {
    let harness = SecurityTestHarness::new();
    let temp_dir = tempdir().expect("Failed to create tempdir");
    let forbidden_dir = temp_dir.path().join("forbidden");
    fs::create_dir_all(&forbidden_dir).expect("Failed to create forbidden dir");

    let forbidden_file_path = forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file_path, "CLASSIFIED_DATA: DO NOT LEAK").expect("Failed to write test file");

    let forbidden_path_str = forbidden_file_path.to_str().unwrap().to_string();

    // Register Policy that only allows /allowed/*; everything else is default DENY
    let policy = Policy::new("policy-fs-strict", "Strict Isolation Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-only-allowed".to_string(),
            description: "Allow reading only from allowed dir".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/nonexistent/allowed/*".to_string(),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    // Build Request to read forbidden file
    let request = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: forbidden_path_str.clone(),
        },
    ).with_test_id("TEST-002");

    // Execute through Black Wall
    let report = harness.execute_request(request);

    println!("\n=== TEST 002 AUDIT RECORD ===");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // Assertions: Must be DENY and observed result must be BLOCKED
    assert_eq!(report.test_id, "TEST-002");
    assert_eq!(report.decision, Decision::Deny, "TEST 002 must produce DENY");
    assert_eq!(report.enforcement, EnforcementAction::BlockRequest);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall, "TEST 002 access must actually fail");
}
