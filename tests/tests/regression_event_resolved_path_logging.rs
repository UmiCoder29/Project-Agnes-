use agnes_common::{ActionPayload, ActionRequest, ActionType, Decision, SecurityEvent};
use agnes_policy::{Policy, PolicyRule};
use agnes_tests::SecurityTestHarness;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_security_event_records_resolved_path_for_symlink() {
    use agnes_telemetry::{StructuredJsonLogSink, TelemetrySink};

    let temp_dir = tempdir().unwrap();
    let real_dir = temp_dir.path().join("real_dir");
    let link_dir = temp_dir.path().join("link_dir");
    fs::create_dir_all(&real_dir).unwrap();
    fs::create_dir_all(&link_dir).unwrap();

    let real_file = real_dir.join("actual_target.txt");
    fs::write(&real_file, "CONFIDENTIAL_PAYLOAD").unwrap();
    let canonical_real_file = real_file.canonicalize().unwrap();

    let symlink_file = link_dir.join("symlink_pointer.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&real_dir);

    // Policy permits reading from the real directory
    let policy = Policy::new("policy-files", "Filesystem Policy", 1).with_rule(PolicyRule {
        id: "rule-allow-real".to_string(),
        description: "Allow real dir".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", real_dir.canonicalize().unwrap().display()),
        priority: 10,
    });
    harness.policy_engine.add_policy(policy).unwrap();

    let symlink_str = symlink_file.to_string_lossy().to_string();
    let req = ActionRequest::new(
        "agent-007",
        ActionPayload::ReadFile {
            path: symlink_str.clone(),
        },
    );

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Allow);

    // Retrieve the emitted security event from the state engine
    let events = harness.state_engine.get_all_events();
    assert_eq!(events.len(), 1, "Exactly one SecurityEvent should be emitted");
    let event: &SecurityEvent = &events[0];

    let canonical_str = canonical_real_file.to_string_lossy().to_string();

    // 1. Direct typed struct fields: must record resolved path, raw path, rule_id, policy_id, action, decision
    assert_eq!(event.resolved_resource.as_deref(), Some(canonical_str.as_str()));
    assert_ne!(event.resolved_resource.as_deref(), Some(symlink_str.as_str()));
    assert_eq!(event.raw_resource, symlink_str);
    assert_eq!(event.rule_id.as_deref(), Some("rule-allow-real"));
    assert_eq!(event.policy_id, "policy-files");
    assert_eq!(event.action_type, ActionType::ReadFile);
    assert_eq!(event.decision, Decision::Allow);

    // 2. Structured log serialization: must output valid JSON containing resolved_resource, raw_resource, rule_id
    let serialized = serde_json::to_string(event).unwrap();
    assert!(
        serialized.contains(&format!("\"resolved_resource\":\"{}\"", canonical_str)),
        "Serialized event must contain resolved_resource"
    );
    assert!(
        serialized.contains(&format!("\"raw_resource\":\"{}\"", symlink_str)),
        "Serialized event must contain raw_resource"
    );
    assert!(
        serialized.contains("\"rule_id\":\"rule-allow-real\""),
        "Serialized event must contain rule_id"
    );
    assert!(
        serialized.contains("\"action_type\":\"READ_FILE\""),
        "Serialized event must contain action_type"
    );
    assert!(
        serialized.contains("\"decision\":\"ALLOW\""),
        "Serialized event must contain decision"
    );

    // 3. StructuredJsonLogSink must accept the event without error
    let log_sink = StructuredJsonLogSink;
    assert!(log_sink.record_event(event).await.is_ok());

    // 4. Inspect the deserialized JSON Value representation
    let event_json = serde_json::to_value(event).unwrap();
    assert_eq!(
        event_json["resolved_resource"],
        canonical_str,
        "Security event must record the post-canonicalization resolved path that was actually evaluated"
    );
    assert_ne!(
        event_json["resolved_resource"],
        symlink_str,
        "Resolved resource must not be the raw requested symlink path"
    );
    assert_eq!(event_json["raw_resource"], symlink_str);
    assert_eq!(event_json["rule_id"], "rule-allow-real");
    assert_eq!(event_json["policy_id"], "policy-files");
    assert_eq!(event_json["action_type"], "READ_FILE");
    assert_eq!(event_json["decision"], "ALLOW");
}

#[test]
fn test_security_event_records_rule_id_and_none_resolved_for_non_path_action() {
    let harness = SecurityTestHarness::new();

    // Policy permits HttpRequest to internal endpoint
    let policy = Policy::new("policy-network", "Network Policy", 1).with_rule(PolicyRule {
        id: "rule-allow-http".to_string(),
        description: "Allow internal HTTP".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::HttpRequest],
        resource_pattern: "https://api.internal.corp/*".to_string(),
        priority: 10,
    });
    harness.policy_engine.add_policy(policy).unwrap();

    let target_url = "https://api.internal.corp/v1/status".to_string();
    let req = ActionRequest::new(
        "agent-007",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: target_url.clone(),
            headers: None,
            body: None,
        },
    );

    let decision_resp = harness.policy_engine.evaluate(&req);
    assert_eq!(decision_resp.decision, Decision::Allow);

    let event = SecurityEvent::new(
        &req,
        &decision_resp.matched_policy_id,
        decision_resp.reason.rule_id.clone(),
        decision_resp.decision,
        &decision_resp.reason.explanation,
        decision_resp.resolved_resource.clone(),
        agnes_common::EnforcementAction::PermitExecution,
        agnes_common::ObservedResult::AccessSuccess,
        serde_json::json!({ "rule_id": decision_resp.reason.rule_id }),
    );

    // Non-path action: resolved_resource is None (no path resolution), raw_resource is target URL
    assert_eq!(event.resolved_resource, None);
    assert_eq!(event.raw_resource, target_url);
    assert_eq!(event.rule_id.as_deref(), Some("rule-allow-http"));
    assert_eq!(event.policy_id, "policy-network");
    assert_eq!(event.action_type, ActionType::HttpRequest);
    assert_eq!(event.decision, Decision::Allow);

    let event_json = serde_json::to_value(&event).unwrap();
    assert!(event_json.get("resolved_resource").is_none() || event_json["resolved_resource"].is_null());
    assert_eq!(event_json["raw_resource"], target_url);
    assert_eq!(event_json["rule_id"], "rule-allow-http");
}

#[test]
fn test_security_event_denied_before_resolution_relative_path() {
    let harness = SecurityTestHarness::new();
    let req = ActionRequest::new(
        "agent-007",
        ActionPayload::ReadFile {
            path: "relative/path/to/secret.txt".to_string(),
        },
    );

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);

    let events = harness.state_engine.get_all_events();
    assert_eq!(events.len(), 1);
    let event_json = serde_json::to_value(&events[0]).unwrap();

    // Denied before resolution: must NOT show an evaluated path
    assert!(
        event_json.get("resolved_resource").is_none() || event_json["resolved_resource"].is_null(),
        "Resolved resource must be null/absent for requests denied before resolution"
    );

    // Must say why it was denied
    assert_eq!(event_json["policy_id"], "fail-closed-relative-path");
    assert_eq!(event_json["decision"], "DENY");
    let reason = event_json["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("Relative path rejected"),
        "Event reason must explain that the relative path was rejected: got '{}'",
        reason
    );
}

#[test]
fn test_security_event_denied_before_resolution_request_mismatch() {
    let harness = SecurityTestHarness::new();
    let mut req = ActionRequest::new(
        "agent-007",
        ActionPayload::ReadFile {
            path: "/tmp/authorized.txt".to_string(),
        },
    );
    // Tamper with header target to mismatch payload target
    req.target_resource = "/tmp/tampered_header.txt".to_string();

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);

    let events = harness.state_engine.get_all_events();
    assert_eq!(events.len(), 1);
    let event_json = serde_json::to_value(&events[0]).unwrap();

    assert!(
        event_json.get("resolved_resource").is_none() || event_json["resolved_resource"].is_null(),
        "Resolved resource must be null/absent when request mismatch denies before resolution"
    );
    assert_eq!(event_json["policy_id"], "fail-closed-request-mismatch");
    assert_eq!(event_json["decision"], "DENY");
    let reason = event_json["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("Request mismatch"),
        "Event reason must explain request mismatch: got '{}'",
        reason
    );
}

#[test]
fn test_security_event_denied_before_resolution_symlink_loop() {
    let temp_dir = tempdir().unwrap();
    let loop_a = temp_dir.path().join("loop_a");
    let loop_b = temp_dir.path().join("loop_b");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
        std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();
    }

    let harness = SecurityTestHarness::new();
    let req = ActionRequest::new(
        "agent-007",
        ActionPayload::ReadFile {
            path: loop_a.to_string_lossy().to_string(),
        },
    );

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);

    let events = harness.state_engine.get_all_events();
    assert_eq!(events.len(), 1);
    let event_json = serde_json::to_value(&events[0]).unwrap();

    assert!(
        event_json.get("resolved_resource").is_none() || event_json["resolved_resource"].is_null(),
        "Resolved resource must be null/absent when symlink loop fails resolution"
    );
    assert_eq!(event_json["policy_id"], "fail-closed-path-resolution");
    assert_eq!(event_json["decision"], "DENY");
    let reason = event_json["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("Path resolution failed"),
        "Event reason must explain path resolution failure: got '{}'",
        reason
    );
}
