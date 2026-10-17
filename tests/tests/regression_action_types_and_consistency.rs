use agnes_common::{ActionPayload, ActionRequest, ActionType, Decision};
use agnes_policy::{Policy, PolicyEngine, PolicyLoadError, PolicyRule};

fn make_payload_for_action(action: ActionType, temp_path: &str) -> ActionPayload {
    match action {
        ActionType::ReadFile => ActionPayload::ReadFile {
            path: temp_path.to_string(),
        },
        ActionType::WriteFile => ActionPayload::WriteFile {
            path: temp_path.to_string(),
            content: "test-data".to_string(),
        },
        ActionType::ExecuteProcess => ActionPayload::ExecuteProcess {
            command: "/bin/echo hello".to_string(),
            args: vec!["hello".to_string()],
        },
        ActionType::CreateProcess => ActionPayload::CreateProcess {
            executable: "/bin/sh".to_string(),
            args: vec![],
        },
        ActionType::NetworkConnect => ActionPayload::NetworkConnect {
            destination: "127.0.0.1".to_string(),
            port: 8080,
        },
        ActionType::DnsLookup => ActionPayload::DnsLookup {
            hostname: "example.com".to_string(),
        },
        ActionType::HttpRequest => ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/api".to_string(),
            headers: None,
            body: None,
        },
        ActionType::CallTool => ActionPayload::CallTool {
            tool_name: "calculator".to_string(),
            arguments: serde_json::json!({}),
        },
        ActionType::CallMcpTool => ActionPayload::CallMcpTool {
            server_name: "github".to_string(),
            tool_name: "create_issue".to_string(),
            arguments: serde_json::json!({}),
        },
        ActionType::ReadSecret => ActionPayload::ReadSecret {
            secret_id: "db-password".to_string(),
        },
        ActionType::SendData => ActionPayload::SendData {
            destination: "metrics-collector".to_string(),
            payload_preview: "telemetry".to_string(),
        },
        ActionType::ModifyPolicy => ActionPayload::ModifyPolicy {
            policy_id: "policy-001".to_string(),
            action: "append".to_string(),
        },
        ActionType::RequestCredential => ActionPayload::RequestCredential {
            scope: "read:all".to_string(),
        },
        ActionType::CommunicateWithAgent => ActionPayload::CommunicateWithAgent {
            target_agent: "agent-002".to_string(),
            message: "ping".to_string(),
        },
    }
}

// -----------------------------------------------------------------------------
// 1. Request Consistency: Action Type and Target Resource Mismatches
// -----------------------------------------------------------------------------

#[test]
fn test_request_consistency_action_type_mismatch_fails_on_old_code() {
    let engine = PolicyEngine::new();
    let temp = tempfile::tempdir().unwrap();
    let allowed_file = temp.path().join("allowed.txt");
    std::fs::write(&allowed_file, "ALLOWED").unwrap();
    let canonical = allowed_file.canonicalize().unwrap();
    let path_str = canonical.to_str().unwrap().to_string();

    let policy = Policy::new("p-allow", "Allow read", 1).with_rule(PolicyRule {
        id: "r1".to_string(),
        description: "Allow allowed file".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: path_str.clone(),
        priority: 10,
    });
    engine.add_policy(policy).unwrap();

    // Mismatch 1: action_type header is READ_FILE and target_resource is allowed file,
    // but payload is HTTP_REQUEST to https://evil.com
    let req_mismatched_action = ActionRequest {
        correlation_id: uuid::Uuid::new_v4(),
        test_id: Some("MISMATCH-ACTION".to_string()),
        timestamp: chrono::Utc::now(),
        agent_id: "agent-001".to_string(),
        session_id: None,
        action_type: ActionType::ReadFile,
        target_resource: path_str.clone(),
        payload: ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://evil.com".to_string(),
            headers: None,
            body: None,
        },
    };

    let decision = engine.evaluate(&req_mismatched_action);
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "Mismatched action_type vs payload MUST be Denied"
    );
    assert_eq!(
        decision.matched_policy_id,
        "fail-closed-request-mismatch",
        "Reason MUST be fail-closed-request-mismatch"
    );
}

#[test]
fn test_request_consistency_target_resource_mismatch_fails_on_old_code() {
    let engine = PolicyEngine::new();
    let temp = tempfile::tempdir().unwrap();
    let allowed_file = temp.path().join("allowed.txt");
    std::fs::write(&allowed_file, "ALLOWED").unwrap();
    let canonical = allowed_file.canonicalize().unwrap();
    let path_str = canonical.to_str().unwrap().to_string();

    let policy = Policy::new("p-allow", "Allow read", 1).with_rule(PolicyRule {
        id: "r1".to_string(),
        description: "Allow allowed file".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: path_str.clone(),
        priority: 10,
    });
    engine.add_policy(policy).unwrap();

    // Mismatch 2: target_resource header is allowed file, but payload has different target path "/etc/shadow"
    let req_mismatched_target = ActionRequest {
        correlation_id: uuid::Uuid::new_v4(),
        test_id: Some("MISMATCH-TARGET".to_string()),
        timestamp: chrono::Utc::now(),
        agent_id: "agent-001".to_string(),
        session_id: None,
        action_type: ActionType::ReadFile,
        target_resource: path_str,
        payload: ActionPayload::ReadFile {
            path: "/etc/shadow".to_string(),
        },
    };

    let decision = engine.evaluate(&req_mismatched_target);
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "Mismatched target_resource vs payload MUST be Denied"
    );
    assert_eq!(
        decision.matched_policy_id,
        "fail-closed-request-mismatch",
        "Reason MUST be fail-closed-request-mismatch"
    );
}

#[test]
fn test_request_consistency_covers_every_payload_variant() {
    let engine = PolicyEngine::new();
    let temp = tempfile::tempdir().unwrap();
    let dummy_file = temp.path().join("dummy.txt");
    std::fs::write(&dummy_file, "DUMMY").unwrap();
    let path_str = dummy_file.canonicalize().unwrap().to_str().unwrap().to_string();

    for &action in &ActionType::ALL {
        let payload = make_payload_for_action(action, &path_str);
        let valid_target = payload.target_resource();
        let expected_action = payload.action_type();
        assert_eq!(expected_action, action);

        // 1. Action type header mismatch
        let different_action = if action == ActionType::ReadFile {
            ActionType::HttpRequest
        } else {
            ActionType::ReadFile
        };

        let req_mismatched_action = ActionRequest {
            correlation_id: uuid::Uuid::new_v4(),
            test_id: Some(format!("MISMATCH-ACTION-{:?}", action)),
            timestamp: chrono::Utc::now(),
            agent_id: "agent-001".to_string(),
            session_id: None,
            action_type: different_action,
            target_resource: valid_target.clone(),
            payload: payload.clone(),
        };

        let res1 = engine.evaluate(&req_mismatched_action);
        assert_eq!(
            res1.decision,
            Decision::Deny,
            "Action {:?} header mismatch must be Denied",
            action
        );
        assert_eq!(
            res1.matched_policy_id, "fail-closed-request-mismatch",
            "Action {:?} header mismatch reason must be fail-closed-request-mismatch",
            action
        );

        // 2. Target resource header mismatch
        let req_mismatched_target = ActionRequest {
            correlation_id: uuid::Uuid::new_v4(),
            test_id: Some(format!("MISMATCH-TARGET-{:?}", action)),
            timestamp: chrono::Utc::now(),
            agent_id: "agent-001".to_string(),
            session_id: None,
            action_type: action,
            target_resource: format!("{}_TAMPERED", valid_target),
            payload,
        };

        let res2 = engine.evaluate(&req_mismatched_target);
        assert_eq!(
            res2.decision,
            Decision::Deny,
            "Action {:?} target mismatch must be Denied",
            action
        );
        assert_eq!(
            res2.matched_policy_id, "fail-closed-request-mismatch",
            "Action {:?} target mismatch reason must be fail-closed-request-mismatch",
            action
        );
    }
}

// -----------------------------------------------------------------------------
// 2. Unknown and Unmatched Action Types: Default Deny across all 14 variants
// -----------------------------------------------------------------------------

#[test]
fn test_all_14_action_types_default_deny_and_unmatched_different_action() {
    let temp = tempfile::tempdir().unwrap();
    let dummy_file = temp.path().join("dummy.txt");
    std::fs::write(&dummy_file, "DUMMY").unwrap();
    let path_str = dummy_file.canonicalize().unwrap().to_str().unwrap().to_string();

    for &action in &ActionType::ALL {
        let payload = make_payload_for_action(action, &path_str);
        let request = ActionRequest::new("agent-001", payload);

        // Case A: Engine has NO policies loaded -> default Deny
        let engine_empty = PolicyEngine::new();
        let eval_empty = engine_empty.evaluate(&request);
        assert_eq!(
            eval_empty.decision,
            Decision::Deny,
            "Action {:?} with no policies must be Denied",
            action
        );
        assert_eq!(
            eval_empty.matched_policy_id, "default-fail-closed",
            "Action {:?} with no policies must have reason default-fail-closed",
            action
        );

        // Case B: Engine has an Allow rule for a DIFFERENT action type -> Deny
        let engine_other = PolicyEngine::new();
        let (other_action, other_pattern) = if action == ActionType::ReadFile {
            (ActionType::HttpRequest, "https://allowed.other/*".to_string())
        } else {
            (ActionType::ReadFile, format!("{}/*", temp.path().display()))
        };

        engine_other
            .add_policy(
                Policy::new("p-other", "Allow different action", 1).with_rule(PolicyRule {
                    id: "r-other".to_string(),
                    description: "Allow other action only".to_string(),
                    decision: Decision::Allow,
                    agent_pattern: "*".to_string(),
                    action_types: vec![other_action],
                    resource_pattern: other_pattern,
                    priority: 10,
                }),
            )
            .unwrap();

        let eval_other = engine_other.evaluate(&request);
        assert_eq!(
            eval_other.decision,
            Decision::Deny,
            "Action {:?} with only rule for {:?} must be Denied",
            action, other_action
        );
        assert_eq!(
            eval_other.matched_policy_id, "default-fail-closed",
            "Action {:?} with only rule for {:?} must have reason default-fail-closed",
            action, other_action
        );
    }
}

// -----------------------------------------------------------------------------
// 3. Pattern Kinds: LiteralString vs FilesystemPath
// -----------------------------------------------------------------------------

#[test]
fn test_http_host_allow_allows_only_that_host() {
    let engine = PolicyEngine::new();

    // Allow HttpRequest only to https://api.example.com/*
    let policy = Policy::new("p-http-host", "Allow specific host", 1).with_rule(PolicyRule {
        id: "r-allow-host".to_string(),
        description: "Allow example.com API".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::HttpRequest],
        resource_pattern: "https://api.example.com/*".to_string(),
        priority: 10,
    });
    engine.add_policy(policy).unwrap();

    // Allowed: exact prefix match under host
    let req_ok = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.example.com/v1/users".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_ok).decision, Decision::Allow);

    // Denied: different host
    let req_other_host = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.evil.com/v1/users".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_other_host).decision, Decision::Deny);

    // Denied: host subdomain spoof attempt (https://api.example.com.attacker.com)
    let req_spoof_host = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.example.com.attacker.com/bypass".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_spoof_host).decision, Decision::Deny);
}

#[test]
fn test_specific_deny_beats_allow_all_same_type() {
    let engine = PolicyEngine::new();

    let policy = Policy::new("p-specific-deny", "Allow all except blocked", 1)
        .with_rule(PolicyRule {
            id: "r-allow-all".to_string(),
            description: "Allow all HTTP".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "*".to_string(),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "r-deny-blocked".to_string(),
            description: "Deny specific host".to_string(),
            decision: Decision::Deny,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://blocked.example.com/*".to_string(),
            priority: 10,
        });

    engine.add_policy(policy).unwrap();

    let req_allowed = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://trusted.example.com/data".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_allowed).decision, Decision::Allow);

    let req_blocked = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://blocked.example.com/secret".to_string(),
            headers: None,
            body: None,
        },
    );
    let eval_blocked = engine.evaluate(&req_blocked);
    assert_eq!(
        eval_blocked.decision,
        Decision::Deny,
        "Specific Deny must beat catch-all Allow of the same type"
    );
    assert_eq!(eval_blocked.reason.rule_id.as_deref(), Some("r-deny-blocked"));
}

#[test]
fn test_specific_read_secret_id_allowed_and_different_id_denied() {
    let engine = PolicyEngine::new();

    let policy = Policy::new("p-secret", "Allow specific secret", 1).with_rule(PolicyRule {
        id: "r-secret".to_string(),
        description: "Allow db-password only".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadSecret],
        resource_pattern: "db-password".to_string(),
        priority: 10,
    });
    engine.add_policy(policy).unwrap();

    let req_allowed = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: "db-password".to_string(),
        },
    );
    assert_eq!(engine.evaluate(&req_allowed).decision, Decision::Allow);

    // Exact matching: "db-password-admin" must not match "db-password"
    let req_denied_prefix = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: "db-password-admin".to_string(),
        },
    );
    assert_eq!(engine.evaluate(&req_denied_prefix).decision, Decision::Deny);

    let req_denied_other = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: "api-secret-key".to_string(),
        },
    );
    assert_eq!(engine.evaluate(&req_denied_other).decision, Decision::Deny);
}

#[test]
fn test_policy_mixing_file_and_http_rules_loads_and_evaluates() {
    let engine = PolicyEngine::new();
    let temp = tempfile::tempdir().unwrap();
    let allowed_file = temp.path().join("data.txt");
    std::fs::write(&allowed_file, "DATA").unwrap();
    let canonical = allowed_file.canonicalize().unwrap();
    let path_str = canonical.to_str().unwrap().to_string();

    let policy = Policy::new("p-mixed", "Mixed file and http policy", 1)
        .with_rule(PolicyRule {
            id: "r-file".to_string(),
            description: "Allow file read".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: path_str.clone(),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "r-http".to_string(),
            description: "Allow http API".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://api.service.com/*".to_string(),
            priority: 10,
        });

    // The mixed policy MUST load cleanly and atomically
    assert!(
        engine.add_policy(policy).is_ok(),
        "A policy containing separate file rules and HTTP rules must load successfully"
    );

    // Allowed file read
    let req_file = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: path_str,
        },
    );
    assert_eq!(engine.evaluate(&req_file).decision, Decision::Allow);

    // Allowed HTTP request
    let req_http = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.service.com/v1/metrics".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_http).decision, Decision::Allow);

    // Denied unlisted HTTP request
    let req_unlisted_http = ActionRequest::new(
        "agent-001",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://other.service.com/v1".to_string(),
            headers: None,
            body: None,
        },
    );
    assert_eq!(engine.evaluate(&req_unlisted_http).decision, Decision::Deny);
}

#[test]
fn test_rule_mixing_path_and_non_path_action_types_rejected_at_load() {
    let engine = PolicyEngine::new();

    // A single rule that mixes ReadFile (FilesystemPath) and HttpRequest (LiteralString)
    let mixed_rule_policy = Policy::new("p-invalid-mixed-rule", "Invalid rule", 1).with_rule(PolicyRule {
        id: "r-mixed-types".to_string(),
        description: "Rule mixing path and non-path action types".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile, ActionType::HttpRequest],
        resource_pattern: "*".to_string(),
        priority: 10,
    });

    let result = engine.add_policy(mixed_rule_policy);
    assert!(
        result.is_err(),
        "A rule mixing path and non-path action types must be rejected at load time"
    );

    match result.unwrap_err() {
        PolicyLoadError::InvalidRulePattern { policy_id, rule_id, reason } => {
            assert_eq!(policy_id, "p-invalid-mixed-rule");
            assert_eq!(rule_id, "r-mixed-types");
            assert!(
                reason.contains("mixes filesystem path action types and literal string action types"),
                "Error reason must clearly state mixed pattern kinds, got: {}",
                reason
            );
        }
        err => panic!("Expected InvalidRulePattern error, got: {:?}", err),
    }

    // Verify engine remains empty and fails closed
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/tmp/anything.txt".to_string(),
        },
    );
    assert_eq!(engine.evaluate(&req).decision, Decision::Deny);
}

#[test]
fn test_non_file_request_not_treated_as_relative_path_or_cwd_dependent() {
    let engine = PolicyEngine::new();

    // Policy allows ReadSecret with a hierarchical, non-absolute name "production/keys/api"
    let policy = Policy::new("p-secret-hierarchy", "Allow hierarchical secret", 1).with_rule(PolicyRule {
        id: "r-secret-sub".to_string(),
        description: "Allow production/keys/api".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadSecret],
        resource_pattern: "production/keys/api".to_string(),
        priority: 10,
    });
    engine.add_policy(policy).unwrap();

    let req_secret = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: "production/keys/api".to_string(),
        },
    );

    let eval = engine.evaluate(&req_secret);
    assert_eq!(
        eval.decision,
        Decision::Allow,
        "Non-file action target must NOT be rejected as a relative path"
    );

    // Unmatched secret with slash must default deny, NOT fail with fail-closed-relative-path
    let req_other_secret = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadSecret {
            secret_id: "staging/keys/api".to_string(),
        },
    );
    let eval_other = engine.evaluate(&req_other_secret);
    assert_eq!(eval_other.decision, Decision::Deny);
    assert_eq!(
        eval_other.matched_policy_id, "default-fail-closed",
        "Unmatched non-file action must resolve to default-fail-closed, not fail-closed-relative-path"
    );
}
