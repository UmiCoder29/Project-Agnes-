use std::sync::RwLock;
use agnes_common::{ActionRequest, Decision, DecisionReason, PolicyDecisionResponse};
use chrono::Utc;
use tracing::{debug, info};

use crate::model::{Policy, PolicyRule};
use crate::path::resolve_request_target;

#[derive(Default)]
pub struct PolicyEngine {
    policies: RwLock<Vec<Policy>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
        }
    }

    pub fn add_policy(&self, policy: Policy) {
        let mut guard = match self.policies.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        info!(policy_id = %policy.id, policy_name = %policy.name, "Loaded policy into engine");
        guard.push(policy);
    }

    /// Clears all loaded policies and clears any lock poison flag.
    /// In Rust 1.77+, `RwLock::clear_poison` allows an operator or recovery routine
    /// to explicitly reset the policy engine to an unpoisoned, known-good state.
    pub fn clear(&self) {
        let mut guard = match self.policies.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clear();
        self.policies.clear_poison();
    }

    /// Loads and registers a policy from a JSON configuration string.
    /// Uses Policy::from_json as the single canonical parsing entrypoint.
    /// If parsing fails, the previously loaded policy set is left completely unmodified (atomic).
    pub fn load_policy_from_json(&self, json_str: &str) -> Result<(), serde_json::Error> {
        let policy = Policy::from_json(json_str)?;
        self.add_policy(policy);
        Ok(())
    }

    /// Evaluates an ActionRequest deterministically.
    /// Default is FAIL-CLOSED (Deny).
    /// Deny takes precedence over Allow at equal priority.
    ///
    /// Resolves the REAL, final path (following all symlinks) before evaluating rules.
    /// If evaluation encounters an error, poisoned lock, or internal panic, it strictly
    /// fails closed to Deny.
    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecisionResponse {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.evaluate_internal(request)
        }));

        match result {
            Ok(response) => response,
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Internal panic during policy evaluation".to_string()
                };

                tracing::error!(panic = %msg, "Policy evaluation panicked: FAIL-CLOSED DENY");

                PolicyDecisionResponse {
                    decision: Decision::Deny,
                    reason: DecisionReason {
                        policy_id: "fail-closed-evaluation-panic".to_string(),
                        rule_id: None,
                        explanation: format!("Internal evaluation panic (fail-closed DENY): {}", msg),
                    },
                    matched_policy_id: "fail-closed-evaluation-panic".to_string(),
                    evaluated_at: Utc::now(),
                    resolved_resource: None,
                }
            }
        }
    }

    fn evaluate_internal(&self, request: &ActionRequest) -> PolicyDecisionResponse {
        // 1. Resolve real, final path following all symlinks for all path-bearing actions.
        let (resolved_target, resolved_resource_opt) = match resolve_request_target(request) {
            Ok(Some(path)) => {
                let s = path.to_string_lossy().to_string();
                (s.clone(), Some(s))
            }
            Ok(None) => (request.target_resource.clone(), None),
            Err(err) => {
                debug!(
                    target = %request.target_resource,
                    action = ?request.action_type,
                    error = %err,
                    "Path resolution failed for action target: fail-closed DENY"
                );
                return PolicyDecisionResponse {
                    decision: Decision::Deny,
                    reason: DecisionReason {
                        policy_id: "fail-closed-path-resolution".to_string(),
                        rule_id: None,
                        explanation: format!(
                            "Path resolution failed for '{}': {}",
                            request.target_resource, err
                        ),
                    },
                    matched_policy_id: "fail-closed-path-resolution".to_string(),
                    evaluated_at: Utc::now(),
                    resolved_resource: None,
                };
            }
        };

        let guard = match self.policies.read() {
            Ok(g) => g,
            Err(err) => {
                tracing::error!(error = %err, "PolicyEngine storage lock is poisoned: fail-closed DENY");
                return PolicyDecisionResponse {
                    decision: Decision::Deny,
                    reason: DecisionReason {
                        policy_id: "fail-closed-lock-poisoned".to_string(),
                        rule_id: None,
                        explanation: "Internal error: policy storage lock poisoned (fail-closed DENY)".to_string(),
                    },
                    matched_policy_id: "fail-closed-lock-poisoned".to_string(),
                    evaluated_at: Utc::now(),
                    resolved_resource: None,
                };
            }
        };

        let mut matching_rules: Vec<(&Policy, &PolicyRule)> = Vec::new();

        for policy in guard.iter() {
            for rule in &policy.rules {
                if rule.matches_target(request, &resolved_target) {
                    matching_rules.push((policy, rule));
                }
            }
        }

        if matching_rules.is_empty() {
            debug!(
                agent = %request.agent_id,
                action = ?request.action_type,
                resource = %request.target_resource,
                resolved = %resolved_target,
                "No matching rule found: default FAIL-CLOSED deny"
            );

            return PolicyDecisionResponse {
                decision: Decision::Deny,
                reason: DecisionReason {
                    policy_id: "default-fail-closed".to_string(),
                    rule_id: None,
                    explanation: "Default deny: no matching policy rule explicitly allowed this action"
                        .to_string(),
                },
                matched_policy_id: "default-fail-closed".to_string(),
                evaluated_at: Utc::now(),
                resolved_resource: resolved_resource_opt,
            };
        }

        // Sort rules deterministically:
        // 1. Priority DESC
        // 2. Decision: Deny before Allow (Deny has higher precedence on collision)
        // 3. Rule ID ASC for deterministic tie-break
        matching_rules.sort_by(|(p_a, r_a), (p_b, r_b)| {
            r_b.priority
                .cmp(&r_a.priority)
                .then_with(|| {
                    match (r_a.decision, r_b.decision) {
                        (Decision::Deny, Decision::Allow) => std::cmp::Ordering::Less,
                        (Decision::Allow, Decision::Deny) => std::cmp::Ordering::Greater,
                        _ => std::cmp::Ordering::Equal,
                    }
                })
                .then_with(|| p_a.id.cmp(&p_b.id))
                .then_with(|| r_a.id.cmp(&r_b.id))
        });

        let (chosen_policy, chosen_rule) = match matching_rules.first().copied() {
            Some(pair) => pair,
            None => {
                debug!(
                    target = %resolved_target,
                    action = ?request.action_type,
                    "No matching policy rule found; default deny"
                );
                return PolicyDecisionResponse {
                    decision: Decision::Deny,
                    reason: DecisionReason {
                        policy_id: "default-fail-closed".to_string(),
                        rule_id: None,
                        explanation: "No matching policy rule found; default deny".to_string(),
                    },
                    matched_policy_id: "default-fail-closed".to_string(),
                    evaluated_at: Utc::now(),
                    resolved_resource: resolved_resource_opt,
                };
            }
        };

        debug!(
            agent = %request.agent_id,
            decision = ?chosen_rule.decision,
            policy = %chosen_policy.id,
            rule = %chosen_rule.id,
            resolved = %resolved_target,
            "Policy decision reached"
        );

        PolicyDecisionResponse {
            decision: chosen_rule.decision,
            reason: DecisionReason {
                policy_id: chosen_policy.id.clone(),
                rule_id: Some(chosen_rule.id.clone()),
                explanation: format!(
                    "Rule '{}' in policy '{}' evaluated to {:?}",
                    chosen_rule.id, chosen_policy.id, chosen_rule.decision
                ),
            },
            matched_policy_id: chosen_policy.id.clone(),
            evaluated_at: Utc::now(),
            resolved_resource: resolved_resource_opt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agnes_common::{ActionPayload, ActionType};

    // CASE 1: When a path or action matches zero rules (or empty policy list),
    // evaluation MUST resolve to Deny (default-fail-closed).
    #[test]
    fn test_audit_zero_matching_rules_resolves_to_deny() {
        let engine = PolicyEngine::new();

        // 1a. Completely empty engine
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/nonexistent_file.txt".to_string(),
            },
        );
        let decision = engine.evaluate(&req);
        assert_eq!(
            decision.decision,
            Decision::Deny,
            "Must default to Deny when no policies exist"
        );
        assert_eq!(decision.matched_policy_id, "default-fail-closed");

        // 1b. Policy exists but rules match other agents / resources
        let policy = Policy::new("policy-other", "Other Policy", 1).with_rule(PolicyRule {
            id: "rule-unrelated".to_string(),
            description: "Allows agent-002 only".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-002".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/file.txt".to_string(),
            priority: 10,
        });
        engine.add_policy(policy);

        let decision = engine.evaluate(&req);
        assert_eq!(
            decision.decision,
            Decision::Deny,
            "Must default to Deny when zero rules match the request"
        );
        assert_eq!(decision.matched_policy_id, "default-fail-closed");
    }

    // CASE 2: When policy configuration fails to parse at startup (corrupted syntax,
    // invalid JSON, missing fields, or unrecognized action types), parsing must fail
    // safely with an error (preventing invalid startup), and unpopulated engines must Deny.
    #[test]
    fn test_audit_policy_config_parsing_failure_at_startup() {
        // Invalid JSON syntax
        let malformed_json = r#"{"id": "p1", "name": "bad", rules: [}"#;
        let res: Result<Policy, _> = serde_json::from_str(malformed_json);
        assert!(res.is_err(), "Must reject malformed JSON");

        // Missing required fields
        let missing_fields = r#"{"id": "p1"}"#;
        let res: Result<Policy, _> = serde_json::from_str(missing_fields);
        assert!(res.is_err(), "Must reject policy with missing fields");

        // Invalid action type enum
        let invalid_enum = r#"{
            "id": "p1",
            "name": "bad-enum",
            "version": 1,
            "rules": [{
                "id": "r1",
                "description": "d",
                "decision": "ALLOW",
                "agent_pattern": "*",
                "action_types": ["NON_EXISTENT_ACTION"],
                "resource_pattern": "*",
                "priority": 1
            }]
        }"#;
        let res: Result<Policy, _> = serde_json::from_str(invalid_enum);
        assert!(res.is_err(), "Must reject policy with invalid action type enum");

        // Engine with failed parse must remain empty and evaluate to Deny
        let engine = PolicyEngine::new();
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/canary.txt".to_string(),
            },
        );
        let decision = engine.evaluate(&req);
        assert_eq!(decision.decision, Decision::Deny);
    }

    // CASE 3a: What happens if policy evaluation function itself panics or errors.
    // The policy engine MUST catch the panic/error and fail closed to Deny.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn test_audit_policy_evaluation_panic_resolves_to_deny() {
        let engine = PolicyEngine::new();
        let policy = Policy::new("policy-test", "Test Policy", 1).with_rule(PolicyRule {
            id: "rule-allow".to_string(),
            description: "Allow".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy);

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/panic_trigger.txt".to_string(),
            },
        );

        // Inject panic via resolution hook
        crate::path::set_resolution_hook(|_| {
            panic!("SIMULATED_INTERNAL_EVALUATION_PANIC");
        });

        let decision = engine.evaluate(&req);
        crate::path::clear_resolution_hook();

        assert_eq!(
            decision.decision,
            Decision::Deny,
            "Evaluation must fail closed to Deny when internal evaluation panics"
        );
        assert_eq!(decision.matched_policy_id, "fail-closed-evaluation-panic");
    }

    // CASE 3b: What happens if the internal storage lock is poisoned.
    // The policy engine MUST handle poisoned locks gracefully and fail closed to Deny.
    // When clear() is called, it clears the poison so the operator can recover.
    #[test]
    fn test_audit_policy_lock_poisoning_and_clear_recovery() {
        let engine = std::sync::Arc::new(PolicyEngine::new());
        let policy = Policy::new("p-allow", "Allow policy", 1).with_rule(PolicyRule {
            id: "r-allow".to_string(),
            description: "Allow".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy.clone());

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/file.txt".to_string(),
            },
        );

        let engine_clone = engine.clone();
        // Deliberately poison the lock by panicking on a background thread while holding write lock
        let _ = std::thread::spawn(move || {
            let mut guard = engine_clone.policies.write().unwrap();
            guard.push(Policy::new("p1", "p1", 1));
            panic!("Poisoning write lock");
        }).join();

        // While poisoned, evaluate MUST Deny
        let decision_poisoned = engine.evaluate(&req);
        assert_eq!(
            decision_poisoned.decision,
            Decision::Deny,
            "Must resolve to Deny when storage lock is poisoned"
        );
        assert_eq!(decision_poisoned.matched_policy_id, "fail-closed-lock-poisoned");

        // Operator calls clear() to clear the poison flag and reset policy state
        engine.clear();

        // Re-add known-good policy
        engine.add_policy(policy);

        // Subsequent evaluation succeeds with Allow
        let decision_recovered = engine.evaluate(&req);
        assert_eq!(
            decision_recovered.decision,
            Decision::Allow,
            "Must successfully evaluate after clear() clears poison and reloads policies"
        );
    }

    // CASE 4: Adversarial cases - empty patterns match nothing and resolve to Deny.
    #[test]
    fn test_audit_empty_rule_patterns_do_not_match_and_resolve_to_deny() {
        let engine = PolicyEngine::new();

        // Rule with empty agent_pattern
        let policy_empty_agent = Policy::new("p-empty-agent", "p", 1).with_rule(PolicyRule {
            id: "r1".to_string(),
            description: "empty agent".to_string(),
            decision: Decision::Allow,
            agent_pattern: "".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy_empty_agent);

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/test.txt".to_string(),
            },
        );
        assert_eq!(engine.evaluate(&req).decision, Decision::Deny);

        // Rule with empty action_types
        engine.clear();
        let policy_empty_actions = Policy::new("p-empty-actions", "p", 1).with_rule(PolicyRule {
            id: "r2".to_string(),
            description: "empty actions".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy_empty_actions);
        assert_eq!(engine.evaluate(&req).decision, Decision::Deny);

        // Rule with empty resource_pattern
        engine.clear();
        let policy_empty_resource = Policy::new("p-empty-resource", "p", 1).with_rule(PolicyRule {
            id: "r3".to_string(),
            description: "empty resource".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "".to_string(),
            priority: 10,
        });
        engine.add_policy(policy_empty_resource);
        assert_eq!(engine.evaluate(&req).decision, Decision::Deny);
    }

    // CASE 5: Adversarial cases - unresolvable paths resolve to Deny.
    #[test]
    fn test_audit_unresolvable_paths_resolve_to_deny() {
        let engine = PolicyEngine::new();
        let policy = Policy::new("p-allow-all", "Allow all", 1).with_rule(PolicyRule {
            id: "r-all".to_string(),
            description: "all".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy);

        // Path with null byte
        let req_null = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/null\0byte.txt".to_string(),
            },
        );
        assert_eq!(engine.evaluate(&req_null).decision, Decision::Deny);

        // Path with empty string
        let req_empty = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "".to_string(),
            },
        );
        assert_eq!(engine.evaluate(&req_empty).decision, Decision::Deny);
    }

    // CASE 6: Adversarial cases - malformed request with unknown action type is rejected.
    #[test]
    fn test_audit_malformed_request_unknown_action_type_never_allowed() {
        let engine = PolicyEngine::new();
        let policy = Policy::new("p-allow-all", "Allow all", 1).with_rule(PolicyRule {
            id: "r-all".to_string(),
            description: "all".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile, ActionType::WriteFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });
        engine.add_policy(policy);

        // Malformed request with unknown action type string
        let malformed_req_json = r#"{
            "correlation_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-10-15T12:00:00Z",
            "agent_id": "agent-001",
            "action_type": "UNKNOWN_MALICIOUS_ACTION",
            "payload": {
                "type": "UNKNOWN_ACTION",
                "details": {}
            },
            "target_resource": "/tmp/secret.txt"
        }"#;

        let parse_result = serde_json::from_str::<ActionRequest>(malformed_req_json);
        assert!(parse_result.is_err(), "Malformed request with unknown action type must be rejected at deserialization boundary");
    }

    // CASE 7: Non-atomic config load preserves existing policies if parsing fails.
    #[test]
    fn test_audit_non_atomic_config_load_preserves_existing_policies() {
        let engine = PolicyEngine::new();
        let valid_json = r#"{
            "id": "policy-valid",
            "name": "Valid Policy",
            "version": 1,
            "rules": [{
                "id": "rule-allow-valid",
                "description": "Allow read",
                "decision": "ALLOW",
                "agent_pattern": "*",
                "action_types": ["READ_FILE"],
                "resource_pattern": "*",
                "priority": 10
            }]
        }"#;

        // 1. Successfully load valid policy
        let load_res = engine.load_policy_from_json(valid_json);
        assert!(load_res.is_ok());

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/test.txt".to_string(),
            },
        );
        assert_eq!(engine.evaluate(&req).decision, Decision::Allow);

        // 2. Attempt to load corrupted / invalid JSON
        let invalid_json = r#"{"id": "broken", "rules": [ INVALID_JSON"#;
        let fail_res = engine.load_policy_from_json(invalid_json);
        assert!(fail_res.is_err(), "Invalid JSON must fail load");

        // 3. Previously loaded policy set must remain exactly intact and evaluate to Allow
        let decision_after = engine.evaluate(&req);
        assert_eq!(
            decision_after.decision,
            Decision::Allow,
            "Existing policies must remain active after failed load"
        );
        assert_eq!(decision_after.matched_policy_id, "policy-valid");
    }
}


