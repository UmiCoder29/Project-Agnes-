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

    pub fn clear(&self) {
        let mut guard = match self.policies.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clear();
    }

    /// Loads and registers a policy from a JSON configuration string.
    /// Fails safely on any parsing error, ensuring malformed configurations
    /// never enter the policy engine.
    pub fn load_policy_from_json(&self, json_str: &str) -> Result<(), serde_json::Error> {
        let policy: Policy = serde_json::from_str(json_str)?;
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

        let (chosen_policy, chosen_rule) = matching_rules[0];

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
    #[test]
    fn test_audit_policy_lock_poisoning_resolves_to_deny() {
        let engine = std::sync::Arc::new(PolicyEngine::new());
        let engine_clone = engine.clone();

        // Deliberately poison the lock by panicking on a background thread while holding write lock
        let _ = std::thread::spawn(move || {
            let mut guard = engine_clone.policies.write().unwrap();
            guard.push(Policy::new("p1", "p1", 1));
            panic!("Poisoning write lock");
        }).join();

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/file.txt".to_string(),
            },
        );

        let decision = engine.evaluate(&req);
        assert_eq!(
            decision.decision,
            Decision::Deny,
            "Must resolve to Deny when storage lock is poisoned"
        );
        assert_eq!(decision.matched_policy_id, "fail-closed-lock-poisoned");
    }
}


