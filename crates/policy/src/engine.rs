use std::sync::RwLock;
use agnes_common::{ActionRequest, ActionType, Decision, DecisionReason, PolicyDecisionResponse};
use chrono::Utc;
use tracing::{debug, info};

use crate::model::{Policy, PolicyRule};
use crate::path::resolve_real_path;

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
        let mut guard = self.policies.write().expect("lock poisoned");
        info!(policy_id = %policy.id, policy_name = %policy.name, "Loaded policy into engine");
        guard.push(policy);
    }

    pub fn clear(&self) {
        let mut guard = self.policies.write().expect("lock poisoned");
        guard.clear();
    }

    /// Evaluates an ActionRequest deterministically.
    /// Default is FAIL-CLOSED (Deny).
    /// Deny takes precedence over Allow at equal priority.
    ///
    /// Resolves the REAL, final path (following all symlinks) before evaluating rules.
    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecisionResponse {
        // 1. Resolve real, final path following all symlinks for filesystem actions.
        let (resolved_target, resolved_resource_opt) = if request.action_type == ActionType::ReadFile
            || request.action_type == ActionType::WriteFile
        {
            match resolve_real_path(&request.target_resource) {
                Ok(path) => {
                    let s = path.to_string_lossy().to_string();
                    (s.clone(), Some(s))
                }
                Err(err) => {
                    debug!(
                        target = %request.target_resource,
                        error = %err,
                        "Path resolution failed for filesystem action: fail-closed DENY"
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
            }
        } else {
            (request.target_resource.clone(), None)
        };

        let guard = self.policies.read().expect("lock poisoned");

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
