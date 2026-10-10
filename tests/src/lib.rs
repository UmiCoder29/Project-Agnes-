use agnes_common::{
    ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult, SecurityEvent,
};
use agnes_enforcement::FilesystemEnforcer;
use agnes_policy::PolicyEngine;
use agnes_state::StateEngine;
use agnes_telemetry::InMemoryTelemetrySink;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestExecutionReport {
    pub test_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent: String,
    pub action: ActionType,
    pub resource: String,
    pub policy: String,
    pub decision: Decision,
    pub enforcement: EnforcementAction,
    pub observed_result: ObservedResult,
    pub logs: String,
    pub correlation_id: uuid::Uuid,
}

pub struct SecurityTestHarness {
    pub policy_engine: PolicyEngine,
    pub state_engine: StateEngine,
    pub fs_enforcer: FilesystemEnforcer,
    pub telemetry: InMemoryTelemetrySink,
}

impl SecurityTestHarness {
    pub fn new() -> Self {
        Self {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            telemetry: InMemoryTelemetrySink::new(),
        }
    }

    pub fn execute_request(&self, request: ActionRequest) -> TestExecutionReport {
        // 1. Policy Decision
        let decision_resp = self.policy_engine.evaluate(&request);

        // 2. Enforcement
        let enforcement_res = match &request.action_type {
            ActionType::ReadFile => self.fs_enforcer.enforce_read(&request, &decision_resp),
            _ => panic!("Unsupported action in v0.1 test harness"),
        };

        // 3. Telemetry Event
        let event = SecurityEvent::new(
            &request,
            &decision_resp.matched_policy_id,
            decision_resp.decision,
            &decision_resp.reason.explanation,
            enforcement_res.enforcement_action,
            enforcement_res.observed_result,
            serde_json::json!({
                "rule_id": decision_resp.reason.rule_id,
                "error": enforcement_res.error_message,
                "output_preview": enforcement_res.output.as_ref().map(|s| s.chars().take(50).collect::<String>()),
            }),
        );

        self.state_engine.record_event(event);

        TestExecutionReport {
            test_id: request.test_id.unwrap_or_else(|| "UNSPECIFIED".to_string()),
            timestamp: chrono::Utc::now(),
            agent: request.agent_id,
            action: request.action_type,
            resource: request.target_resource,
            policy: decision_resp.matched_policy_id,
            decision: decision_resp.decision,
            enforcement: enforcement_res.enforcement_action,
            observed_result: enforcement_res.observed_result,
            logs: format!(
                "Policy evaluated to {:?}. Reason: {}. Enforcement: {:?}. Output: {:?}",
                decision_resp.decision, decision_resp.reason.explanation, enforcement_res.enforcement_action, enforcement_res.output
            ),
            correlation_id: request.correlation_id,
        }
    }
}
