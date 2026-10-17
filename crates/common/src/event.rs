use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::action::{ActionRequest, ActionType};
use crate::decision::Decision;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementAction {
    PermitExecution,
    BlockRequest,
    DropConnection,
    TerminateProcess,
    SimulatePermissionDenied,
    KernelResolveBeneathBlock,
    CanonicalBoundaryViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedResult {
    AccessSuccess,
    AccessFailed,
    BlockedByFirewall,
    TargetUnreachable,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub correlation_id: Uuid,
    pub test_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub action_type: ActionType,
    #[serde(default)]
    pub raw_resource: String,
    pub target_resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_resource: Option<String>,
    #[serde(alias = "matched_policy_id")]
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "matched_rule_id")]
    pub rule_id: Option<String>,
    pub decision: Decision,
    pub reason: String,
    pub enforcement_action: EnforcementAction,
    pub observed_result: ObservedResult,
    pub details: serde_json::Value,
}

impl SecurityEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ActionRequest,
        policy_id: impl Into<String>,
        rule_id: Option<String>,
        decision: Decision,
        reason: impl Into<String>,
        resolved_resource: Option<String>,
        enforcement_action: EnforcementAction,
        observed_result: ObservedResult,
        details: serde_json::Value,
    ) -> Self {
        Self {
            correlation_id: request.correlation_id,
            test_id: request.test_id.clone(),
            timestamp: Utc::now(),
            agent_id: request.agent_id.clone(),
            action_type: request.action_type,
            raw_resource: request.target_resource.clone(),
            target_resource: request.target_resource.clone(),
            resolved_resource,
            policy_id: policy_id.into(),
            rule_id,
            decision,
            reason: reason.into(),
            enforcement_action,
            observed_result,
            details,
        }
    }
}
