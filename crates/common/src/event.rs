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
    pub target_resource: String,
    pub policy_id: String,
    pub decision: Decision,
    pub reason: String,
    pub enforcement_action: EnforcementAction,
    pub observed_result: ObservedResult,
    pub details: serde_json::Value,
}

impl SecurityEvent {
    pub fn new(
        request: &ActionRequest,
        policy_id: impl Into<String>,
        decision: Decision,
        reason: impl Into<String>,
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
            target_resource: request.target_resource.clone(),
            policy_id: policy_id.into(),
            decision,
            reason: reason.into(),
            enforcement_action,
            observed_result,
            details,
        }
    }
}
