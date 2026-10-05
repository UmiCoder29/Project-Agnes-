use blackwall_common::{
    ActionPayload, ActionRequest, Decision, EnforcementAction, ObservedResult, PolicyDecisionResponse,
};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub enforcement_action: EnforcementAction,
    pub observed_result: ObservedResult,
    pub output: Option<String>,
    pub error_message: Option<String>,
}

pub struct FilesystemEnforcer;

impl FilesystemEnforcer {
    pub fn new() -> Self {
        Self
    }

    /// Enforces file read action according to the deterministic policy decision.
    ///
    /// If decision == DENY:
    ///   Enforcement blocks access completely. No read handle is granted.
    ///   The access attempt is verified to fail.
    ///
    /// If decision == ALLOW:
    ///   Access is permitted through the security gate.
    ///   The actual target file read is performed and its success/failure is recorded.
    pub fn enforce_read(&self, request: &ActionRequest, decision_resp: &PolicyDecisionResponse) -> EnforcementResult {
        let path_str = match &request.payload {
            ActionPayload::ReadFile { path } => path,
            _ => {
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::Error,
                    output: None,
                    error_message: Some("Invalid payload for file read".to_string()),
                }
            }
        };

        match decision_resp.decision {
            Decision::Deny => {
                info!(
                    target = %path_str,
                    agent = %request.agent_id,
                    rule = ?decision_resp.reason.rule_id,
                    "ENFORCEMENT: Blocking file read access"
                );

                // Actively refuse to grant access / block file descriptor
                EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some(format!(
                        "EACCES: Black Wall denied access to '{}'. Policy: {}",
                        path_str, decision_resp.matched_policy_id
                    )),
                }
            }
            Decision::Allow => {
                info!(
                    target = %path_str,
                    agent = %request.agent_id,
                    rule = ?decision_resp.reason.rule_id,
                    "ENFORCEMENT: Permitting file read access"
                );

                let target_path = Path::new(path_str);
                match fs::read_to_string(target_path) {
                    Ok(content) => EnforcementResult {
                        enforcement_action: EnforcementAction::PermitExecution,
                        observed_result: ObservedResult::AccessSuccess,
                        output: Some(content),
                        error_message: None,
                    },
                    Err(err) => {
                        warn!(target = %path_str, error = %err, "File read permitted but target OS error occurred");
                        EnforcementResult {
                            enforcement_action: EnforcementAction::PermitExecution,
                            observed_result: ObservedResult::AccessFailed,
                            output: None,
                            error_message: Some(format!("OS Error reading '{}': {}", path_str, err)),
                        }
                    }
                }
            }
        }
    }
}
