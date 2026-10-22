use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("Failed to load policy '{policy_id}': rule '{rule_id}' has invalid or unresolvable pattern: {reason}")]
    InvalidRulePattern {
        policy_id: String,
        rule_id: String,
        reason: String,
    },
    #[error("Failed to parse policy JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Policy with ID '{policy_id}' is already loaded")]
    DuplicatePolicyId {
        policy_id: String,
    },
}

impl PolicyLoadError {
    pub fn policy_id(&self) -> Option<&str> {
        match self {
            Self::InvalidRulePattern { policy_id, .. } => Some(policy_id),
            Self::DuplicatePolicyId { policy_id } => Some(policy_id),
            _ => None,
        }
    }

    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::InvalidRulePattern { rule_id, .. } => Some(rule_id),
            _ => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::InvalidRulePattern { reason, .. } => Some(reason),
            Self::DuplicatePolicyId { .. } => Some("Duplicate policy ID"),
            _ => None,
        }
    }
}
