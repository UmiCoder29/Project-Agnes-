use agnes_common::{ActionRequest, ActionType, Decision};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub decision: Decision,
    /// Agent ID match: specific ID, or "*" for all
    pub agent_pattern: String,
    /// Allowed or denied action types. If empty, matches all.
    pub action_types: Vec<ActionType>,
    /// Resource pattern (exact match, prefix with '*', or wildcard)
    pub resource_pattern: String,
    /// Priority: Higher values evaluated first. If equal, DENY takes precedence.
    pub priority: i32,
}

use crate::path::{resolve_real_path, resolve_request_target};

impl PolicyRule {
    pub fn matches(&self, request: &ActionRequest) -> bool {
        let target = match resolve_request_target(request) {
            Ok(Some(path)) => path.to_string_lossy().to_string(),
            Ok(None) => request.target_resource.clone(),
            Err(_) => {
                // Fail-closed: unresolvable or ambiguous path
                return false;
            }
        };

        self.matches_target(request, &target)
    }

    pub fn matches_target(&self, request: &ActionRequest, target: &str) -> bool {
        // 1. Agent match
        if self.agent_pattern != "*" && self.agent_pattern != request.agent_id {
            return false;
        }

        // 2. Action type match
        if !self.action_types.is_empty() && !self.action_types.contains(&request.action_type) {
            return false;
        }

        // Reject control characters / null bytes in target
        if target.contains('\0') {
            return false;
        }

        // 3. Resource pattern match (target is already resolved exactly once by PolicyEngine::evaluate)
        self.matches_resource(target)
    }

    pub fn matches_resource(&self, target: &str) -> bool {
        if self.resource_pattern == "*" {
            return true;
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix("/*") {
            let prefix = prefix.trim_end_matches('/');
            if target.starts_with(prefix) && (target.len() == prefix.len() || target[prefix.len()..].starts_with('/')) {
                return true;
            }
            if let Ok(canon_prefix) = resolve_real_path(prefix) {
                let canon_str = canon_prefix.to_string_lossy();
                let canon_str = canon_str.trim_end_matches('/');
                if target.starts_with(canon_str) && (target.len() == canon_str.len() || target[canon_str.len()..].starts_with('/')) {
                    return true;
                }
            }
            return false;
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix('*') {
            if target.starts_with(prefix) {
                return true;
            }
            if let Ok(canon_prefix) = resolve_real_path(prefix) {
                let canon_str = canon_prefix.to_string_lossy();
                if target.starts_with(canon_str.as_ref()) {
                    return true;
                }
            }
            return false;
        }

        // Exact match
        if self.resource_pattern == target {
            return true;
        }
        if let Ok(canon_pat) = resolve_real_path(&self.resource_pattern) {
            if canon_pat.to_string_lossy() == target {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version,
            rules: Vec::new(),
        }
    }

    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }
}
