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

use std::path::{Component, Path, PathBuf};

pub fn normalize_lexical_path(p: &str) -> String {
    let path = Path::new(p);
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out.to_string_lossy().to_string()
}

impl PolicyRule {
    pub fn matches(&self, request: &ActionRequest) -> bool {
        // 1. Agent match
        if self.agent_pattern != "*" && self.agent_pattern != request.agent_id {
            return false;
        }

        // 2. Action type match
        if !self.action_types.is_empty() && !self.action_types.contains(&request.action_type) {
            return false;
        }

        // Reject control characters / null bytes in target
        if request.target_resource.contains('\0') {
            return false;
        }

        // 3. Resource pattern match with normalization for file paths
        let normalized_target = if request.action_type == ActionType::ReadFile || request.action_type == ActionType::WriteFile {
            normalize_lexical_path(&request.target_resource)
        } else {
            request.target_resource.clone()
        };

        self.matches_resource(&normalized_target)
    }

    fn matches_resource(&self, target: &str) -> bool {
        if self.resource_pattern == "*" {
            return true;
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix("/*") {
            return target.starts_with(prefix) && (target.len() == prefix.len() || target[prefix.len()..].starts_with('/'));
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix('*') {
            return target.starts_with(prefix);
        }

        // Exact match
        self.resource_pattern == target
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
