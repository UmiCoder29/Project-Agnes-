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

use std::path::{Component, Path};
use crate::path::{resolve_real_path, resolve_request_target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleSpecificity {
    /// 1. Exact matches (no wildcards) are strictly more specific than wildcard/prefix patterns.
    pub is_exact: bool,
    /// 2. Number of directory path components in the matched prefix (e.g. /a/b/c has 3, /a has 1).
    pub component_count: usize,
    /// 3. Character length of the matched prefix for tie-breaking patterns with identical component counts.
    pub prefix_len: usize,
}

/// Resolves a resource pattern to its real canonical location on disk.
/// - Catch-all wildcard "*" is preserved as "*".
/// - Prefix patterns (e.g. "/path/link/*" or "/path/link*") resolve the directory prefix through
///   symlinks via `resolve_real_path`, binding the rule to the real canonical location.
/// - Exact paths are resolved directly via `resolve_real_path`.
/// - Fails closed if the pattern is empty, contains null bytes, or contains unresolvable symlinks/paths.
pub fn resolve_resource_pattern(pattern: &str) -> Result<String, std::io::Error> {
    if pattern.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Empty resource pattern",
        ));
    }

    if pattern == "*" {
        return Ok("*".to_string());
    }

    if pattern.contains('\0') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Null byte in resource pattern",
        ));
    }

    if let Some(prefix) = pattern.strip_suffix("/*") {
        let clean_prefix = prefix.trim_end_matches('/');
        if clean_prefix.is_empty() {
            // Root pattern /*
            return Ok("/*".to_string());
        }
        let resolved = resolve_real_path(clean_prefix)?;
        let s = resolved.to_string_lossy();
        let s_trimmed = s.trim_end_matches('/');
        return Ok(format!("{}/*", s_trimmed));
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.is_empty() {
            return Ok("*".to_string());
        }
        let resolved = resolve_real_path(prefix)?;
        return Ok(format!("{}*", resolved.to_string_lossy()));
    }

    // Exact path
    let resolved = resolve_real_path(pattern)?;
    Ok(resolved.to_string_lossy().to_string())
}

impl PolicyRule {
    /// Computes the specificity of this rule's resource pattern.
    ///
    /// Specificity ranks:
    /// 1. Exact matches (no wildcards) are most specific.
    /// 2. Deeper path prefixes (more normal path components) beat shallower parent directories.
    /// 3. Longer prefix character lengths break ties between same component counts.
    /// 4. Catch-all wildcards ("*") have zero specificity.
    pub fn specificity(&self) -> RuleSpecificity {
        if self.resource_pattern == "*" {
            return RuleSpecificity {
                is_exact: false,
                component_count: 0,
                prefix_len: 0,
            };
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix("/*") {
            let clean_prefix = prefix.trim_end_matches('/');
            let count = Path::new(clean_prefix)
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            return RuleSpecificity {
                is_exact: false,
                component_count: count,
                prefix_len: clean_prefix.len(),
            };
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix('*') {
            let count = Path::new(prefix)
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            return RuleSpecificity {
                is_exact: false,
                component_count: count,
                prefix_len: prefix.len(),
            };
        }

        // Exact match
        let count = Path::new(&self.resource_pattern)
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count();
        RuleSpecificity {
            is_exact: true,
            component_count: count,
            prefix_len: self.resource_pattern.len(),
        }
    }

    /// Resolves this rule's resource pattern to its real canonical filesystem location.
    /// Traversal components and symbolic links in directory prefixes or exact paths are expanded.
    /// Fails closed if the pattern cannot be resolved (e.g. symlink loop, null byte, or invalid path).
    pub fn resolve_pattern(&mut self) -> Result<(), std::io::Error> {
        self.resource_pattern = resolve_resource_pattern(&self.resource_pattern)?;
        Ok(())
    }

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
        // 1. Agent match: empty pattern matches nothing (fail-closed)
        if self.agent_pattern.is_empty() {
            return false;
        }
        if self.agent_pattern != "*" && self.agent_pattern != request.agent_id {
            return false;
        }

        // 2. Action type match: empty action_types list matches nothing (fail-closed)
        if self.action_types.is_empty() || !self.action_types.contains(&request.action_type) {
            return false;
        }

        // Reject control characters / null bytes in target
        if target.contains('\0') {
            return false;
        }

        // 3. Resource pattern match: empty pattern matches nothing (fail-closed)
        if self.resource_pattern.is_empty() {
            return false;
        }

        // 4. Resource pattern match (target is already resolved exactly once by PolicyEngine::evaluate)
        self.matches_resource(target)
    }

    pub fn matches_resource(&self, target: &str) -> bool {
        if self.resource_pattern.is_empty() {
            return false;
        }

        if self.resource_pattern == "*" {
            return true;
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix("/*") {
            let prefix = prefix.trim_end_matches('/');
            if let Some(rest) = target.strip_prefix(prefix) {
                if rest.is_empty() || rest.starts_with('/') {
                    return true;
                }
            }
            return false;
        }

        if let Some(prefix) = self.resource_pattern.strip_suffix('*') {
            if target.starts_with(prefix) {
                return true;
            }
            return false;
        }

        // Exact match
        if self.resource_pattern == target {
            return true;
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

    /// Parses a Policy from a JSON configuration string.
    /// Fails safely if the JSON is malformed, missing required fields, or has invalid types.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

