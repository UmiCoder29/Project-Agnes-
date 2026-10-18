use agnes_common::{ActionRequest, ActionType, Decision, PatternKind};
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

    /// Returns the pattern kind for this rule based on its action types.
    /// Rules cannot mix filesystem path action types and literal string action types.
    pub fn pattern_kind(&self) -> Result<PatternKind, String> {
        if self.action_types.is_empty() {
            if self.resource_pattern.starts_with('/') {
                return Ok(PatternKind::FilesystemPath);
            }
            return Ok(PatternKind::LiteralString);
        }

        let mut has_fs = false;
        let mut has_lit = false;
        for action in &self.action_types {
            match action.pattern_kind() {
                PatternKind::FilesystemPath => has_fs = true,
                PatternKind::LiteralString => has_lit = true,
            }
        }

        if has_fs && has_lit {
            return Err("Rule mixes filesystem path action types and literal string action types".to_string());
        }

        if has_fs {
            Ok(PatternKind::FilesystemPath)
        } else {
            Ok(PatternKind::LiteralString)
        }
    }

    /// Resolves this rule's resource pattern.
    /// - For FilesystemPath: resolves directory prefixes or exact paths to real canonical locations on disk.
    /// - For LiteralString: validates non-empty and absence of null bytes, without filesystem resolution.
    ///
    /// Fails closed if the pattern cannot be resolved or validated.
    pub fn resolve_pattern(&mut self) -> Result<(), std::io::Error> {
        let kind = self.pattern_kind().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        })?;

        match kind {
            PatternKind::FilesystemPath => {
                self.resource_pattern = resolve_resource_pattern(&self.resource_pattern)?;
            }
            PatternKind::LiteralString => {
                if self.resource_pattern.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Empty resource pattern",
                    ));
                }
                if self.resource_pattern.contains('\0') {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Null byte in resource pattern",
                    ));
                }
            }
        }
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

        let kind = self.pattern_kind().unwrap_or(PatternKind::LiteralString);
        match kind {
            PatternKind::LiteralString => {
                if self.resource_pattern == "*" {
                    return true;
                }
                if let Some(prefix) = self.resource_pattern.strip_suffix('*') {
                    return target.starts_with(prefix);
                }
                self.resource_pattern == target
            }
            PatternKind::FilesystemPath => {
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
                self.resource_pattern == target
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
}

use crate::error::PolicyLoadError;

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

    /// Validates and resolves all rule patterns in this policy atomically.
    /// If ANY rule's pattern fails to resolve (e.g. symlink loop, invalid path, null byte,
    /// leading/trailing whitespace), returns PolicyLoadError naming the policy id, rule id, and reason.
    pub fn validate_and_resolve_patterns(&mut self) -> Result<(), PolicyLoadError> {
        for rule in &mut self.rules {
            if let Err(err) = rule.resolve_pattern() {
                return Err(PolicyLoadError::InvalidRulePattern {
                    policy_id: self.id.clone(),
                    rule_id: rule.id.clone(),
                    reason: err.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Parses a Policy from a JSON configuration string and validates all rule patterns atomically.
    /// Fails safely if the JSON is malformed, missing required fields, or if any rule pattern is invalid.
    pub fn from_json(json_str: &str) -> Result<Self, PolicyLoadError> {
        let mut policy: Policy = serde_json::from_str(json_str)?;
        policy.validate_and_resolve_patterns()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agnes_common::ActionPayload;
    use tempfile::tempdir;

    #[test]
    fn test_resolve_resource_pattern_root_and_prefix_star() {
        // Root pattern /* and multiple leading slashes
        assert_eq!(resolve_resource_pattern("/*").unwrap(), "/*");
        assert_eq!(resolve_resource_pattern("//*").unwrap(), "/*");
        assert_eq!(resolve_resource_pattern("*").unwrap(), "*");

        // Empty pattern and null byte
        assert!(resolve_resource_pattern("").is_err());
        assert!(resolve_resource_pattern("/*\0").is_err());

        // Prefix with * (not preceded by slash)
        let temp = tempdir().unwrap();
        let target_dir = temp.path().join("mydir");
        std::fs::create_dir_all(&target_dir).unwrap();
        let canonical_dir = target_dir.canonicalize().unwrap();

        let pattern_prefix_star = format!("{}*", canonical_dir.display());
        let resolved = resolve_resource_pattern(&pattern_prefix_star).unwrap();
        assert_eq!(resolved, format!("{}*", canonical_dir.display()));

        // Relative path for prefix* fails (must be absolute)
        let bad_prefix_star = "relative/path*";
        assert!(resolve_resource_pattern(bad_prefix_star).is_err());
    }

    #[test]
    fn test_rule_specificity_ordering() {
        let rule_global = PolicyRule {
            id: "r-global".to_string(),
            description: "all".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        };
        assert_eq!(
            rule_global.specificity(),
            RuleSpecificity {
                is_exact: false,
                component_count: 0,
                prefix_len: 0,
            }
        );

        let rule_depth2 = PolicyRule {
            id: "r-depth2".to_string(),
            description: "depth 2".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/dir/*".to_string(),
            priority: 10,
        };
        let spec2 = rule_depth2.specificity();
        assert!(!spec2.is_exact);
        assert_eq!(spec2.component_count, 2);

        let rule_depth3 = PolicyRule {
            id: "r-depth3".to_string(),
            description: "depth 3".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/dir/subdir/*".to_string(),
            priority: 10,
        };
        let spec3 = rule_depth3.specificity();
        assert!(!spec3.is_exact);
        assert_eq!(spec3.component_count, 3);
        assert!(spec3 > spec2, "Deeper component count must rank more specific");

        let rule_prefix_longer = PolicyRule {
            id: "r-longer".to_string(),
            description: "longer".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/longer_name/*".to_string(),
            priority: 10,
        };
        let rule_prefix_shorter = PolicyRule {
            id: "r-shorter".to_string(),
            description: "shorter".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/short/*".to_string(),
            priority: 10,
        };
        assert!(
            rule_prefix_longer.specificity() > rule_prefix_shorter.specificity(),
            "Longer prefix len must break tie between identical component counts"
        );

        let rule_prefix_no_slash = PolicyRule {
            id: "r-no-slash".to_string(),
            description: "no slash".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/dir*".to_string(),
            priority: 10,
        };
        assert_eq!(rule_prefix_no_slash.specificity().component_count, 2);

        let rule_exact = PolicyRule {
            id: "r-exact".to_string(),
            description: "exact".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/dir/file.txt".to_string(),
            priority: 10,
        };
        assert!(rule_exact.specificity().is_exact);
        assert!(rule_exact.specificity() > rule_depth3.specificity());
    }

    #[test]
    fn test_pattern_kind_derivation_from_empty_action_types_and_mixed() {
        // Empty action types with path-starting pattern -> FilesystemPath
        let rule_fs_empty_actions = PolicyRule {
            id: "r1".to_string(),
            description: "d".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![],
            resource_pattern: "/sandbox/file.txt".to_string(),
            priority: 10,
        };
        assert_eq!(
            rule_fs_empty_actions.pattern_kind().unwrap(),
            PatternKind::FilesystemPath
        );

        // Empty action types with non-path pattern -> LiteralString
        let rule_lit_empty_actions = PolicyRule {
            id: "r2".to_string(),
            description: "d".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![],
            resource_pattern: "https://api.example.com".to_string(),
            priority: 10,
        };
        assert_eq!(
            rule_lit_empty_actions.pattern_kind().unwrap(),
            PatternKind::LiteralString
        );

        // Rule mixing ReadFile and HttpRequest -> Err
        let rule_mixed = PolicyRule {
            id: "r3".to_string(),
            description: "mixed".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile, ActionType::HttpRequest],
            resource_pattern: "/sandbox/*".to_string(),
            priority: 10,
        };
        assert!(rule_mixed.pattern_kind().is_err());
    }

    #[test]
    fn test_literal_string_pattern_validation() {
        let mut rule_empty = PolicyRule {
            id: "r-empty".to_string(),
            description: "empty".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "".to_string(),
            priority: 10,
        };
        assert!(rule_empty.resolve_pattern().is_err());

        let mut rule_null = PolicyRule {
            id: "r-null".to_string(),
            description: "null".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://bad\0host".to_string(),
            priority: 10,
        };
        assert!(rule_null.resolve_pattern().is_err());

        let mut rule_valid = PolicyRule {
            id: "r-valid".to_string(),
            description: "valid".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://trusted.internal/*".to_string(),
            priority: 10,
        };
        assert!(rule_valid.resolve_pattern().is_ok());
    }

    #[test]
    fn test_matches_resource_filesystem_prefix_boundary_leak_protection() {
        let rule_dir = PolicyRule {
            id: "r-dir".to_string(),
            description: "dir".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/data/*".to_string(),
            priority: 10,
        };

        // Subfiles and subdirectories match
        assert!(rule_dir.matches_resource("/sandbox/data/file.txt"));
        assert!(rule_dir.matches_resource("/sandbox/data/sub/nested.txt"));
        assert!(rule_dir.matches_resource("/sandbox/data"));

        // Must NOT match sibling paths that share prefix string (no boundary leak)
        assert!(!rule_dir.matches_resource("/sandbox/data_leak.txt"));
        assert!(!rule_dir.matches_resource("/sandbox/database.db"));
        assert!(!rule_dir.matches_resource("/sandbox/other/file.txt"));

        // Prefix without slash
        let rule_prefix_star = PolicyRule {
            id: "r-star".to_string(),
            description: "star".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/data*".to_string(),
            priority: 10,
        };
        assert!(rule_prefix_star.matches_resource("/sandbox/data"));
        assert!(rule_prefix_star.matches_resource("/sandbox/data_leak.txt"));
        assert!(!rule_prefix_star.matches_resource("/sandbox/other.txt"));
    }

    #[test]
    fn test_matches_resource_literal_string_variants() {
        // Global wildcard for literal string
        let rule_wild = PolicyRule {
            id: "r-lit-wild".to_string(),
            description: "d".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "*".to_string(),
            priority: 10,
        };
        assert!(rule_wild.matches_resource("https://anywhere.com"));

        // Prefix wildcard for literal string
        let rule_prefix = PolicyRule {
            id: "r-lit-prefix".to_string(),
            description: "d".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://api.trusted.com/*".to_string(),
            priority: 10,
        };
        assert!(rule_prefix.matches_resource("https://api.trusted.com/v1/users"));
        assert!(!rule_prefix.matches_resource("https://api.untrusted.com/v1/users"));

        // Exact match for literal string
        let rule_exact = PolicyRule {
            id: "r-lit-exact".to_string(),
            description: "d".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://api.trusted.com/exact".to_string(),
            priority: 10,
        };
        assert!(rule_exact.matches_resource("https://api.trusted.com/exact"));
        assert!(!rule_exact.matches_resource("https://api.trusted.com/exact/extra"));
    }

    #[test]
    fn test_matches_target_null_byte_rejection_and_agent_matching() {
        let rule = PolicyRule {
            id: "r-agent".to_string(),
            description: "agent specific".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-007".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/*".to_string(),
            priority: 10,
        };

        let req_matching = ActionRequest::new(
            "agent-007",
            ActionPayload::ReadFile {
                path: "/sandbox/file.txt".to_string(),
            },
        );
        assert!(rule.matches_target(&req_matching, "/sandbox/file.txt"));

        let req_different_agent = ActionRequest::new(
            "agent-999",
            ActionPayload::ReadFile {
                path: "/sandbox/file.txt".to_string(),
            },
        );
        assert!(!rule.matches_target(&req_different_agent, "/sandbox/file.txt"));

        // Target with null byte is rejected fail-closed
        assert!(!rule.matches_target(&req_matching, "/sandbox/null\0byte.txt"));
    }
}

