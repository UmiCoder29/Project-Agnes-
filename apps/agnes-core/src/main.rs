use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use agnes_common::{
    ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult, SecurityEvent,
};
use agnes_enforcement::{
    DefaultFilesystemFoldingProbe, EnforcementResult, FilesystemEnforcer, FilesystemFoldingProbe,
};
use agnes_policy::{Policy, PolicyEngine, PolicyLoadError};
use agnes_state::StateEngine;
use agnes_telemetry::{InMemoryTelemetrySink, StructuredJsonLogSink, TelemetrySink};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

pub struct AppState {
    pub policy_engine: PolicyEngine,
    pub state_engine: StateEngine,
    pub fs_enforcer: FilesystemEnforcer,
    pub memory_sink: InMemoryTelemetrySink,
    pub log_sink: StructuredJsonLogSink,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayActionResponse {
    pub correlation_id: Uuid,
    pub test_id: Option<String>,
    pub decision: Decision,
    pub reason: String,
    pub matched_policy_id: String,
    pub enforcement_action: EnforcementAction,
    pub observed_result: ObservedResult,
    pub output: Option<String>,
    pub error_message: Option<String>,
}

use std::path::{Path, PathBuf};

/// Configures sandbox roots on the given filesystem enforcer using the default filesystem folding probe.
pub fn configure_sandbox_roots(enforcer: &FilesystemEnforcer, roots_env: Option<&str>) -> Vec<PathBuf> {
    configure_sandbox_roots_with_probe(enforcer, roots_env, &DefaultFilesystemFoldingProbe)
}

/// Configures sandbox roots with an injectable probe for case and Unicode normalization folding detection.
///
/// Security constraints:
/// - Each entry must be an absolute path (`p.is_absolute()`). Empty entries (leading, trailing, or
///   doubled colons) and relative paths (e.g. `.` or `path/to/dir`) are strictly rejected.
/// - Never defaults to "/" or resolves relative paths against the current working directory.
/// - Each root must exist, be resolvable to canonical form, and be a directory other than root "/".
/// - Startup check: for each root, verifies that the hosting filesystem does NOT fold case or
///   Unicode normalization. If folding is detected, or if probing cannot be verified, rejects the root.
/// - If the variable is unset, empty, or if ANY entry is invalid or on a folding filesystem, logs
///   a clear error and registers NO roots in the enforcer (all-or-nothing fail-closed rule).
pub fn configure_sandbox_roots_with_probe(
    enforcer: &FilesystemEnforcer,
    roots_env: Option<&str>,
    probe: &dyn FilesystemFoldingProbe,
) -> Vec<PathBuf> {
    let raw = match roots_env {
        Some(s) => s.trim(),
        None => {
            error!("AGNES_SANDBOX_ROOTS is unset; starting gateway with NO sandbox roots (ReadFile actions will be denied)");
            return Vec::new();
        }
    };

    if raw.is_empty() {
        error!("AGNES_SANDBOX_ROOTS is empty; starting gateway with NO sandbox roots (ReadFile actions will be denied)");
        return Vec::new();
    }

    let mut validated_roots = Vec::new();
    for raw_entry in raw.split(':') {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            error!(
                raw = %raw,
                "AGNES_SANDBOX_ROOTS contains an empty path entry (e.g. leading, trailing, or doubled colon); starting gateway with NO sandbox roots"
            );
            return Vec::new();
        }

        let p = Path::new(entry);
        if !p.is_absolute() {
            error!(
                root = %entry,
                "AGNES_SANDBOX_ROOTS entry is not an absolute path; starting gateway with NO sandbox roots"
            );
            return Vec::new();
        }

        let canonical = match p.canonicalize() {
            Ok(c) => c,
            Err(err) => {
                error!(
                    root = %entry,
                    error = %err,
                    "AGNES_SANDBOX_ROOTS entry does not exist or failed to resolve; starting gateway with NO sandbox roots"
                );
                return Vec::new();
            }
        };

        if !canonical.is_dir() {
            error!(
                root = %entry,
                canonical = %canonical.display(),
                "AGNES_SANDBOX_ROOTS entry is not a directory; starting gateway with NO sandbox roots"
            );
            return Vec::new();
        }

        // Explicit security rule: never allow root directory "/"
        if canonical == Path::new("/") {
            error!(
                root = %entry,
                "AGNES_SANDBOX_ROOTS entry cannot be root directory '/'; starting gateway with NO sandbox roots"
            );
            return Vec::new();
        }

        // Startup folding probe check: detect case or Unicode normalization folding
        if let Err(probe_err) = probe.detect_folding(&canonical) {
            error!(
                root = %entry,
                canonical = %canonical.display(),
                error = %probe_err,
                "AGNES_SANDBOX_ROOTS entry rejected by filesystem folding probe; starting gateway with NO sandbox roots"
            );
            return Vec::new();
        }

        validated_roots.push(canonical);
    }

    for root in &validated_roots {
        info!(root = %root.display(), "Registered gateway sandbox root");
        enforcer.register_sandbox_root(root);
    }

    validated_roots
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting Project Agnes Runtime Security Core v0.1");

    let fs_enforcer = FilesystemEnforcer::new();
    let roots_env = std::env::var("AGNES_SANDBOX_ROOTS").ok();
    configure_sandbox_roots(&fs_enforcer, roots_env.as_deref());

    let state = Arc::new(AppState {
        policy_engine: PolicyEngine::new(),
        state_engine: StateEngine::new(),
        fs_enforcer,
        memory_sink: InMemoryTelemetrySink::new(),
        log_sink: StructuredJsonLogSink,
    });

    let app = create_app(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse::<u16>()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Project Agnes Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub fn create_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/action", post(action_handler))
        .route("/v1/policies", post(add_policy_handler))
        .route("/v1/events", get(list_events_handler))
        .route("/v1/state/:agent_id", get(agent_state_handler))
        .with_state(state)
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "UP", "version": "0.1.0", "component": "agnes-core" })))
}

async fn add_policy_handler(
    State(state): State<Arc<AppState>>,
    Json(policy): Json<Policy>,
) -> impl IntoResponse {
    info!(policy_id = %policy.id, rules_count = policy.rules.len(), "Registering policy");
    match state.policy_engine.add_policy(policy) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "Policy registered" })),
        ),
        Err(err) => {
            warn!(error = %err, "Failed to register policy: rejecting whole policy");
            let status = match err {
                PolicyLoadError::DuplicatePolicyId { .. } => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": "Failed to register policy",
                    "details": err.to_string(),
                    "policy_id": err.policy_id(),
                    "rule_id": err.rule_id(),
                    "reason": err.reason(),
                })),
            )
        }
    }
}

async fn list_events_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let events = state.state_engine.get_all_events();
    Json(events)
}

async fn agent_state_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(agent_id): AxumPath<String>,
) -> impl IntoResponse {
    match state.state_engine.get_session(&agent_id) {
        Some(session) => match serde_json::to_value(session) {
            Ok(val) => (StatusCode::OK, Json(val)),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization failure: {}", err) })),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Agent session not found" })),
        ),
    }
}

pub async fn process_action(state: &AppState, request: ActionRequest) -> GatewayActionResponse {
    // 1. Evaluate policy deterministically
    let decision_resp = state.policy_engine.evaluate(&request);

    // 2. Perform enforcement based on action type
    let enforcement_res = match &request.action_type {
        ActionType::ReadFile => state.fs_enforcer.enforce_read(&request, &decision_resp),
        ActionType::WriteFile
        | ActionType::ExecuteProcess
        | ActionType::CreateProcess
        | ActionType::NetworkConnect
        | ActionType::DnsLookup
        | ActionType::HttpRequest
        | ActionType::CallTool
        | ActionType::CallMcpTool
        | ActionType::ReadSecret
        | ActionType::SendData
        | ActionType::ModifyPolicy
        | ActionType::RequestCredential
        | ActionType::CommunicateWithAgent => {
            // General enforcement stub for other types in v0.1:
            // Project Agnes currently only enforces ReadFile.
            // For all other action types, policy evaluation succeeds but no actual runtime enforcement or interception is performed.
            match decision_resp.decision {
                Decision::Deny => EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some(format!("Action blocked by policy: {}", decision_resp.matched_policy_id)),
                },
                Decision::Allow => EnforcementResult {
                    enforcement_action: EnforcementAction::PermitExecution,
                    observed_result: ObservedResult::AccessSuccess,
                    output: Some("Allowed by policy; enforcement not implemented for this action type".to_string()),
                    error_message: None,
                },
            }
        }
    };

    // 3. Construct Security Event
    let event = SecurityEvent::new(
        &request,
        &decision_resp.matched_policy_id,
        decision_resp.reason.rule_id.clone(),
        decision_resp.decision,
        &decision_resp.reason.explanation,
        decision_resp.resolved_resource.clone(),
        enforcement_res.enforcement_action,
        enforcement_res.observed_result,
        serde_json::json!({
            "rule_id": decision_resp.reason.rule_id,
            "error": enforcement_res.error_message,
        }),
    );

    // 4. Update state engine
    state.state_engine.record_event(event.clone());

    // 5. Emit telemetry to sinks
    let _ = state.memory_sink.record_event(&event).await;
    let _ = state.log_sink.record_event(&event).await;

    GatewayActionResponse {
        correlation_id: request.correlation_id,
        test_id: request.test_id,
        decision: decision_resp.decision,
        reason: decision_resp.reason.explanation,
        matched_policy_id: decision_resp.matched_policy_id,
        enforcement_action: enforcement_res.enforcement_action,
        observed_result: enforcement_res.observed_result,
        output: enforcement_res.output,
        error_message: enforcement_res.error_message,
    }
}

async fn action_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ActionRequest>,
) -> impl IntoResponse {
    let response = process_action(&state, request).await;
    let status = match response.decision {
        Decision::Allow => StatusCode::OK,
        Decision::Deny => StatusCode::FORBIDDEN,
    };
    (status, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agnes_common::{
        ActionPayload, ActionRequest, ActionType, Decision, DecisionReason, EnforcementAction,
        ObservedResult, PolicyDecisionResponse,
    };
    use agnes_policy::{Policy, PolicyRule};
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_gateway_read_inside_configured_root_allowed_and_outside_blocked() {
        let temp_dir = tempdir().unwrap();
        let allowed_dir = temp_dir.path().join("allowed_sandbox");
        let outside_dir = temp_dir.path().join("outside_sandbox");
        fs::create_dir_all(&allowed_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let allowed_file = allowed_dir.join("test.txt");
        let outside_file = outside_dir.join("secret.txt");
        fs::write(&allowed_file, "AUTHORIZED_GATEWAY_DATA").unwrap();
        fs::write(&outside_file, "UNAUTHORIZED_OUTSIDE_DATA").unwrap();

        let fs_enforcer = FilesystemEnforcer::new();
        let roots_str = allowed_dir.to_string_lossy().to_string();
        let roots = configure_sandbox_roots(&fs_enforcer, Some(&roots_str));
        assert_eq!(roots.len(), 1);

        let policy_engine = PolicyEngine::new();
        policy_engine.add_policy(Policy::new("p-allow-all", "Allow all", 1).with_rule(PolicyRule {
            id: "r-allow".to_string(),
            description: "Allow".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        })).unwrap();

        let state = AppState {
            policy_engine,
            state_engine: StateEngine::new(),
            fs_enforcer,
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        };

        // 1. Read inside configured root: Allowed end to end with content
        let req_inside = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: allowed_file.to_string_lossy().to_string(),
            },
        );
        let resp_inside = process_action(&state, req_inside).await;
        assert_eq!(resp_inside.decision, Decision::Allow);
        assert_eq!(resp_inside.enforcement_action, EnforcementAction::PermitExecution);
        assert_eq!(resp_inside.observed_result, ObservedResult::AccessSuccess);
        assert_eq!(resp_inside.output.as_deref(), Some("AUTHORIZED_GATEWAY_DATA"));

        // 2. Read outside configured root: Blocked by firewall
        let req_outside = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: outside_file.to_string_lossy().to_string(),
            },
        );
        let resp_outside = process_action(&state, req_outside).await;
        assert_eq!(resp_outside.enforcement_action, EnforcementAction::CanonicalBoundaryViolation);
        assert_eq!(resp_outside.observed_result, ObservedResult::BlockedByFirewall);
        assert_eq!(resp_outside.output, None);
    }

    fn assert_enforcer_blocks_canary(enforcer: &FilesystemEnforcer, canary_file: &Path, context: &str) {
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: canary_file.to_string_lossy().to_string(),
            },
        );
        let decision = PolicyDecisionResponse {
            decision: Decision::Allow,
            reason: DecisionReason {
                policy_id: "p-allow-all".to_string(),
                rule_id: Some("r-allow".to_string()),
                explanation: "Allow all".to_string(),
            },
            matched_policy_id: "p-allow-all".to_string(),
            evaluated_at: chrono::Utc::now(),
            resolved_resource: Some(canary_file.to_string_lossy().to_string()),
        };

        let result = enforcer.enforce_read(&req, &decision);
        assert_eq!(
            result.enforcement_action,
            EnforcementAction::CanonicalBoundaryViolation,
            "{}: Enforcer must produce CanonicalBoundaryViolation when no roots are registered",
            context
        );
        assert_eq!(
            result.observed_result,
            ObservedResult::BlockedByFirewall,
            "{}: Enforcer must produce BlockedByFirewall when no roots are registered",
            context
        );
        assert_eq!(
            result.output, None,
            "{}: Enforcer must produce no output when blocked by firewall",
            context
        );
    }

    fn assert_enforcer_permits_canary(
        enforcer: &FilesystemEnforcer,
        canary_file: &Path,
        expected_data: &str,
        context: &str,
    ) {
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: canary_file.to_string_lossy().to_string(),
            },
        );
        let decision = PolicyDecisionResponse {
            decision: Decision::Allow,
            reason: DecisionReason {
                policy_id: "p-allow-all".to_string(),
                rule_id: Some("r-allow".to_string()),
                explanation: "Allow all".to_string(),
            },
            matched_policy_id: "p-allow-all".to_string(),
            evaluated_at: chrono::Utc::now(),
            resolved_resource: Some(canary_file.to_string_lossy().to_string()),
        };

        let result = enforcer.enforce_read(&req, &decision);
        assert_eq!(
            result.enforcement_action,
            EnforcementAction::PermitExecution,
            "{}: Enforcer must produce PermitExecution for valid root",
            context
        );
        assert_eq!(
            result.observed_result,
            ObservedResult::AccessSuccess,
            "{}: Enforcer must produce AccessSuccess for valid root",
            context
        );
        assert_eq!(
            result.output.as_deref(),
            Some(expected_data),
            "{}: Enforcer must return file contents for valid root",
            context
        );
    }

    #[test]
    fn test_configure_sandbox_roots_fail_closed_validation() {
        let temp_dir = tempdir().unwrap();
        let valid_dir = temp_dir.path().join("valid_dir");
        fs::create_dir_all(&valid_dir).unwrap();
        let canary_file = valid_dir.join("canary.txt");
        fs::write(&canary_file, "AUTHORIZED_CANARY_PAYLOAD").unwrap();

        let file_path = temp_dir.path().join("file.txt");
        fs::write(&file_path, "not a dir").unwrap();

        let file_path_str = file_path.to_string_lossy().to_string();
        let valid_dir_str = valid_dir.to_string_lossy().to_string();

        let trailing_colon = format!("{}:", valid_dir_str);
        let leading_colon = format!(":{}", valid_dir_str);
        let doubled_colon = format!("{}::{}", valid_dir_str, valid_dir_str);
        let mixed_valid_invalid = format!("{}:/nonexistent_sandbox_xyz_456", valid_dir_str);
        let mixed_invalid_valid = format!("/nonexistent_sandbox_xyz_456:{}", valid_dir_str);
        let mixed_valid_relative = format!("{}:relative/path", valid_dir_str);

        let failing_cases: Vec<(Option<&str>, &str)> = vec![
            (None, "unset (None)"),
            (Some(""), "empty string"),
            (Some("   "), "whitespace only"),
            (Some("/nonexistent_sandbox_dir_xyz_123"), "non-existent absolute path"),
            (Some(&file_path_str), "regular file instead of directory"),
            (Some("/"), "root directory '/'"),
            (Some(&trailing_colon), "trailing colon"),
            (Some(&leading_colon), "leading colon"),
            (Some(&doubled_colon), "doubled colon"),
            (Some("relative/dir"), "relative path"),
            (Some("."), "dot (current directory)"),
            (Some("./relative"), "relative path prefixed with ./"),
            (Some(".."), "parent directory '..'"),
            (Some(&mixed_valid_invalid), "mixed valid and non-existent entry"),
            (Some(&mixed_invalid_valid), "mixed non-existent entry and valid"),
            (Some(&mixed_valid_relative), "mixed valid and relative path"),
        ];

        for (input, description) in failing_cases {
            let enforcer = FilesystemEnforcer::new();
            let roots = configure_sandbox_roots(&enforcer, input);
            assert!(
                roots.is_empty(),
                "Case '{}' ({:?}) must register NO roots (returned {:?})",
                description,
                input,
                roots
            );
            assert_enforcer_blocks_canary(&enforcer, &canary_file, description);
        }

        // Positive case: valid single root registers successfully and allows access
        {
            let enforcer = FilesystemEnforcer::new();
            let roots = configure_sandbox_roots(&enforcer, Some(&valid_dir_str));
            assert_eq!(roots.len(), 1);
            assert_enforcer_permits_canary(
                &enforcer,
                &canary_file,
                "AUTHORIZED_CANARY_PAYLOAD",
                "valid single root",
            );
        }

        // Positive case: valid multiple roots register successfully and allow access
        {
            let valid_dir2 = temp_dir.path().join("valid_dir2");
            fs::create_dir_all(&valid_dir2).unwrap();
            let canary_file2 = valid_dir2.join("canary2.txt");
            fs::write(&canary_file2, "AUTHORIZED_CANARY_PAYLOAD_2").unwrap();

            let enforcer = FilesystemEnforcer::new();
            let multi = format!("{}:{}", valid_dir_str, valid_dir2.display());
            let roots = configure_sandbox_roots(&enforcer, Some(&multi));
            assert_eq!(roots.len(), 2);
            assert_enforcer_permits_canary(
                &enforcer,
                &canary_file,
                "AUTHORIZED_CANARY_PAYLOAD",
                "valid multi-root (dir 1)",
            );
            assert_enforcer_permits_canary(
                &enforcer,
                &canary_file2,
                "AUTHORIZED_CANARY_PAYLOAD_2",
                "valid multi-root (dir 2)",
            );
        }
    }

    struct SimulatedFoldingProbe;
    impl FilesystemFoldingProbe for SimulatedFoldingProbe {
        fn detect_folding(&self, root: &Path) -> Result<(), String> {
            Err(format!(
                "Simulated folding filesystem detected for root '{}'",
                root.display()
            ))
        }
    }

    #[test]
    fn test_configure_sandbox_roots_simulated_folding_refuses_roots_and_blocks_read() {
        let temp_dir = tempdir().unwrap();
        let valid_dir = temp_dir.path().join("valid_dir");
        fs::create_dir_all(&valid_dir).unwrap();
        let canary_file = valid_dir.join("canary.txt");
        fs::write(&canary_file, "CANARY_SECRET_DATA").unwrap();

        let enforcer = FilesystemEnforcer::new();
        let valid_dir_str = valid_dir.to_string_lossy().to_string();

        let roots = configure_sandbox_roots_with_probe(
            &enforcer,
            Some(&valid_dir_str),
            &SimulatedFoldingProbe,
        );

        assert!(
            roots.is_empty(),
            "Simulated folding filesystem must refuse root and register NO roots (all-or-nothing)"
        );
        assert_enforcer_blocks_canary(
            &enforcer,
            &canary_file,
            "simulated folding filesystem must block file reads fail-closed",
        );
    }

    #[test]
    fn test_configure_sandbox_roots_normal_root_accepted_and_probe_file_cleaned_up() {
        let temp_dir = tempdir().unwrap();
        let valid_dir = temp_dir.path().join("valid_dir");
        fs::create_dir_all(&valid_dir).unwrap();
        let canary_file = valid_dir.join("canary.txt");
        fs::write(&canary_file, "AUTHORIZED_PAYLOAD").unwrap();

        let enforcer = FilesystemEnforcer::new();
        let valid_dir_str = valid_dir.to_string_lossy().to_string();

        let roots = configure_sandbox_roots(&enforcer, Some(&valid_dir_str));
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], valid_dir.canonicalize().unwrap());

        // Verify that the probe file was removed and never remains on disk
        let entries: Vec<_> = fs::read_dir(&valid_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();

        for name in &entries {
            assert!(
                !name.starts_with(".agnes_probe_"),
                "Probe file '{}' must never remain on disk after startup check",
                name
            );
        }
        assert_eq!(entries, vec!["canary.txt"]);

        assert_enforcer_permits_canary(
            &enforcer,
            &canary_file,
            "AUTHORIZED_PAYLOAD",
            "normal root accepted and canary readable",
        );
    }

    #[tokio::test]
    async fn test_post_policies_endpoint_rejects_invalid_pattern_with_400_and_registers_nothing() {
        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        // 1. Policy with a rule containing an unresolvable pattern (leading space)
        let invalid_policy = Policy::new("p-bad-lead-space", "Invalid Policy", 1)
            .with_rule(PolicyRule {
                id: "rule-allow".to_string(),
                description: "Allow all".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: "*".to_string(),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "rule-bad-deny".to_string(),
                description: "Deny with leading space".to_string(),
                decision: Decision::Deny,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: " /secret/*".to_string(),
                priority: 100,
            });

        let response = add_policy_handler(State(state.clone()), Json(invalid_policy)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "POST /v1/policies must return HTTP 400 Bad Request on invalid rule pattern"
        );

        // 2. Engine must have registered NOTHING from the invalid policy (default deny)
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/tmp/anything.txt".to_string(),
            },
        );
        let eval = state.policy_engine.evaluate(&req);
        assert_eq!(
            eval.decision,
            Decision::Deny,
            "Rejected policy must not leave partial rules registered in engine"
        );
        assert_eq!(eval.matched_policy_id, "default-fail-closed");

        // 3. Positive verification: valid policy returns 201 Created and registers
        let valid_policy = Policy::new("p-good", "Valid Policy", 1)
            .with_rule(PolicyRule {
                id: "rule-allow".to_string(),
                description: "Allow all".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: "*".to_string(),
                priority: 10,
            });

        let good_response = add_policy_handler(State(state.clone()), Json(valid_policy)).await.into_response();
        assert_eq!(
            good_response.status(),
            StatusCode::CREATED,
            "POST /v1/policies must return HTTP 201 Created on valid policy"
        );
        assert_eq!(state.policy_engine.evaluate(&req).decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_gateway_relative_path_returns_403_fail_closed_relative_path() {
        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        // Even with a policy that allows wildcard ReadFile
        state
            .policy_engine
            .add_policy(
                Policy::new("p-allow-all", "Allow all", 1).with_rule(PolicyRule {
                    id: "r-allow".to_string(),
                    description: "Allow".to_string(),
                    decision: Decision::Allow,
                    agent_pattern: "*".to_string(),
                    action_types: vec![ActionType::ReadFile],
                    resource_pattern: "*".to_string(),
                    priority: 10,
                }),
            )
            .unwrap();

        let req_relative = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "relative/path/to/file.txt".to_string(),
            },
        );

        let response = action_handler(State(state.clone()), Json(req_relative.clone())).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "POST /v1/action with a relative path must return HTTP 403 Forbidden"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["decision"], "DENY");
        assert_eq!(body_json["matched_policy_id"], "fail-closed-relative-path");
        assert_eq!(body_json["enforcement_action"], "BLOCK_REQUEST");
        assert_eq!(body_json["observed_result"], "BLOCKED_BY_FIREWALL");
    }

    #[tokio::test]
    async fn test_post_policy_duplicate_id_returns_409_conflict() {
        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        let policy = Policy::new("p-unique-1", "Unique Policy 1", 1).with_rule(PolicyRule {
            id: "rule-1".to_string(),
            description: "Rule 1".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        });

        // 1. First registration succeeds with 201 Created
        let resp1 = add_policy_handler(State(state.clone()), Json(policy.clone()))
            .await
            .into_response();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        // 2. Second registration with duplicate policy ID returns 409 Conflict
        let resp2 = add_policy_handler(State(state), Json(policy))
            .await
            .into_response();
        assert_eq!(
            resp2.status(),
            StatusCode::CONFLICT,
            "Registering duplicate policy ID must return HTTP 409 Conflict"
        );

        let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["policy_id"], "p-unique-1");
        assert_eq!(body_json["reason"], "Duplicate policy ID");
    }

    #[tokio::test]
    async fn test_gateway_unknown_action_type_returns_4xx_rejection_never_allow() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        let app = create_app(state);

        // Raw JSON request with an unknown action_type TELEPORT
        let raw_payload = serde_json::json!({
            "correlation_id": uuid::Uuid::new_v4().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "agent_id": "agent-001",
            "action_type": "TELEPORT",
            "target_resource": "mars",
            "payload": {
                "type": "HTTP_REQUEST",
                "details": {
                    "method": "GET",
                    "url": "https://example.com"
                }
            }
        });

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/action")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&raw_payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "POST /v1/action with unknown action_type must return a 4xx client rejection, got {}",
            resp.status()
        );
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "Unknown action_type must NEVER return HTTP 200 Allow"
        );
    }

    #[tokio::test]
    async fn test_gateway_unknown_payload_type_returns_4xx_rejection_never_allow() {
        use axum::body::Body;
        use tower::ServiceExt;

        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        let app = create_app(state);

        // Raw JSON request with an unknown payload type TELEPORT
        let raw_payload = serde_json::json!({
            "correlation_id": uuid::Uuid::new_v4().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "agent_id": "agent-001",
            "action_type": "HTTP_REQUEST",
            "target_resource": "https://example.com",
            "payload": {
                "type": "TELEPORT",
                "details": {
                    "coordinates": "0,0"
                }
            }
        });

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/action")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&raw_payload).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "POST /v1/action with unknown payload type must return a 4xx client rejection, got {}",
            resp.status()
        );
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "Unknown payload type must NEVER return HTTP 200 Allow"
        );
    }

    #[tokio::test]
    async fn test_gateway_request_mismatch_returns_403_fail_closed_request_mismatch() {
        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        // Even with an Allow-all policy for ReadFile
        state
            .policy_engine
            .add_policy(
                Policy::new("p-allow-all", "Allow all", 1).with_rule(PolicyRule {
                    id: "r-allow".to_string(),
                    description: "Allow".to_string(),
                    decision: Decision::Allow,
                    agent_pattern: "*".to_string(),
                    action_types: vec![ActionType::ReadFile],
                    resource_pattern: "*".to_string(),
                    priority: 10,
                }),
            )
            .unwrap();

        // Mismatched request: action_type header is ReadFile, but payload is HttpRequest
        let req_mismatched = ActionRequest {
            correlation_id: uuid::Uuid::new_v4(),
            test_id: Some("MISMATCH-GW".to_string()),
            timestamp: chrono::Utc::now(),
            agent_id: "agent-001".to_string(),
            session_id: None,
            action_type: ActionType::ReadFile,
            target_resource: "/tmp/allowed.txt".to_string(),
            payload: ActionPayload::HttpRequest {
                method: "GET".to_string(),
                url: "https://evil.com".to_string(),
                headers: None,
                body: None,
            },
        };

        let response = action_handler(State(state.clone()), Json(req_mismatched)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "POST /v1/action with mismatched header and payload must return HTTP 403 Forbidden"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["decision"], "DENY");
        assert_eq!(body_json["matched_policy_id"], "fail-closed-request-mismatch");
        assert_eq!(body_json["enforcement_action"], "BLOCK_REQUEST");

        // Target mismatch: action_type and payload type are ReadFile, but target paths differ
        let req_target_mismatch = ActionRequest {
            correlation_id: uuid::Uuid::new_v4(),
            test_id: Some("MISMATCH-TARGET-GW".to_string()),
            timestamp: chrono::Utc::now(),
            agent_id: "agent-001".to_string(),
            session_id: None,
            action_type: ActionType::ReadFile,
            target_resource: "/tmp/allowed.txt".to_string(),
            payload: ActionPayload::ReadFile {
                path: "/tmp/different.txt".to_string(),
            },
        };

        let response2 = action_handler(State(state), Json(req_target_mismatch)).await.into_response();
        assert_eq!(response2.status(), StatusCode::FORBIDDEN);
        let body_bytes2 = axum::body::to_bytes(response2.into_body(), usize::MAX).await.unwrap();
        let body_json2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
        assert_eq!(body_json2["decision"], "DENY");
        assert_eq!(body_json2["matched_policy_id"], "fail-closed-request-mismatch");
        assert_eq!(body_json2["enforcement_action"], "BLOCK_REQUEST");
        assert_eq!(body_json2["observed_result"], "BLOCKED_BY_FIREWALL");
    }

    #[tokio::test]
    async fn test_gateway_non_read_file_allow_stub_honesty() {
        let state = Arc::new(AppState {
            policy_engine: PolicyEngine::new(),
            state_engine: StateEngine::new(),
            fs_enforcer: FilesystemEnforcer::new(),
            memory_sink: InMemoryTelemetrySink::new(),
            log_sink: StructuredJsonLogSink,
        });

        // Allow HttpRequest to https://trusted.internal/*
        state
            .policy_engine
            .add_policy(
                Policy::new("p-allow-http", "Allow http", 1).with_rule(PolicyRule {
                    id: "r-http".to_string(),
                    description: "Allow internal HTTP".to_string(),
                    decision: Decision::Allow,
                    agent_pattern: "*".to_string(),
                    action_types: vec![ActionType::HttpRequest],
                    resource_pattern: "https://trusted.internal/*".to_string(),
                    priority: 10,
                }),
            )
            .unwrap();

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::HttpRequest {
                method: "GET".to_string(),
                url: "https://trusted.internal/api/v1".to_string(),
                headers: None,
                body: None,
            },
        );

        let response = action_handler(State(state), Json(req)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body_json["decision"], "ALLOW");
        assert_eq!(body_json["enforcement_action"], "PERMIT_EXECUTION");
        assert_eq!(body_json["observed_result"], "ACCESS_SUCCESS");
        assert_eq!(
            body_json["output"],
            "Allowed by policy; enforcement not implemented for this action type"
        );
    }

    #[tokio::test]
    async fn test_process_action_emits_security_event_with_resolved_path_and_rule_id() {
        let temp_dir = tempdir().unwrap();
        let sandbox_dir = temp_dir.path().join("sandbox");
        let link_dir = temp_dir.path().join("symlinks");
        fs::create_dir_all(&sandbox_dir).unwrap();
        fs::create_dir_all(&link_dir).unwrap();

        let real_file = sandbox_dir.join("payload.txt");
        fs::write(&real_file, "SECRET_CORE_DATA").unwrap();
        let canonical_real_file = real_file.canonicalize().unwrap();

        let symlink_file = link_dir.join("link_to_payload.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &symlink_file).unwrap();

        let fs_enforcer = FilesystemEnforcer::new();
        fs_enforcer.register_sandbox_root(&sandbox_dir);

        let policy_engine = PolicyEngine::new();
        policy_engine
            .add_policy(
                Policy::new("p-core-test", "Core Policy", 1).with_rule(PolicyRule {
                    id: "r-core-allow".to_string(),
                    description: "Allow sandbox reads".to_string(),
                    decision: Decision::Allow,
                    agent_pattern: "*".to_string(),
                    action_types: vec![ActionType::ReadFile],
                    resource_pattern: format!("{}/*", sandbox_dir.canonicalize().unwrap().display()),
                    priority: 10,
                }),
            )
            .unwrap();

        let memory_sink = InMemoryTelemetrySink::new();
        let state = AppState {
            policy_engine,
            state_engine: StateEngine::new(),
            fs_enforcer,
            memory_sink,
            log_sink: StructuredJsonLogSink,
        };

        let symlink_str = symlink_file.to_string_lossy().to_string();
        let canonical_str = canonical_real_file.to_string_lossy().to_string();

        let req = ActionRequest::new(
            "agent-core",
            ActionPayload::ReadFile {
                path: symlink_str.clone(),
            },
        );

        let resp = process_action(&state, req).await;
        assert_eq!(resp.decision, Decision::Allow);

        // Verify emitted SecurityEvent in InMemoryTelemetrySink
        let events = state.memory_sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];

        assert_eq!(event.action_type, ActionType::ReadFile);
        assert_eq!(event.decision, Decision::Allow);
        assert_eq!(event.policy_id, "p-core-test");
        assert_eq!(event.rule_id.as_deref(), Some("r-core-allow"));
        assert_eq!(event.raw_resource, symlink_str);
        assert_eq!(event.resolved_resource.as_deref(), Some(canonical_str.as_str()));

        // Also check JSON representation matches expectations
        let event_json = serde_json::to_value(event).unwrap();
        assert_eq!(event_json["resolved_resource"], canonical_str);
        assert_eq!(event_json["raw_resource"], symlink_str);
        assert_eq!(event_json["rule_id"], "r-core-allow");
        assert_eq!(event_json["policy_id"], "p-core-test");
    }
}
