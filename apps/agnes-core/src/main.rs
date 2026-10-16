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
use agnes_enforcement::{EnforcementResult, FilesystemEnforcer};
use agnes_policy::{Policy, PolicyEngine};
use agnes_state::StateEngine;
use agnes_telemetry::{InMemoryTelemetrySink, StructuredJsonLogSink, TelemetrySink};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
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

/// Configures sandbox roots on the given filesystem enforcer.
///
/// Follows strict fail-closed requirements:
/// - Reads a colon-separated list of paths (e.g. from AGNES_SANDBOX_ROOTS).
/// - Each root must exist and be a directory.
/// - If the variable is unset, empty, or if ANY entry is invalid (non-existent, regular file,
///   unresolvable, or root "/"), logs a clear error and registers NO roots (reads stay denied).
/// - Never defaults to "/" or the current working directory.
pub fn configure_sandbox_roots(enforcer: &FilesystemEnforcer, roots_env: Option<&str>) -> Vec<PathBuf> {
    let raw = match roots_env {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            error!("AGNES_SANDBOX_ROOTS is unset or empty; starting gateway with NO sandbox roots (ReadFile actions will be denied)");
            return Vec::new();
        }
    };

    let entries: Vec<&str> = raw.split(':').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if entries.is_empty() {
        error!("AGNES_SANDBOX_ROOTS contains no valid path entries; starting gateway with NO sandbox roots");
        return Vec::new();
    }

    let mut validated_roots = Vec::new();
    for entry in &entries {
        let p = Path::new(entry);
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

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/action", post(action_handler))
        .route("/v1/policies", post(add_policy_handler))
        .route("/v1/events", get(list_events_handler))
        .route("/v1/state/:agent_id", get(agent_state_handler))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse::<u16>()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Project Agnes Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "UP", "version": "0.1.0", "component": "agnes-core" })))
}

async fn add_policy_handler(
    State(state): State<Arc<AppState>>,
    Json(policy): Json<Policy>,
) -> impl IntoResponse {
    info!(policy_id = %policy.id, rules_count = policy.rules.len(), "Registering policy");
    state.policy_engine.add_policy(policy);
    (StatusCode::CREATED, Json(serde_json::json!({ "status": "Policy registered" })))
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
        _ => {
            // General enforcement stub for other types in v0.1
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
                    output: Some("Execution permitted".to_string()),
                    error_message: None,
                },
            }
        }
    };

    // 3. Construct Security Event
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
    use agnes_common::{ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult};
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
        }));

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

    #[test]
    fn test_configure_sandbox_roots_fail_closed_validation() {
        let enforcer = FilesystemEnforcer::new();

        // Unset
        let roots = configure_sandbox_roots(&enforcer, None);
        assert!(roots.is_empty());

        // Empty
        let roots = configure_sandbox_roots(&enforcer, Some(""));
        assert!(roots.is_empty());

        // Non-existent path
        let roots = configure_sandbox_roots(&enforcer, Some("/nonexistent_sandbox_dir_xyz_123"));
        assert!(roots.is_empty());

        // File instead of directory
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        fs::write(&file_path, "not a dir").unwrap();
        let roots = configure_sandbox_roots(&enforcer, Some(&file_path.to_string_lossy()));
        assert!(roots.is_empty());

        // Root directory "/"
        let roots = configure_sandbox_roots(&enforcer, Some("/"));
        assert!(roots.is_empty());

        // Mixed valid and invalid: must start with NO roots (all-or-nothing fail closed)
        let valid_dir = temp_dir.path().join("valid_dir");
        fs::create_dir_all(&valid_dir).unwrap();
        let mixed = format!("{}:/nonexistent_xyz", valid_dir.display());
        let roots = configure_sandbox_roots(&enforcer, Some(&mixed));
        assert!(roots.is_empty());

        // Valid multiple colon-separated
        let valid_dir2 = temp_dir.path().join("valid_dir2");
        fs::create_dir_all(&valid_dir2).unwrap();
        let multi = format!("{}:{}", valid_dir.display(), valid_dir2.display());
        let roots = configure_sandbox_roots(&enforcer, Some(&multi));
        assert_eq!(roots.len(), 2);
    }
}
