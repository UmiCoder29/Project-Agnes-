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
use tracing::info;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting Project Agnes Runtime Security Core v0.1");

    let state = Arc::new(AppState {
        policy_engine: PolicyEngine::new(),
        state_engine: StateEngine::new(),
        fs_enforcer: FilesystemEnforcer::new(),
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
        Some(session) => (StatusCode::OK, Json(serde_json::to_value(session).unwrap())),
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
