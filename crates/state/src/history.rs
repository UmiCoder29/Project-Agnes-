use std::collections::HashMap;
use std::sync::RwLock;
use agnes_common::SecurityEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub agent_id: String,
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub action_count: u64,
    pub capabilities: Vec<String>,
}

#[derive(Default)]
pub struct StateEngine {
    sessions: RwLock<HashMap<String, AgentSession>>,
    history: RwLock<Vec<SecurityEvent>>,
}

impl StateEngine {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
        }
    }

    pub fn record_event(&self, event: SecurityEvent) {
        // Safe to recover via into_inner(): `history` is an append-only audit event buffer;
        // no security or authorization decision depends on it, and preserving audit event logging
        // after a thread panic is critical for post-incident observability.
        let mut hist = match self.history.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Recovering poisoned history write lock in StateEngine");
                e.into_inner()
            }
        };

        // Safe to recover via into_inner(): `sessions` tracks informational agent activity counts
        // for monitoring/telemetry; no authorization or policy decision depends on this state.
        let mut sess = match self.sessions.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Recovering poisoned sessions write lock in StateEngine");
                e.into_inner()
            }
        };

        let session = sess.entry(event.agent_id.clone()).or_insert_with(|| AgentSession {
            agent_id: event.agent_id.clone(),
            session_id: uuid::Uuid::new_v4().to_string(),
            started_at: Utc::now(),
            action_count: 0,
            capabilities: Vec::new(),
        });

        session.action_count += 1;
        let cap = format!("{:?}:{}", event.action_type, event.target_resource);
        if !session.capabilities.contains(&cap) {
            session.capabilities.push(cap);
        }

        hist.push(event);
    }

    pub fn get_history(&self, agent_id: &str) -> Vec<SecurityEvent> {
        // Safe to recover via into_inner(): read-only query of append-only audit history for telemetry.
        let hist = match self.history.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        hist.iter().filter(|e| e.agent_id == agent_id).cloned().collect()
    }

    pub fn get_all_events(&self) -> Vec<SecurityEvent> {
        // Safe to recover via into_inner(): read-only query of append-only audit history for telemetry.
        let hist = match self.history.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        hist.clone()
    }

    pub fn get_session(&self, agent_id: &str) -> Option<AgentSession> {
        // Safe to recover via into_inner(): read-only query of session activity counts for telemetry.
        let sess = match self.sessions.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        sess.get(agent_id).cloned()
    }
}
