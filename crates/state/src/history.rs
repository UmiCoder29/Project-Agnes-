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
        let mut hist = self.history.write().expect("lock poisoned");
        let mut sess = self.sessions.write().expect("lock poisoned");

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
        let hist = self.history.read().expect("lock poisoned");
        hist.iter().filter(|e| e.agent_id == agent_id).cloned().collect()
    }

    pub fn get_all_events(&self) -> Vec<SecurityEvent> {
        let hist = self.history.read().expect("lock poisoned");
        hist.clone()
    }

    pub fn get_session(&self, agent_id: &str) -> Option<AgentSession> {
        let sess = self.sessions.read().expect("lock poisoned");
        sess.get(agent_id).cloned()
    }
}
