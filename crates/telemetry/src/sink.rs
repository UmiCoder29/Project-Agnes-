use async_trait::async_trait;
use blackwall_common::SecurityEvent;
use std::sync::RwLock;
use tracing::info;

#[async_trait]
pub trait TelemetrySink: Send + Sync {
    async fn record_event(&self, event: &SecurityEvent) -> Result<(), String>;
}

pub struct StructuredJsonLogSink;

#[async_trait]
impl TelemetrySink for StructuredJsonLogSink {
    async fn record_event(&self, event: &SecurityEvent) -> Result<(), String> {
        let serialized = serde_json::to_string(event).map_err(|e| e.to_string())?;
        info!(target: "blackwall::telemetry", "{}", serialized);
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryTelemetrySink {
    events: RwLock<Vec<SecurityEvent>>,
}

impl InMemoryTelemetrySink {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
        }
    }

    pub fn events(&self) -> Vec<SecurityEvent> {
        self.events.read().expect("lock poisoned").clone()
    }
}

#[async_trait]
impl TelemetrySink for InMemoryTelemetrySink {
    async fn record_event(&self, event: &SecurityEvent) -> Result<(), String> {
        let mut guard = self.events.write().expect("lock poisoned");
        guard.push(event.clone());
        Ok(())
    }
}
