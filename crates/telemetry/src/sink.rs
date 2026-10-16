use async_trait::async_trait;
use agnes_common::SecurityEvent;
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
        info!(target: "agnes::telemetry", "{}", serialized);
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
        // Safe to recover via into_inner(): `events` is an in-memory audit log for testing and telemetry.
        // Reading existing events after a thread panic preserves observational visibility.
        let guard = match self.events.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.clone()
    }
}

#[async_trait]
impl TelemetrySink for InMemoryTelemetrySink {
    async fn record_event(&self, event: &SecurityEvent) -> Result<(), String> {
        // Safe to recover via into_inner(): append-only telemetry buffer; no authorization decision depends
        // on telemetry events, and continuing to record security telemetry after a thread panic is safe.
        let mut guard = match self.events.write() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Recovering poisoned events write lock in InMemoryTelemetrySink");
                e.into_inner()
            }
        };
        guard.push(event.clone());
        Ok(())
    }
}
