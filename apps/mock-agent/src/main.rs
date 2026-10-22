use agnes_common::{ActionPayload, ActionRequest};
use serde_json::Value;
use std::env;
use tracing::info;

pub struct MockAgent {
    pub agent_id: String,
    pub gateway_url: String,
    client: reqwest::Client,
}

impl MockAgent {
    pub fn new(agent_id: impl Into<String>, gateway_url: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            gateway_url: gateway_url.into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn dispatch_action(&self, payload: ActionPayload, test_id: Option<String>) -> anyhow::Result<Value> {
        let mut request = ActionRequest::new(&self.agent_id, payload);
        if let Some(t_id) = test_id {
            request = request.with_test_id(t_id);
        }

        info!(
            agent = %self.agent_id,
            action = ?request.action_type,
            resource = %request.target_resource,
            "Mock agent sending action to Project Agnes Gateway"
        );

        let endpoint = format!("{}/v1/action", self.gateway_url);
        let resp = self.client.post(&endpoint).json(&request).send().await?;
        let status = resp.status();
        let body: Value = resp.json().await?;

        info!(status = %status, response = ?body, "Received response from Project Agnes Gateway");
        Ok(body)
    }

    // Generator helpers for mock agent
    pub fn generate_read_file(path: impl Into<String>) -> ActionPayload {
        ActionPayload::ReadFile { path: path.into() }
    }

    pub fn generate_write_file(path: impl Into<String>, content: impl Into<String>) -> ActionPayload {
        ActionPayload::WriteFile {
            path: path.into(),
            content: content.into(),
        }
    }

    pub fn generate_execute_process(command: impl Into<String>, args: Vec<String>) -> ActionPayload {
        ActionPayload::ExecuteProcess {
            command: command.into(),
            args,
        }
    }

    pub fn generate_create_process(executable: impl Into<String>, args: Vec<String>) -> ActionPayload {
        ActionPayload::CreateProcess {
            executable: executable.into(),
            args,
        }
    }

    pub fn generate_network_connect(destination: impl Into<String>, port: u16) -> ActionPayload {
        ActionPayload::NetworkConnect {
            destination: destination.into(),
            port,
        }
    }

    pub fn generate_dns_lookup(hostname: impl Into<String>) -> ActionPayload {
        ActionPayload::DnsLookup {
            hostname: hostname.into(),
        }
    }

    pub fn generate_http_request(method: impl Into<String>, url: impl Into<String>) -> ActionPayload {
        ActionPayload::HttpRequest {
            method: method.into(),
            url: url.into(),
            headers: None,
            body: None,
        }
    }

    pub fn generate_call_tool(tool_name: impl Into<String>, arguments: Value) -> ActionPayload {
        ActionPayload::CallTool {
            tool_name: tool_name.into(),
            arguments,
        }
    }

    pub fn generate_call_mcp_tool(
        server_name: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: Value,
    ) -> ActionPayload {
        ActionPayload::CallMcpTool {
            server_name: server_name.into(),
            tool_name: tool_name.into(),
            arguments,
        }
    }

    pub fn generate_read_secret(secret_id: impl Into<String>) -> ActionPayload {
        ActionPayload::ReadSecret {
            secret_id: secret_id.into(),
        }
    }

    pub fn generate_send_data(destination: impl Into<String>, preview: impl Into<String>) -> ActionPayload {
        ActionPayload::SendData {
            destination: destination.into(),
            payload_preview: preview.into(),
        }
    }

    pub fn generate_modify_policy(policy_id: impl Into<String>, action: impl Into<String>) -> ActionPayload {
        ActionPayload::ModifyPolicy {
            policy_id: policy_id.into(),
            action: action.into(),
        }
    }

    pub fn generate_request_credential(scope: impl Into<String>) -> ActionPayload {
        ActionPayload::RequestCredential {
            scope: scope.into(),
        }
    }

    pub fn generate_communicate_with_agent(
        target_agent: impl Into<String>,
        message: impl Into<String>,
    ) -> ActionPayload {
        ActionPayload::CommunicateWithAgent {
            target_agent: target_agent.into(),
            message: message.into(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let agent_id = env::var("AGENT_ID").unwrap_or_else(|_| "mock-agent-001".to_string());
    // Deliberate legacy fallback: support BLACKWALL_GATEWAY_URL from pre-rename configurations
    // while prioritizing the standard AGNES_GATEWAY_URL environment variable.
    let gateway_url = env::var("AGNES_GATEWAY_URL")
        .or_else(|_| env::var("BLACKWALL_GATEWAY_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    let agent = MockAgent::new(agent_id, gateway_url);
    info!("Mock agent initialized. Ready to generate security actions.");

    // Demonstration run
    let action = MockAgent::generate_read_file("/allowed/sample.txt");
    let _ = agent.dispatch_action(action, Some("TEST-INIT".to_string())).await;

    Ok(())
}
