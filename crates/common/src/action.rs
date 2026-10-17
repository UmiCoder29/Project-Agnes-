use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    ReadFile,
    WriteFile,
    ExecuteProcess,
    CreateProcess,
    NetworkConnect,
    DnsLookup,
    HttpRequest,
    CallTool,
    CallMcpTool,
    ReadSecret,
    SendData,
    ModifyPolicy,
    RequestCredential,
    CommunicateWithAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternKind {
    FilesystemPath,
    LiteralString,
}

impl ActionType {
    pub const ALL: [ActionType; 14] = [
        ActionType::ReadFile,
        ActionType::WriteFile,
        ActionType::ExecuteProcess,
        ActionType::CreateProcess,
        ActionType::NetworkConnect,
        ActionType::DnsLookup,
        ActionType::HttpRequest,
        ActionType::CallTool,
        ActionType::CallMcpTool,
        ActionType::ReadSecret,
        ActionType::SendData,
        ActionType::ModifyPolicy,
        ActionType::RequestCredential,
        ActionType::CommunicateWithAgent,
    ];

    pub fn pattern_kind(&self) -> PatternKind {
        match self {
            ActionType::ReadFile | ActionType::WriteFile => PatternKind::FilesystemPath,
            ActionType::ExecuteProcess
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
            | ActionType::CommunicateWithAgent => PatternKind::LiteralString,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ActionPayload {
    #[serde(rename = "READ_FILE")]
    ReadFile {
        path: String,
    },
    #[serde(rename = "WRITE_FILE")]
    WriteFile {
        path: String,
        content: String,
    },
    #[serde(rename = "EXECUTE_PROCESS")]
    ExecuteProcess {
        command: String,
        args: Vec<String>,
    },
    #[serde(rename = "CREATE_PROCESS")]
    CreateProcess {
        executable: String,
        args: Vec<String>,
    },
    #[serde(rename = "NETWORK_CONNECT")]
    NetworkConnect {
        destination: String,
        port: u16,
    },
    #[serde(rename = "DNS_LOOKUP")]
    DnsLookup {
        hostname: String,
    },
    #[serde(rename = "HTTP_REQUEST")]
    HttpRequest {
        method: String,
        url: String,
        headers: Option<std::collections::HashMap<String, String>>,
        body: Option<String>,
    },
    #[serde(rename = "CALL_TOOL")]
    CallTool {
        tool_name: String,
        arguments: serde_json::Value,
    },
    #[serde(rename = "CALL_MCP_TOOL")]
    CallMcpTool {
        server_name: String,
        tool_name: String,
        arguments: serde_json::Value,
    },
    #[serde(rename = "READ_SECRET")]
    ReadSecret {
        secret_id: String,
    },
    #[serde(rename = "SEND_DATA")]
    SendData {
        destination: String,
        payload_preview: String,
    },
    #[serde(rename = "MODIFY_POLICY")]
    ModifyPolicy {
        policy_id: String,
        action: String,
    },
    #[serde(rename = "REQUEST_CREDENTIAL")]
    RequestCredential {
        scope: String,
    },
    #[serde(rename = "COMMUNICATE_WITH_AGENT")]
    CommunicateWithAgent {
        target_agent: String,
        message: String,
    },
}

impl ActionPayload {
    pub fn action_type(&self) -> ActionType {
        match self {
            ActionPayload::ReadFile { .. } => ActionType::ReadFile,
            ActionPayload::WriteFile { .. } => ActionType::WriteFile,
            ActionPayload::ExecuteProcess { .. } => ActionType::ExecuteProcess,
            ActionPayload::CreateProcess { .. } => ActionType::CreateProcess,
            ActionPayload::NetworkConnect { .. } => ActionType::NetworkConnect,
            ActionPayload::DnsLookup { .. } => ActionType::DnsLookup,
            ActionPayload::HttpRequest { .. } => ActionType::HttpRequest,
            ActionPayload::CallTool { .. } => ActionType::CallTool,
            ActionPayload::CallMcpTool { .. } => ActionType::CallMcpTool,
            ActionPayload::ReadSecret { .. } => ActionType::ReadSecret,
            ActionPayload::SendData { .. } => ActionType::SendData,
            ActionPayload::ModifyPolicy { .. } => ActionType::ModifyPolicy,
            ActionPayload::RequestCredential { .. } => ActionType::RequestCredential,
            ActionPayload::CommunicateWithAgent { .. } => ActionType::CommunicateWithAgent,
        }
    }

    pub fn target_resource(&self) -> String {
        match self {
            ActionPayload::ReadFile { path } => path.clone(),
            ActionPayload::WriteFile { path, .. } => path.clone(),
            ActionPayload::ExecuteProcess { command, .. } => command.clone(),
            ActionPayload::CreateProcess { executable, .. } => executable.clone(),
            ActionPayload::NetworkConnect { destination, port } => format!("{}:{}", destination, port),
            ActionPayload::DnsLookup { hostname } => hostname.clone(),
            ActionPayload::HttpRequest { url, .. } => url.clone(),
            ActionPayload::CallTool { tool_name, .. } => tool_name.clone(),
            ActionPayload::CallMcpTool { server_name, tool_name, .. } => format!("{}/{}", server_name, tool_name),
            ActionPayload::ReadSecret { secret_id } => secret_id.clone(),
            ActionPayload::SendData { destination, .. } => destination.clone(),
            ActionPayload::ModifyPolicy { policy_id, .. } => policy_id.clone(),
            ActionPayload::RequestCredential { scope } => scope.clone(),
            ActionPayload::CommunicateWithAgent { target_agent, .. } => target_agent.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub correlation_id: Uuid,
    pub test_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub action_type: ActionType,
    pub payload: ActionPayload,
    pub target_resource: String,
}

impl ActionRequest {
    pub fn new(agent_id: impl Into<String>, payload: ActionPayload) -> Self {
        let action_type = payload.action_type();
        let target_resource = payload.target_resource();

        Self {
            correlation_id: Uuid::new_v4(),
            test_id: None,
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            session_id: None,
            action_type,
            payload,
            target_resource,
        }
    }

    pub fn with_test_id(mut self, test_id: impl Into<String>) -> Self {
        self.test_id = Some(test_id.into());
        self
    }
}
