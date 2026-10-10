use thiserror::Error;

#[derive(Error, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AgnesError {
    #[error("Action denied by policy: {0}")]
    PolicyDenied(String),

    #[error("Enforcement failure: {0}")]
    EnforcementFailure(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type BlackWallError = AgnesError;
