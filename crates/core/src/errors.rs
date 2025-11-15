use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("title must not be empty")]
    EmptyTitle,
    #[error("content must not be empty")]
    EmptyContent,
    #[error("invalid type: {0}")]
    InvalidType(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("storage io error: {0}")]
    StorageIo(String),
    #[error("internal error: {0}")]
    Internal(String),
}
