use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Not found")]
    NotFound,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Authentication error: {0}")]
    Auth(String),
}
