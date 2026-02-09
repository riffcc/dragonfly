use axum::{Json, response::{IntoResponse, Response}};
use proxmox_client::Error as ProxmoxClientError;
use std::error::Error as StdError;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum ProxmoxHandlerError {
    #[error("Proxmox API error: {0}")]
    ApiError(#[from] ProxmoxClientError),
    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),
    #[error("Login error: {0}")]
    LoginError(Box<dyn StdError + Send + Sync>),
    #[error("HTTP client error: {0}")]
    HttpClientError(Box<dyn StdError + Send + Sync>),
    #[error("TLS Certificate validation error: {0}")]
    TlsValidationError(String),
}

impl IntoResponse for ProxmoxHandlerError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code, suggest_disable_tls_verify) = match &self {
            ProxmoxHandlerError::ApiError(e) => {
                error!("Proxmox API Error: {}", e);
                let err_str = e.to_string();
                if err_str.contains("certificate")
                    || err_str.contains("SSL")
                    || err_str.contains("TLS")
                    || err_str.contains("self-signed")
                    || err_str.contains("unknown issuer")
                {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        format!(
                            "Proxmox SSL certificate validation failed. You may need to try again with certificate validation disabled: {}",
                            e
                        ),
                        "TLS_VALIDATION_ERROR".to_string(),
                        true,
                    )
                } else {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Proxmox API interaction failed: {}", e),
                        "API_ERROR".to_string(),
                        false,
                    )
                }
            }
            ProxmoxHandlerError::TlsValidationError(msg) => {
                error!("Proxmox TLS Validation Error: {}", msg);
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!(
                        "Proxmox SSL certificate validation failed: {}. Try again with certificate validation disabled.",
                        msg
                    ),
                    "TLS_VALIDATION_ERROR".to_string(),
                    true,
                )
            }
            ProxmoxHandlerError::DbError(e) => {
                error!("Database Error: {}", e);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database operation failed: {}", e),
                    "DB_ERROR".to_string(),
                    false,
                )
            }
            ProxmoxHandlerError::ConfigError(msg) => {
                error!("Configuration Error: {}", msg);
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    msg.clone(),
                    "CONFIG_ERROR".to_string(),
                    false,
                )
            }
            ProxmoxHandlerError::InternalError(e) => {
                error!("Internal Server Error: {}", e);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred.".to_string(),
                    "INTERNAL_ERROR".to_string(),
                    false,
                )
            }
            ProxmoxHandlerError::LoginError(e) => {
                error!("Proxmox Login Error: {}", e);
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    format!("Proxmox authentication failed: {}", e),
                    "LOGIN_ERROR".to_string(),
                    false,
                )
            }
            ProxmoxHandlerError::HttpClientError(e) => {
                error!("Proxmox HTTP Client Error: {}", e);
                let err_str = e.to_string();
                if err_str.contains("certificate")
                    || err_str.contains("SSL")
                    || err_str.contains("TLS")
                    || err_str.contains("self signed")
                    || err_str.contains("unknown issuer")
                {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        format!(
                            "Proxmox SSL certificate validation failed: {}. Try again with certificate validation disabled.",
                            e
                        ),
                        "TLS_VALIDATION_ERROR".to_string(),
                        true,
                    )
                } else {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Proxmox HTTP communication failed: {}", e),
                        "HTTP_ERROR".to_string(),
                        false,
                    )
                }
            }
        };

        let response_json = serde_json::json!({
            "error": error_code,
            "message": error_message,
            "suggest_disable_tls_verify": suggest_disable_tls_verify
        });

        (status, Json(response_json)).into_response()
    }
}

pub type ProxmoxResult<T> = std::result::Result<T, ProxmoxHandlerError>;
