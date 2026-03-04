//! CRUD handlers for API token management.
//!
//! - `POST   /api/tokens`             — Create a new token (session auth only)
//! - `GET    /api/tokens`             — List all tokens (metadata only)
//! - `POST   /api/tokens/{id}/rotate` — Rotate: revoke old, create new with same name (session only)
//! - `DELETE /api/tokens/{id}`        — Revoke a token (soft-delete for audit trail)

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::api_token::{AuthenticatedCaller, generate_raw_token, hash_token, token_prefix};
use crate::store::v1::ApiToken;

/// Request body for creating a new API token.
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
}

/// Response for a newly created token — includes the raw token ONCE.
#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub prefix: String,
    pub created_at: String,
}

/// Response for listing tokens — no raw values, ever.
#[derive(Debug, Serialize)]
pub struct TokenListEntry {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub created_by: Uuid,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked: bool,
}

/// Create a new API token. Requires session auth (no token-minting-tokens).
pub async fn create_api_token(
    State(state): State<AppState>,
    caller: AuthenticatedCaller,
    Json(body): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    // Must be authenticated
    let user = match caller.user {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Authentication required"})),
            )
                .into_response();
        }
    };

    // Token creation requires session auth — no token-minting-tokens
    if caller.via_token {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Token creation requires session auth (browser login)"})),
        )
            .into_response();
    }

    let name = body.name.trim().to_string();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Token name must not be empty"})),
        )
            .into_response();
    }

    // Generate the token
    let raw_token = generate_raw_token();
    let token_hash = hash_token(&raw_token);
    let prefix = token_prefix(&raw_token);
    let now = chrono::Utc::now().to_rfc3339();

    let created_by = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::now_v7());

    let api_token = ApiToken {
        id: Uuid::now_v7(),
        name: name.clone(),
        token_hash,
        prefix: prefix.clone(),
        created_by,
        created_at: now.clone(),
        expires_at: None,
        revoked: false,
    };

    if let Err(e) = state.store.put_api_token(&api_token).await {
        warn!("Failed to store API token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to create token: {}", e)})),
        )
            .into_response();
    }

    info!(
        name = %name,
        prefix = %prefix,
        created_by = %user.username,
        "API token created"
    );

    (
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            id: api_token.id,
            name,
            token: raw_token,
            prefix,
            created_at: now,
        }),
    )
        .into_response()
}

/// List all API tokens (metadata only — raw values are never exposed).
pub async fn list_api_tokens(
    State(state): State<AppState>,
    caller: AuthenticatedCaller,
) -> impl IntoResponse {
    if caller.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response();
    }

    match state.store.list_api_tokens().await {
        Ok(tokens) => {
            let entries: Vec<TokenListEntry> = tokens
                .into_iter()
                .map(|t| TokenListEntry {
                    id: t.id,
                    name: t.name,
                    prefix: t.prefix,
                    created_by: t.created_by,
                    created_at: t.created_at,
                    expires_at: t.expires_at,
                    revoked: t.revoked,
                })
                .collect();
            (StatusCode::OK, Json(json!(entries))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to list tokens: {}", e)})),
        )
            .into_response(),
    }
}

/// Revoke an API token (soft-delete: sets `revoked = true`).
pub async fn revoke_api_token(
    State(state): State<AppState>,
    caller: AuthenticatedCaller,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if caller.user.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response();
    }

    // Fetch the token first so we can soft-revoke
    match state.store.get_api_token(id).await {
        Ok(Some(mut token)) => {
            if token.revoked {
                return (
                    StatusCode::OK,
                    Json(json!({"message": "Token already revoked"})),
                )
                    .into_response();
            }

            token.revoked = true;
            if let Err(e) = state.store.put_api_token(&token).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to revoke token: {}", e)})),
                )
                    .into_response();
            }

            info!(id = %id, prefix = %token.prefix, "API token revoked");
            (
                StatusCode::OK,
                Json(json!({"message": "Token revoked", "id": id})),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Token not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to fetch token: {}", e)})),
        )
            .into_response(),
    }
}

/// Rotate an API token: revoke the old one and create a new one with the same name.
/// Requires session auth (no token-minting-tokens).
pub async fn rotate_api_token(
    State(state): State<AppState>,
    caller: AuthenticatedCaller,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let user = match caller.user {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Authentication required"})),
            )
                .into_response();
        }
    };

    // Token rotation requires session auth — no token-minting-tokens
    if caller.via_token {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Token rotation requires session auth (browser login)"})),
        )
            .into_response();
    }

    // Fetch the old token
    let old_token = match state.store.get_api_token(id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Token not found"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to fetch token: {}", e)})),
            )
                .into_response();
        }
    };

    if old_token.revoked {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cannot rotate a revoked token"})),
        )
            .into_response();
    }

    // Revoke the old token
    let mut revoked = old_token.clone();
    revoked.revoked = true;
    if let Err(e) = state.store.put_api_token(&revoked).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to revoke old token: {}", e)})),
        )
            .into_response();
    }

    // Create the new token with the same name
    let raw_token = generate_raw_token();
    let new_hash = hash_token(&raw_token);
    let prefix = token_prefix(&raw_token);
    let now = chrono::Utc::now().to_rfc3339();
    let created_by = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::now_v7());

    let new_token = ApiToken {
        id: Uuid::now_v7(),
        name: old_token.name.clone(),
        token_hash: new_hash,
        prefix: prefix.clone(),
        created_by,
        created_at: now.clone(),
        expires_at: None,
        revoked: false,
    };

    if let Err(e) = state.store.put_api_token(&new_token).await {
        warn!("Failed to store rotated token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to create new token: {}", e)})),
        )
            .into_response();
    }

    info!(
        old_id = %id,
        new_id = %new_token.id,
        name = %old_token.name,
        prefix = %prefix,
        rotated_by = %user.username,
        "API token rotated"
    );

    (
        StatusCode::OK,
        Json(CreateTokenResponse {
            id: new_token.id,
            name: old_token.name,
            token: raw_token,
            prefix,
            created_at: now,
        }),
    )
        .into_response()
}
