//! API token generation, hashing, and Bearer authentication extractor.
//!
//! Tokens use SHA-256 hashing (not Argon2) because they are high-entropy
//! random values — the same approach used by GitHub, Stripe, and GitLab.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use hex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::AppState;
use crate::auth::{AdminUser, AuthSession};

/// Prefix for all Dragonfly API tokens.
const TOKEN_PREFIX: &str = "df_";

/// Number of random bytes in each token (produces 96 hex chars).
const TOKEN_RANDOM_BYTES: usize = 48;

/// Number of hex chars to show in the display prefix (after "df_").
const PREFIX_DISPLAY_LEN: usize = 8;

/// Generate a raw API token: `df_` followed by 96 hex characters (48 random bytes).
pub fn generate_raw_token() -> String {
    let mut buf = [0u8; TOKEN_RANDOM_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("{}{}", TOKEN_PREFIX, hex::encode(buf))
}

/// SHA-256 hash a raw token, returning the hex-encoded digest.
pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Extract the display prefix from a raw token (e.g. `df_a1b2c3d4`).
pub fn token_prefix(raw: &str) -> String {
    let hex_part = raw.strip_prefix(TOKEN_PREFIX).unwrap_or(raw);
    let show = &hex_part[..hex_part.len().min(PREFIX_DISPLAY_LEN)];
    format!("{}{}", TOKEN_PREFIX, show)
}

/// Represents an authenticated caller — either via Bearer token or session cookie.
///
/// Handlers that want to support both API tokens AND browser sessions use this
/// instead of `AuthSession` directly.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    /// The authenticated user, if any. `None` means unauthenticated.
    pub user: Option<AdminUser>,
    /// `true` if authentication came from a Bearer token.
    pub via_token: bool,
}

impl AuthenticatedCaller {
    /// Returns `true` if the caller is authenticated (regardless of method).
    pub fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }
}

impl FromRequestParts<AppState> for AuthenticatedCaller {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Check for Authorization: Bearer header
        if let Some(auth_header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(header_str) = auth_header.to_str() {
                if let Some(raw_token) = header_str.strip_prefix("Bearer ") {
                    let raw_token = raw_token.trim();
                    if raw_token.starts_with(TOKEN_PREFIX) {
                        let token_hash = hash_token(raw_token);

                        match state.store.get_api_token_by_hash(&token_hash).await {
                            Ok(Some(api_token)) => {
                                debug!(
                                    prefix = %api_token.prefix,
                                    name = %api_token.name,
                                    "Authenticated via API token"
                                );
                                return Ok(AuthenticatedCaller {
                                    user: Some(AdminUser {
                                        id: api_token.created_by.to_string(),
                                        username: format!("token:{}", api_token.name),
                                    }),
                                    via_token: true,
                                });
                            }
                            Ok(None) => {
                                debug!("Bearer token lookup returned no match");
                            }
                            Err(e) => {
                                debug!("Error looking up API token: {}", e);
                            }
                        }
                    }
                }
            }
        }

        // 2. Fall back to session auth
        if let Ok(auth_session) = AuthSession::from_request_parts(parts, state).await {
            if let Some(user) = auth_session.user {
                return Ok(AuthenticatedCaller {
                    user: Some(user),
                    via_token: false,
                });
            }
        }

        // 3. Unauthenticated
        Ok(AuthenticatedCaller {
            user: None,
            via_token: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_raw_token_has_prefix() {
        let token = generate_raw_token();
        assert!(token.starts_with("df_"), "Token must start with df_ prefix");
        // df_ (3 chars) + 96 hex chars = 99 chars total
        assert_eq!(token.len(), 3 + TOKEN_RANDOM_BYTES * 2);
    }

    #[test]
    fn test_generate_raw_token_unique() {
        let t1 = generate_raw_token();
        let t2 = generate_raw_token();
        assert_ne!(t1, t2, "Two generated tokens must be different");
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "df_aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd11223344556677889900aabbccdd1122";
        let h1 = hash_token(token);
        let h2 = hash_token(token);
        assert_eq!(h1, h2, "Hashing the same token must produce the same hash");
        // SHA-256 output is 64 hex chars
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let h1 = hash_token("df_aaaa");
        let h2 = hash_token("df_bbbb");
        assert_ne!(h1, h2, "Different tokens must produce different hashes");
    }

    #[test]
    fn test_token_prefix_extraction() {
        let token = "df_aabbccdd1122334455667788";
        let prefix = token_prefix(token);
        assert_eq!(prefix, "df_aabbccdd");
    }

    #[test]
    fn test_token_prefix_short_token() {
        let token = "df_ab";
        let prefix = token_prefix(token);
        assert_eq!(prefix, "df_ab");
    }
}
