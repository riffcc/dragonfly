use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
// use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType};
// use openidconnect::{AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse, reqwest::async_http_client};
// use openidconnect::url::Url;
use crate::AppState;
use crate::ui::AddAlert;
use crate::ui::AlertMessage;
use argon2::{
    Argon2, PasswordHasher,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordVerifier as ArgonPasswordVerifier,
        SaltString,
    },
};
use axum::response::Response;
use axum_login::{AuthUser, AuthnBackend, UserId};
use minijinja::{Error as MiniJinjaError, ErrorKind as MiniJinjaErrorKind};
use rand::rngs::OsRng;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io, path::Path as StdPath};
use thiserror::Error;
use tracing::{error, info, warn};
// use oauth2::basic::BasicClient; // Assuming BasicClient is also related to openidconnect for now
// use oauth2;
use urlencoding;
// async_trait no longer needed for axum-login 0.18

// Constants for the initial password file (not for loading, just for UX)
const INITIAL_PASSWORD_FILE: &str = "/var/lib/dragonfly/initial_password.txt";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub password_hash: String,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            username: "admin".to_string(),
            password: None,
            password_hash: String::new(),
        }
    }
}

impl Credentials {
    pub fn create(username: String, password: String) -> io::Result<Self> {
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = match Argon2::default().hash_password(password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to hash password: {}", e),
                ));
            }
        };

        Ok(Self {
            username,
            password: None, // Don't store plaintext password
            password_hash,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AdminUser {
    pub id: String, // UUID as string
    pub username: String,
}

impl AuthUser for AdminUser {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.id.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.username.as_bytes()
    }
}

// Define a custom error type for the AuthnBackend
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials provided.")]
    InvalidCredentials,

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Store error during authentication: {0}")]
    StoreError(String),

    #[error("Password hashing error: {0}")]
    HashingError(PasswordHashError),

    #[error("Internal task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Template/Rendering Error: {0}")]
    TemplateError(#[from] MiniJinjaError),
}

// Manually implement From for argon2::password_hash::Error
impl From<PasswordHashError> for AuthError {
    fn from(err: PasswordHashError) -> Self {
        // Log the specific hashing error for debugging if needed
        error!("Password hashing error occurred: {}", err);
        AuthError::HashingError(err)
    }
}

// Implement IntoResponse for AuthError to handle login failures gracefully
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        error!("Authentication/Authorization Error: {}", self);

        // Determine the HTTP status code and potentially a user-facing message
        let (status, user_message) = match self {
            AuthError::InvalidCredentials | AuthError::UserNotFound(_) => (
                StatusCode::UNAUTHORIZED,
                "Invalid username or password.".to_string(),
            ),
            AuthError::StoreError(_) | AuthError::HashingError(_) | AuthError::JoinError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal server error occurred during login.".to_string(),
            ),
            AuthError::ConfigError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AuthError::TemplateError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal error occurred.".to_string(),
            ),
        };

        // Redirect back to login page with an error message
        let redirect_url = format!("/login?error={}", urlencoding::encode(&user_message));
        (status, Redirect::to(&redirect_url)).into_response()
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub require_login: bool,
    pub default_os: Option<String>,
    pub setup_completed: bool,
    pub admin_username: String,
    pub admin_password_hash: String,
    pub admin_email: String,
    pub oauth_enabled: bool,
    pub oauth_provider: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,

    // Add the missing Proxmox fields
    pub proxmox_host: Option<String>,
    pub proxmox_username: Option<String>,
    pub proxmox_password: Option<String>,
    pub proxmox_port: Option<u16>,
    pub proxmox_skip_tls_verify: Option<bool>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            require_login: true, // Internal tool - require login by default
            default_os: None,
            setup_completed: false,
            admin_username: "admin".to_string(),
            admin_password_hash: String::new(), // Default to empty, should be set
            admin_email: String::new(),
            oauth_enabled: false,
            oauth_provider: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            proxmox_host: None,
            proxmox_username: None,
            proxmox_password: None,
            proxmox_port: None,
            proxmox_skip_tls_verify: Some(false),
        }
    }
}

#[derive(Clone)]
pub struct AdminBackend {
    store: std::sync::Arc<dyn crate::store::v1::Store>,
}

impl std::fmt::Debug for AdminBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBackend").finish()
    }
}

impl AdminBackend {
    pub fn new(store: std::sync::Arc<dyn crate::store::v1::Store>) -> Self {
        Self { store }
    }

    pub async fn update_credentials(
        &self,
        username: String,
        password: String,
    ) -> anyhow::Result<Credentials> {
        // Create new credentials with hashed password
        let new_credentials = Credentials::create(username.clone(), password)?;

        // Find existing user by username or create new
        let now = chrono::Utc::now().to_rfc3339();
        let user = if let Ok(Some(existing)) = self.store.get_user_by_username(&username).await {
            crate::store::v1::User {
                id: existing.id,
                username,
                password_hash: new_credentials.password_hash.clone(),
                created_at: existing.created_at,
                updated_at: now,
            }
        } else {
            crate::store::v1::User {
                id: uuid::Uuid::now_v7(),
                username,
                password_hash: new_credentials.password_hash.clone(),
                created_at: now.clone(),
                updated_at: now,
            }
        };

        self.store
            .put_user(&user)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to save user: {}", e))?;

        Ok(new_credentials)
    }
}

impl AuthnBackend for AdminBackend {
    type User = AdminUser;
    type Credentials = Credentials;
    type Error = AuthError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let username = creds.username.clone();
        let password_bytes = match creds.password {
            Some(p) => p.into_bytes(),
            None => {
                info!(
                    "Authentication attempt for user '{}' failed: No password provided",
                    username
                );
                return Ok(None);
            }
        };

        // Fetch the stored user from SQLite Store
        let user = match self.store.get_user_by_username(&username).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                info!("Authentication failed: User '{}' not found", username);
                return Err(AuthError::InvalidCredentials);
            }
            Err(e) => {
                error!("Database error during authentication: {}", e);
                return Err(AuthError::ConfigError(e.to_string()));
            }
        };

        let user_id = user.id.to_string();
        let stored_hash = user.password_hash.clone();
        let username_for_log = username.clone();

        // Verify the password using Argon2 within a blocking task
        let verification_result =
            tokio::task::spawn_blocking(move || match PasswordHash::new(&stored_hash) {
                Ok(parsed_hash) => Ok(Argon2::default()
                    .verify_password(&password_bytes, &parsed_hash)
                    .is_ok()),
                Err(e) => {
                    error!(
                        "Error parsing stored password hash for user '{}': {}",
                        username, e
                    );
                    Err(e)
                }
            })
            .await?;

        let is_valid = match verification_result {
            Ok(valid) => valid,
            Err(hash_error) => {
                return Err(AuthError::from(hash_error));
            }
        };

        if is_valid {
            info!("Authentication successful for user '{}'", username_for_log);
            Ok(Some(AdminUser {
                id: user_id,
                username: username_for_log,
            }))
        } else {
            info!(
                "Authentication failed: Invalid password for user '{}'",
                username_for_log
            );
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // Parse UUID from string ID
        let uuid = match uuid::Uuid::parse_str(user_id) {
            Ok(id) => id,
            Err(_) => return Ok(None),
        };

        // Fetch user details by ID from Store
        let user_option = match self.store.get_user(uuid).await {
            Ok(Some(user)) => Some(AdminUser {
                id: user.id.to_string(),
                username: user.username,
            }),
            Ok(None) => None,
            Err(e) => {
                error!("Database error fetching user by ID '{}': {}", user_id, e);
                return Err(AuthError::ConfigError(e.to_string()));
            }
        };

        Ok(user_option)
    }
}

pub type AuthSession = axum_login::AuthSession<AdminBackend>;

pub fn auth_router() -> Router<crate::AppState> {
    Router::new()
        .route("/login", get(login_page))
        .route("/login", post(login_handler))
        .route("/logout", post(logout))
        .route("/login-test", get(login_test_handler))
}

#[derive(Serialize)]
struct LoginTemplate {
    is_demo_mode: bool,
    error: Option<String>,
}

async fn login_page(
    State(app_state): State<crate::AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Check if we're in demo mode
    let is_demo_mode = std::env::var("DRAGONFLY_DEMO_MODE").is_ok();

    // Check for error parameter
    let error = params.get("error").cloned();
    if let Some(err) = &error {
        info!("Login page loaded with error: {}", err);
    }

    let template = LoginTemplate {
        is_demo_mode,
        error,
    };

    // Get the environment based on the mode (static or reloading)
    let render_result = match &app_state.template_env {
        crate::TemplateEnv::Static(env) => env
            .get_template("login.html")
            .and_then(|tmpl| tmpl.render(&template)),
        #[cfg(debug_assertions)]
        crate::TemplateEnv::Reloading(reloader) => {
            // Acquire the environment from the reloader
            match reloader.acquire_env() {
                Ok(env) => env
                    .get_template("login.html")
                    .and_then(|tmpl| tmpl.render(&template)),
                Err(e) => {
                    error!("Failed to acquire MiniJinja env from reloader: {}", e);
                    Err(MiniJinjaError::new(
                        MiniJinjaErrorKind::InvalidOperation,
                        format!("Failed to acquire env from reloader: {}", e),
                    ))
                }
            }
        }
    };

    // Handle the final rendering result
    match render_result {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("MiniJinja render/load error for login.html: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template error: {}", e),
            )
                .into_response()
        }
    }
}

async fn login_handler(
    State(app_state): State<AppState>,
    mut auth_session: AuthSession,
    Form(form): Form<LoginForm>,
) -> Response {
    // Check if we're in demo mode
    let is_demo_mode = std::env::var("DRAGONFLY_DEMO_MODE").is_ok();

    if is_demo_mode {
        // In demo mode, simply create a demo user and force-login without authentication
        info!("Demo mode: accepting any credentials for login");

        // Create a simple admin user
        let username = if form.username.trim().is_empty() {
            "demo_user".to_string()
        } else {
            form.username.clone()
        };

        // Create a demo admin user - use a deterministic UUID for demo mode
        let demo_user = AdminUser {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            username,
        };

        // Hard-set the user session
        info!(
            "Demo mode: Setting session for user '{}'",
            demo_user.username
        );
        match auth_session.login(&demo_user).await {
            Ok(_) => {
                info!(
                    "Demo mode: Login successful for user '{}'",
                    demo_user.username
                );
                // Check if mode is set - if not, redirect to welcome
                let current_mode = app_state
                    .store
                    .get_setting("deployment_mode")
                    .await
                    .ok()
                    .flatten();
                let redirect_to = if current_mode.is_some() {
                    "/"
                } else {
                    "/welcome"
                };
                return Redirect::to(redirect_to).into_response();
            }
            Err(e) => {
                error!("Demo mode: Failed to set user session: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error setting demo session",
                )
                    .into_response();
            }
        }
    }

    // Regular authentication flow for non-demo mode
    info!("Processing login request for user '{}'", form.username);

    let credentials = Credentials {
        username: form.username.clone(),
        password: Some(form.password),
        password_hash: String::new(),
    };

    // Try to authenticate the user
    match auth_session.authenticate(credentials).await {
        Ok(Some(user)) => {
            // Successfully authenticated, set up the session
            if let Err(e) = auth_session.login(&user).await {
                error!("Failed to create session after successful auth: {}", e);
                return Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to create session. Please try again."
                }))
                .into_response();
            }

            info!("Login successful for user '{}'", user.username);
            // Check if mode is set - if not, redirect to welcome for setup
            let current_mode = app_state
                .store
                .get_setting("deployment_mode")
                .await
                .ok()
                .flatten();
            let redirect_to = if current_mode.is_some() {
                "/"
            } else {
                "/welcome"
            };
            Json(serde_json::json!({
                "success": true,
                "redirect": redirect_to
            }))
            .into_response()
        }
        Ok(None) => {
            info!("Authentication failed for user '{}'", form.username);
            Json(serde_json::json!({
                "success": false,
                "error": "Invalid username or password."
            }))
            .into_response()
        }
        Err(e) => {
            // Check if this is an InvalidCredentials error (wrapped by axum_login)
            let err_str = format!("{}", e);
            if err_str.contains("Invalid credentials") {
                info!(
                    "Authentication failed for user '{}': invalid credentials",
                    form.username
                );
                Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid username or password."
                }))
                .into_response()
            } else {
                error!("Error during authentication: {}", e);
                Json(serde_json::json!({
                    "success": false,
                    "error": "Internal server error. Please try again."
                }))
                .into_response()
            }
        }
    }
}

async fn logout(mut auth_session: AuthSession) -> Response {
    match auth_session.logout().await {
        Ok(_) => Redirect::to("/login")
            .into_response()
            .add_alert(AlertMessage::success("Successfully logged out.")),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR
            .into_response()
            .add_alert(AlertMessage::error("Failed to log out.")),
    }
}

pub async fn generate_default_credentials(
    store: &std::sync::Arc<dyn crate::store::v1::Store>,
) -> anyhow::Result<Credentials> {
    // Check if an initial password file already exists
    if StdPath::new(INITIAL_PASSWORD_FILE).exists() {
        info!("Initial password file exists - attempting to load existing credentials from store");
        // Try to load credentials from store first
        if let Ok(Some(user)) = store.get_user_by_username("admin").await {
            info!("Found existing admin credentials in store - using those");
            return Ok(Credentials {
                username: user.username,
                password: None,
                password_hash: user.password_hash,
            });
        } else {
            // If we can't load from store but file exists, we should delete the file
            // as it's probably stale/outdated
            info!(
                "Failed to load admin credentials from store but initial password file exists - file may be stale"
            );
            if let Err(e) = fs::remove_file(INITIAL_PASSWORD_FILE) {
                error!("Failed to remove stale initial password file: {}", e);
            }
        }
    }

    info!("Generating new admin credentials");
    let username = "admin".to_string();
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    // Create new credentials with proper error handling
    let credentials = Credentials::create(username.clone(), password.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create admin credentials: {}", e))?;

    // Save to Store
    let now = chrono::Utc::now().to_rfc3339();
    let user = crate::store::v1::User {
        id: uuid::Uuid::now_v7(),
        username,
        password_hash: credentials.password_hash.clone(),
        created_at: now.clone(),
        updated_at: now,
    };

    if let Err(e) = store.put_user(&user).await {
        error!("Failed to save admin credentials to store: {}", e);
        return Err(anyhow::anyhow!(
            "Failed to save admin credentials to store: {}",
            e
        ));
    }

    // Save password to file for user convenience
    if let Err(e) = fs::write(INITIAL_PASSWORD_FILE, &password) {
        error!("Failed to save initial password to file: {}", e);
        // This is not a critical error, so we can continue
    } else {
        info!("Initial admin password saved to {}", INITIAL_PASSWORD_FILE);
    }

    info!(
        "Generated default admin credentials. Username: admin, Password: {}",
        password
    );
    Ok(credentials)
}

pub async fn load_credentials(
    store: &std::sync::Arc<dyn crate::store::v1::Store>,
) -> io::Result<Credentials> {
    // Load from Store - get the admin user
    match store.get_user_by_username("admin").await {
        Ok(Some(user)) => {
            info!("Loaded admin credentials from store");
            Ok(Credentials {
                username: user.username,
                password: None,
                password_hash: user.password_hash,
            })
        }
        Ok(None) => {
            info!("No admin credentials found in store");
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No admin credentials found in store",
            ))
        }
        Err(e) => {
            error!("Error loading admin credentials from store: {}", e);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Store error: {}", e),
            ))
        }
    }
}

pub async fn save_credentials(
    store: &std::sync::Arc<dyn crate::store::v1::Store>,
    credentials: &Credentials,
) -> io::Result<()> {
    // Get or create user
    let now = chrono::Utc::now().to_rfc3339();
    let user = if let Ok(Some(existing)) = store.get_user_by_username(&credentials.username).await {
        crate::store::v1::User {
            id: existing.id,
            username: credentials.username.clone(),
            password_hash: credentials.password_hash.clone(),
            created_at: existing.created_at,
            updated_at: now,
        }
    } else {
        crate::store::v1::User {
            id: uuid::Uuid::now_v7(),
            username: credentials.username.clone(),
            password_hash: credentials.password_hash.clone(),
            created_at: now.clone(),
            updated_at: now,
        }
    };

    if let Err(e) = store.put_user(&user).await {
        error!("Failed to save admin credentials to store: {}", e);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Store error: {}", e),
        ));
    }

    info!("Saved admin credentials to store");
    Ok(())
}

pub fn require_admin(auth_session: &AuthSession) -> Result<(), Response> {
    match auth_session.user {
        Some(_) => Ok(()),
        None => Err(Redirect::to("/login").into_response()),
    }
}

async fn login_test_handler(auth_session: AuthSession) -> impl IntoResponse {
    let is_demo_mode = std::env::var("DRAGONFLY_DEMO_MODE").is_ok();
    let is_authenticated = auth_session.user.is_some();

    let username = auth_session
        .user
        .as_ref()
        .map(|user| user.username.clone())
        .unwrap_or_else(|| "Not logged in".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
        <html>
        <head>
            <title>Login Test</title>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 2rem; }}
                .container {{ max-width: 800px; margin: 0 auto; }}
                .panel {{ background-color: #f5f5f5; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }}
                .demo {{ background-color: #fff3cd; }}
                h1 {{ color: #333; }}
                .label {{ font-weight: bold; margin-right: 0.5rem; }}
                .success {{ color: green; }}
                .error {{ color: red; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Login Test Page</h1>
                
                <div class="panel {demo_class}">
                    <div><span class="label">Demo Mode:</span> {is_demo}</div>
                    <div><span class="label">Session Status:</span> 
                         <span class="{auth_class}">{is_auth}</span>
                    </div>
                    <div><span class="label">Username:</span> {username}</div>
                </div>
                
                <div>
                    <a href="/">Go to Dashboard</a> | 
                    <a href="/login">Go to Login</a>
                </div>
            </div>
        </body>
        </html>
        "#,
        demo_class = if is_demo_mode { "demo" } else { "" },
        is_demo = if is_demo_mode { "Enabled" } else { "Disabled" },
        is_auth = if is_authenticated {
            "Authenticated"
        } else {
            "Not Authenticated"
        },
        auth_class = if is_authenticated { "success" } else { "error" },
        username = username
    );

    Html(html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Create a test store with a user
    async fn create_test_store_with_user(
        username: &str,
        password: &str,
    ) -> (Arc<dyn crate::store::v1::Store>, String) {
        let store: Arc<dyn crate::store::v1::Store> =
            Arc::new(crate::store::v1::MemoryStore::new());

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string();

        let user_id = uuid::Uuid::now_v7();
        let now = chrono::Utc::now().to_rfc3339();
        let user = crate::store::v1::User {
            id: user_id,
            username: username.to_string(),
            password_hash,
            created_at: now.clone(),
            updated_at: now,
        };

        store
            .put_user(&user)
            .await
            .expect("Failed to create test user");
        (store, user_id.to_string())
    }

    #[tokio::test]
    async fn test_credentials_create() {
        let creds = Credentials::create("testuser".to_string(), "testpass123".to_string())
            .expect("Failed to create credentials");

        assert_eq!(creds.username, "testuser");
        assert!(creds.password.is_none()); // Password should not be stored in plaintext
        assert!(!creds.password_hash.is_empty());
        assert!(creds.password_hash.starts_with("$argon2")); // Argon2 hash format
    }

    #[tokio::test]
    async fn test_credentials_default() {
        let creds = Credentials::default();
        assert_eq!(creds.username, "admin");
        assert!(creds.password.is_none());
        assert!(creds.password_hash.is_empty());
    }

    #[tokio::test]
    async fn test_admin_backend_authenticate_success() {
        let (store, _user_id) = create_test_store_with_user("admin", "correctpassword").await;
        let backend = AdminBackend::new(store);

        let credentials = Credentials {
            username: "admin".to_string(),
            password: Some("correctpassword".to_string()),
            password_hash: String::new(),
        };

        let result = backend.authenticate(credentials).await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.username, "admin");
    }

    #[tokio::test]
    async fn test_admin_backend_authenticate_wrong_password() {
        let (store, _user_id) = create_test_store_with_user("admin", "correctpassword").await;
        let backend = AdminBackend::new(store);

        let credentials = Credentials {
            username: "admin".to_string(),
            password: Some("wrongpassword".to_string()),
            password_hash: String::new(),
        };

        let result = backend.authenticate(credentials).await;
        // Wrong password should return InvalidCredentials error
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::InvalidCredentials => {}
            other => panic!("Expected InvalidCredentials, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_admin_backend_authenticate_user_not_found() {
        let store: Arc<dyn crate::store::v1::Store> =
            Arc::new(crate::store::v1::MemoryStore::new());
        let backend = AdminBackend::new(store);

        let credentials = Credentials {
            username: "nonexistent".to_string(),
            password: Some("anypassword".to_string()),
            password_hash: String::new(),
        };

        let result = backend.authenticate(credentials).await;
        // Non-existent user should return InvalidCredentials (for security - don't reveal user existence)
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::InvalidCredentials => {}
            other => panic!("Expected InvalidCredentials, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_admin_backend_authenticate_no_password() {
        let (store, _user_id) = create_test_store_with_user("admin", "password").await;
        let backend = AdminBackend::new(store);

        let credentials = Credentials {
            username: "admin".to_string(),
            password: None, // No password provided
            password_hash: String::new(),
        };

        let result = backend.authenticate(credentials).await;
        assert!(result.is_ok());
        // No password should return None (not authenticated)
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_admin_backend_get_user() {
        let (store, user_id) = create_test_store_with_user("testadmin", "password123").await;
        let backend = AdminBackend::new(store);

        let result = backend.get_user(&user_id).await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, "testadmin");
    }

    #[tokio::test]
    async fn test_admin_backend_get_user_not_found() {
        let store: Arc<dyn crate::store::v1::Store> =
            Arc::new(crate::store::v1::MemoryStore::new());
        let backend = AdminBackend::new(store);

        let nonexistent_id = uuid::Uuid::now_v7().to_string();
        let result = backend.get_user(&nonexistent_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_admin_user_auth_user_impl() {
        let user = AdminUser {
            id: "test-uuid-12345".to_string(),
            username: "testuser".to_string(),
        };

        assert_eq!(user.id(), "test-uuid-12345");
        assert_eq!(user.session_auth_hash(), b"testuser");
    }

    #[tokio::test]
    async fn test_settings_default() {
        let settings = Settings::default();
        assert!(settings.require_login); // Internal tool - require login by default
        assert!(settings.default_os.is_none());
        assert!(!settings.setup_completed);
        assert_eq!(settings.admin_username, "admin");
        assert!(settings.admin_password_hash.is_empty());
        assert!(settings.admin_email.is_empty());
        assert!(!settings.oauth_enabled);
        assert!(settings.oauth_provider.is_none());
        assert!(settings.oauth_client_id.is_none());
        assert!(settings.oauth_client_secret.is_none());
        assert!(settings.proxmox_host.is_none());
        assert!(settings.proxmox_username.is_none());
        assert!(settings.proxmox_password.is_none());
        assert!(settings.proxmox_port.is_none());
        assert_eq!(settings.proxmox_skip_tls_verify, Some(false));
    }

    #[tokio::test]
    async fn test_auth_error_display() {
        let err = AuthError::InvalidCredentials;
        assert_eq!(err.to_string(), "Invalid credentials provided.");

        let err = AuthError::UserNotFound("testuser".to_string());
        assert_eq!(err.to_string(), "User not found: testuser");

        let err = AuthError::ConfigError("test config error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test config error");
    }

    #[tokio::test]
    async fn test_login_template_serialization() {
        let template = LoginTemplate {
            is_demo_mode: true,
            error: Some("test error".to_string()),
        };

        let json = serde_json::to_string(&template).expect("Failed to serialize");
        assert!(json.contains("\"is_demo_mode\":true"));
        assert!(json.contains("\"error\":\"test error\""));
    }

    #[tokio::test]
    async fn test_settings_default_requires_login() {
        // CRITICAL: Default settings must require login
        // This is an internal tool - unauthenticated access should never be allowed
        let settings = Settings::default();
        assert!(
            settings.require_login,
            "Settings::default() MUST have require_login = true. \
             This is a security-critical default for internal tools."
        );
    }
}
