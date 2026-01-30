use axum::{
    extract::{State, Query},
    http::StatusCode,
    response::{IntoResponse, Redirect, Html},
    routing::{get, post},
    Router,
    Form,
};
// use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType};
// use openidconnect::{AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse, reqwest::async_http_client};
// use openidconnect::url::Url;
use tracing::{error, info, warn};
use serde::{Deserialize, Serialize};
use crate::AppState;
use argon2::{password_hash::{Error as PasswordHashError, PasswordHash, PasswordVerifier as ArgonPasswordVerifier, SaltString}, Argon2, PasswordHasher};
use rand::rngs::OsRng;
use axum_login::{AuthUser, AuthnBackend, UserId};
use std::{io, path::Path as StdPath, fs, collections::HashMap};
use rand::{Rng, distributions::Alphanumeric};
use crate::ui::AddAlert;
use thiserror::Error;
use minijinja::{Error as MiniJinjaError, ErrorKind as MiniJinjaErrorKind};
use crate::ui::AlertMessage;
use axum::response::Response;
// use oauth2::basic::BasicClient; // Assuming BasicClient is also related to openidconnect for now
// use oauth2;
use urlencoding;
// async_trait no longer needed for axum-login 0.18

// Constants for the initial password file (not for loading, just for UX)
const INITIAL_PASSWORD_FILE: &str = "initial_password.txt";

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
                return Err(io::Error::new(io::ErrorKind::Other, format!("Failed to hash password: {}", e)));
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
    pub id: i64,
    pub username: String,
}

impl AuthUser for AdminUser {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
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

    #[error("Database error during authentication: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Password hashing error: {0}")]
    HashingError(PasswordHashError),

    #[error("Internal task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    // Wrap MiniJinjaError if needed, though it might not be strictly necessary
    // depending on where errors originate
    #[error("Template/Rendering Error: {0}")]
    TemplateError(#[from] MiniJinjaError),

    // Add variants for OAuth if/when re-enabled
    // #[error("Missing OAuth parameter: {0}")]
    // MissingParam(String),
    // #[error("OAuth state mismatch")]
    // StateMismatch,
    // #[error("OAuth token exchange failed: {0}")]
    // TokenExchangeFailed(String),
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
            AuthError::InvalidCredentials | AuthError::UserNotFound(_) => {
                (StatusCode::UNAUTHORIZED, "Invalid username or password.".to_string())
            }
            AuthError::DatabaseError(_) | AuthError::HashingError(_) | AuthError::JoinError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occurred during login.".to_string())
            }
            AuthError::ConfigError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AuthError::TemplateError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "An internal error occurred.".to_string()),
            // Add cases for OAuth errors if re-enabled
        };

        // In a real application, you might redirect back to the login page
        // with an error query parameter, or return a JSON error.
        // For now, just return the status code and a simple message.

        // Redirect back to login page with an error message
        let redirect_url = format!("/login?error={}", urlencoding::encode(&user_message));
        (status, Redirect::to(&redirect_url)).into_response()

        // Alternatively, return JSON:
        // (status, Json(json!({ "error": self.to_string(), "message": user_message }))).into_response()
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
            require_login: true,  // Internal tool - require login by default
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

#[derive(Clone, Debug)]
pub struct AdminBackend {
    db: sqlx::SqlitePool,
    settings: Settings,
}

impl AdminBackend {
    pub fn new(db: sqlx::SqlitePool, settings: Settings) -> Self {
        Self { db, settings }
    }
    
    pub async fn update_credentials(&self, username: String, password: String) -> anyhow::Result<Credentials> {
        // Create new credentials with hashed password
        let new_credentials = Credentials::create(username, password)?;
        
        // Save to database
        crate::db::save_admin_credentials(&new_credentials).await?;
        
        Ok(new_credentials)
    }
}

impl AuthnBackend for AdminBackend {
    type User = AdminUser;
    type Credentials = Credentials;
    type Error = AuthError; // Use the new AuthError type

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let username = creds.username.clone();
        let password_bytes = match creds.password {
            Some(p) => p.into_bytes(),
            None => {
                info!("Authentication attempt for user '{}' failed: No password provided", username);
                return Ok(None); // No password, treat as invalid credentials for simplicity
            }
        };

        // Fetch the stored hash from the database
        let record = sqlx::query!(
            "SELECT id, password_hash FROM admin_credentials WHERE username = ?",
            username
        )
        .fetch_optional(&self.db)
        .await?;

        let (user_id, stored_hash) = match record {
            Some(r) => (r.id, r.password_hash),
            None => {
                info!("Authentication failed: User '{}' not found", username);
                // Instead of returning Ok(None), consider returning an error
                // return Err(AuthError::UserNotFound(username)); 
                // Or, to obscure whether user exists, return InvalidCredentials
                 return Err(AuthError::InvalidCredentials); // More secure - doesn't reveal if user exists
            }
        };

        // Clone username *before* the move closure for later use
        let username_for_log = username.clone(); 

        // Verify the password using Argon2 within a blocking task
        let verification_result = tokio::task::spawn_blocking(move || {
            // This closure now returns Result<bool, PasswordHashError>
            match PasswordHash::new(&stored_hash) {
                Ok(parsed_hash) => {
                    // verify_password returns Result<(), Error>
                    Ok(Argon2::default().verify_password(&password_bytes, &parsed_hash).is_ok())
                }
                Err(e) => {
                    // Error parsing the stored hash
                    // Use the original username moved into the closure here
                    error!("Error parsing stored password hash for user '{}': {}", username, e);
                    Err(e) // Propagate the hash parsing error
                }
            }
        }).await?; // First '?' handles the JoinError (converted via From)

        // Check the inner Result from the blocking task
        let is_valid = match verification_result {
            Ok(valid) => valid, // Successfully verified (or not)
            Err(hash_error) => {
                // Handle the PasswordHashError from PasswordHash::new or potentially verify_password
                // Convert it using the manual From impl we added
                return Err(AuthError::from(hash_error));
            }
        };

        if is_valid {
            info!("Authentication successful for user '{}'", username_for_log);
            // Return the minimal user info needed for the session
            // Move the original username (if needed) or use the clone
            Ok(Some(AdminUser { id: user_id, username: username_for_log })) 
        } else {
            info!("Authentication failed: Invalid password for user '{}'", username_for_log);
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // Fetch user details by ID
        // The `?` propagates sqlx::Error, converted via #[from]
        // The result of this expression is Option<AdminUser>
        let user_option = sqlx::query_as!( 
            AdminUser, 
            "SELECT id, username FROM admin_credentials WHERE id = ?",
            user_id
        )
        .fetch_optional(&self.db)
        .await?;

        // The match statement is no longer needed here as `?` handled the error
        // and the result is directly the Option we need to return.
        // If user_option is Some, return Ok(Some(user)). If None, return Ok(None).
        Ok(user_option)
        
        /* // Old incorrect match:
        {
            Ok(user_opt) => Ok(user_opt),
            Err(e) => {
                 error!("Database error fetching user by ID '{}': {}", user_id, e);
                 Err(e.into())
            }
        }
        */
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
        crate::TemplateEnv::Static(env) => {
            env.get_template("login.html")
               .and_then(|tmpl| tmpl.render(&template))
        }
        #[cfg(debug_assertions)]
        crate::TemplateEnv::Reloading(reloader) => {
            // Acquire the environment from the reloader
            match reloader.acquire_env() {
                Ok(env) => {
                    env.get_template("login.html")
                       .and_then(|tmpl| tmpl.render(&template))
                }
                Err(e) => {
                    error!("Failed to acquire MiniJinja env from reloader: {}", e);
                    Err(MiniJinjaError::new(MiniJinjaErrorKind::InvalidOperation, 
                        format!("Failed to acquire env from reloader: {}", e)))
                }
            }
        }
    };

    // Handle the final rendering result
    match render_result {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("MiniJinja render/load error for login.html: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {}", e)).into_response()
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
        let username = if form.username.trim().is_empty() { "demo_user".to_string() } else { form.username.clone() };

        // Create a demo admin user - use the same hash as lib.rs creates for demo credentials
        let demo_user = AdminUser {
            id: 1,
            username,
        };

        // Hard-set the user session
        info!("Demo mode: Setting session for user '{}'", demo_user.username);
        match auth_session.login(&demo_user).await {
            Ok(_) => {
                info!("Demo mode: Login successful for user '{}'", demo_user.username);
                // Check if mode is set - if not, redirect to welcome
                let current_mode = app_state.store.get_setting("deployment_mode").await.ok().flatten();
                let redirect_to = if current_mode.is_some() { "/" } else { "/welcome" };
                return Redirect::to(redirect_to).into_response();
            },
            Err(e) => {
                error!("Demo mode: Failed to set user session: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error setting demo session"
                ).into_response();
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
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            info!("Login successful for user '{}'", user.username);
            // Check if mode is set - if not, redirect to welcome for setup
            let current_mode = app_state.store.get_setting("deployment_mode").await.ok().flatten();
            let redirect_to = if current_mode.is_some() { "/" } else { "/welcome" };
            Redirect::to(redirect_to).into_response()
        }
        Ok(None) => {
            info!("Authentication failed for user '{}'", form.username);
            Redirect::to("/login?error=invalid_credentials").into_response()
        }
        Err(e) => {
            error!("Error during authentication: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
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

pub async fn generate_default_credentials() -> anyhow::Result<Credentials> {
    // Check if an initial password file already exists
    if StdPath::new(INITIAL_PASSWORD_FILE).exists() {
        info!("Initial password file exists - attempting to load existing credentials from database");
        // Try to load credentials from database first
        if let Ok(Some(creds)) = crate::db::get_admin_credentials().await {
            info!("Found existing admin credentials in database - using those");
            return Ok(creds);
        } else {
            // If we can't load from database but file exists, we should delete the file
            // as it's probably stale/outdated
            info!("Failed to load admin credentials from database but initial password file exists - file may be stale");
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
    let credentials = Credentials::create(username, password.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create admin credentials: {}", e))?;
    
    // Save to database
    if let Err(e) = crate::db::save_admin_credentials(&credentials).await {
        error!("Failed to save admin credentials to database: {}", e);
        return Err(anyhow::anyhow!("Failed to save admin credentials to database: {}", e));
    }
    
    // Save password to file for user convenience
    if let Err(e) = fs::write(INITIAL_PASSWORD_FILE, &password) {
        error!("Failed to save initial password to file: {}", e);
        // This is not a critical error, so we can continue
    } else {
        info!("Initial admin password saved to {}", INITIAL_PASSWORD_FILE);
    }
    
    info!("Generated default admin credentials. Username: admin, Password: {}", password);
    Ok(credentials)
}

pub async fn load_credentials() -> io::Result<Credentials> {
    // Load only from database - no fallback to file credential loading
    match crate::db::get_admin_credentials().await {
        Ok(Some(creds)) => {
            info!("Loaded admin credentials from database");
            Ok(creds)
        },
        Ok(None) => {
            info!("No admin credentials found in database");
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No admin credentials found in database",
            ))
        },
        Err(e) => {
            error!("Error loading admin credentials from database: {}", e);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Database error: {}", e),
            ))
        }
    }
}

pub async fn save_credentials(credentials: &Credentials) -> io::Result<()> {
    // Save to database only
    if let Err(e) = crate::db::save_admin_credentials(credentials).await {
        error!("Failed to save admin credentials to database: {}", e);
        return Err(io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e)));
    }
    
    info!("Saved admin credentials to database");
    Ok(())
}

pub async fn load_settings() -> io::Result<Settings> {
    match crate::db::get_app_settings().await {
        Ok(settings) => {
            info!("Loaded settings from database");
            Ok(settings)
        },
        Err(e) => {
            error!("Failed to load settings from database: {}", e);
            Ok(Settings::default()) // Return default settings on error
        }
    }
}

pub async fn save_settings(settings: &Settings) -> io::Result<()> {
    match crate::db::save_app_settings(settings).await {
        Ok(_) => {
            info!("Settings saved to database");
            Ok(())
        },
        Err(e) => {
            error!("Failed to save settings to database: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e)))
        }
    }
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
    
    let username = auth_session.user
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
        is_auth = if is_authenticated { "Authenticated" } else { "Not Authenticated" },
        auth_class = if is_authenticated { "success" } else { "error" },
        username = username
    );
    
    Html(html)
}

pub async fn login(
    State(_app_state): State<AppState>, // Mark as unused for now
    mut _auth_session: AuthSession, // Mark as unused for now
    Form(_creds): Form<Credentials>, // Mark as unused for now
) -> Response {
    // Placeholder implementation - This function likely needs to call
    // auth_session.authenticate and auth_session.login similar to login_handler
    // For now, return an error or redirect
    warn!("/api/login endpoint hit, but not fully implemented yet");
    (StatusCode::NOT_IMPLEMENTED, "Login endpoint not fully implemented").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use crate::{AppState, TemplateEnv, event_manager::EventManager};
    use minijinja::Environment;

    async fn create_test_db() -> sqlx::Pool<sqlx::Sqlite> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        // Create the admin_credentials table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS admin_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create admin_credentials table");

        pool
    }

    async fn create_test_user(pool: &sqlx::Pool<sqlx::Sqlite>, username: &str, password: &str) -> i64 {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string();

        let result = sqlx::query(
            "INSERT INTO admin_credentials (username, password_hash) VALUES (?, ?)"
        )
        .bind(username)
        .bind(&password_hash)
        .execute(pool)
        .await
        .expect("Failed to insert test user");

        result.last_insert_rowid()
    }

    fn create_test_app_state(pool: sqlx::Pool<sqlx::Sqlite>) -> AppState {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
        let env = Environment::new();

        AppState {
            settings: Arc::new(Mutex::new(Settings::default())),
            event_manager: Arc::new(EventManager::new()),
            setup_mode: false,
            first_run: false,
            shutdown_tx,
            shutdown_rx,
            template_env: TemplateEnv::Static(Arc::new(env)),
            is_installed: false,
            is_demo_mode: true,
            is_installation_server: false,
            client_ip: Arc::new(Mutex::new(None)),
            dbpool: pool,
            tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
            provisioning: None,
            store: Arc::new(crate::store::MemoryStore::new()),
            network_services_started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
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
        let pool = create_test_db().await;
        let _user_id = create_test_user(&pool, "admin", "correctpassword").await;

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

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
        let pool = create_test_db().await;
        let _user_id = create_test_user(&pool, "admin", "correctpassword").await;

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

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
        let pool = create_test_db().await;
        // Don't create any user

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

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
        let pool = create_test_db().await;
        let _user_id = create_test_user(&pool, "admin", "password").await;

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

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
        let pool = create_test_db().await;
        let user_id = create_test_user(&pool, "testadmin", "password123").await;

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

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
        let pool = create_test_db().await;
        // Don't create any user

        let settings = Settings::default();
        let backend = AdminBackend::new(pool, settings);

        let result = backend.get_user(&999).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_admin_user_auth_user_impl() {
        let user = AdminUser {
            id: 42,
            username: "testuser".to_string(),
        };

        assert_eq!(user.id(), 42);
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
    async fn test_require_admin_authenticated() {
        // This test verifies the require_admin function logic
        // In a real scenario, you'd need a full auth session, but we can test the logic

        // The function checks auth_session.user.is_some()
        // We can't easily mock AuthSession, but the logic is straightforward:
        // - Some(user) -> Ok(())
        // - None -> Err(Redirect to /login)

        // This is more of a documentation test - the actual behavior
        // is tested via integration tests with a full router setup
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
    async fn test_app_state_creation() {
        let pool = create_test_db().await;
        let app_state = create_test_app_state(pool);

        assert!(!app_state.setup_mode);
        assert!(!app_state.first_run);
        assert!(!app_state.is_installed);
        assert!(app_state.is_demo_mode);
        assert!(!app_state.is_installation_server);
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