use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::{Pool, Sqlite, SqlitePool, Row};
use tokio::sync::OnceCell;
use tracing::{error, info};
use uuid::Uuid;
use std::fs::{File, OpenOptions};
use std::path::Path;
use serde_json;

use dragonfly_common::models::{Machine, MachineStatus, RegisterRequest};
// Make re-exports public and correct the imported names
pub use dragonfly_common::models::{OsAssignmentRequest, RegisterResponse, ErrorResponse}; // Removed UpdateTagsRequest, corrected others
use crate::auth::{Credentials, Settings};

// Global database pool
static DB_POOL: OnceCell<Pool<Sqlite>> = OnceCell::const_new();

// Initialize the database connection pool
pub async fn init_db() -> Result<SqlitePool> {
    // Create or open the SQLite database file
    let db_path = "sqlite.db";
    
    // Check if the database file exists and create it if not
    let db_exists = std::path::Path::new(db_path).exists();
    if !db_exists {
        info!("Database file doesn't exist, creating it");
    }
    
    // Create SQLite connection string
    let database_url = format!("sqlite://{}?mode=rwc", db_path);
    
    // Connect to SQLite database
    let pool = SqlitePool::connect(&database_url)
        .await
        .map_err(|e| anyhow!("Failed to connect to SQLite database at {}: {}", database_url, e))?;
    
    // Initialize base tables for fresh installation
    create_base_tables(&pool).await?;
    
    // Run migrations
    migrate_db(&pool).await?;
    migrate_add_proxmox_settings(&pool).await?;
    
    // Store the pool globally - DB_POOL is previously defined as a OnceCell
    if let Err(e) = DB_POOL.set(pool.clone()) {
        return Err(anyhow!("Failed to set global database pool: {:?}", e));
    }
    
    info!("Database initialized successfully at {}", db_path);
    Ok(pool)
}

// Create base tables for a fresh installation
async fn create_base_tables(pool: &Pool<Sqlite>) -> Result<()> {
    // Check if machines table exists
    let result = sqlx::query(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='machines'"
    )
    .fetch_one(pool)
    .await?;
    
    let table_exists: i64 = result.get(0);
    
    // Create machines table if it doesn't exist
    if table_exists == 0 {
        info!("Creating machines table");
        sqlx::query(
            r#"
            CREATE TABLE machines (
                id TEXT PRIMARY KEY,
                mac_address TEXT NOT NULL,
                ip_address TEXT,
                hostname TEXT,
                status TEXT NOT NULL,
                os_choice TEXT,
                os_installed TEXT,
                disks TEXT NOT NULL,
                nameservers TEXT NOT NULL,
                memorable_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                bmc_credentials TEXT,
                installation_progress INTEGER DEFAULT 0,
                installation_step TEXT,
                last_deployment_duration INTEGER,
                cpu_model TEXT,
                cpu_cores INTEGER,
                total_ram_bytes INTEGER,
                proxmox_vmid INTEGER,
                proxmox_node TEXT,
                proxmox_cluster TEXT,
                is_proxmox_host BOOLEAN DEFAULT FALSE NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if admin_credentials table exists
    let result = sqlx::query(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_credentials'"
    )
    .fetch_one(pool)
    .await?;
    
    let table_exists: i64 = result.get(0);
    
    // Create admin_credentials table if it doesn't exist
    if table_exists == 0 {
        info!("Creating admin_credentials table");
        sqlx::query(
            r#"
            CREATE TABLE admin_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if app_settings table exists
    let result = sqlx::query(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_settings'"
    )
    .fetch_one(pool)
    .await?;
    
    let table_exists: i64 = result.get(0);
    
    // Create app_settings table if it doesn't exist
    if table_exists == 0 {
        info!("Creating app_settings table");
        sqlx::query(
            r#"
            CREATE TABLE app_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                require_login BOOLEAN NOT NULL DEFAULT 0,
                default_os TEXT,
                setup_completed BOOLEAN NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;
        
        // Insert default settings
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        sqlx::query(
            r#"
            INSERT INTO app_settings (id, require_login, setup_completed, created_at, updated_at)
            VALUES (1, 0, 0, ?, ?)
            "#,
        )
        .bind(&now_str)
        .bind(&now_str)
        .execute(pool)
        .await?;
    }
    
    Ok(())
}

// Get a reference to the database pool
// Make this public so handlers can access it
pub async fn get_pool() -> Result<&'static Pool<Sqlite>> {
    DB_POOL.get().ok_or_else(|| anyhow!("Database pool not initialized"))
}

// Apply database migrations
async fn migrate_db(pool: &Pool<Sqlite>) -> Result<()> {
    // Check if os_installed column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'os_installed'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add os_installed column if it doesn't exist
    if column_exists == 0 {
        info!("Adding os_installed column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN os_installed TEXT
            "#,
        )
        .execute(pool)
        .await?;
        
        // If we have ExistingOS machines, update their os_installed field
        let existing_os_machines = sqlx::query(
            r#"
            SELECT id, status FROM machines WHERE status LIKE 'ExistingOS:%' OR status = 'Existing OS'
            "#,
        )
        .fetch_all(pool)
        .await?;
        
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        for row in existing_os_machines {
            let id: String = row.get(0);
            let status_str: String = row.get(1);
            let os = if status_str.starts_with("ExistingOS: ") {
                status_str.trim_start_matches("ExistingOS: ").to_string()
            } else {
                "Unknown".to_string() // Fallback for "Existing OS" format
            };
            
            info!("Setting os_installed for machine {} to {}", id, os);
            sqlx::query(
                r#"
                UPDATE machines 
                SET os_installed = ?, updated_at = ?, status = ? 
                WHERE id = ?
                "#,
            )
            .bind(os)
            .bind(&now_str)
            .bind("Existing OS") // Update to the new format
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    
    // Check if bmc_credentials column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'bmc_credentials'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add bmc_credentials column if it doesn't exist
    if column_exists == 0 {
        info!("Adding bmc_credentials column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN bmc_credentials TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if installation_progress column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'installation_progress'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add installation_progress column if it doesn't exist
    if column_exists == 0 {
        info!("Adding installation_progress column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN installation_progress INTEGER DEFAULT 0
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if installation_step column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'installation_step'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add installation_step column if it doesn't exist
    if column_exists == 0 {
        info!("Adding installation_step column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN installation_step TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if last_deployment_duration column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'last_deployment_duration'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let duration_column_exists: i64 = result.get(0);
    
    // Add last_deployment_duration column if it doesn't exist
    if duration_column_exists == 0 {
        info!("Adding last_deployment_duration column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN last_deployment_duration INTEGER
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if default_os column exists in app_settings table
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_settings'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let table_exists: i64 = result.get(0);
    
    if table_exists > 0 {
        // Table exists, check for the column
        let result = sqlx::query(
            r#"
            SELECT COUNT(*) AS count FROM pragma_table_info('app_settings') WHERE name = 'default_os'
            "#,
        )
        .fetch_one(pool)
        .await?;
        
        let column_exists: i64 = result.get(0);
        
        // Add default_os column if it doesn't exist
        if column_exists == 0 {
            info!("Adding default_os column to app_settings table");
            sqlx::query(
                r#"
                ALTER TABLE app_settings ADD COLUMN default_os TEXT
                "#,
            )
            .execute(pool)
            .await?;
        }
    }
    
    // Check if setup_completed column exists in app_settings table
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_settings'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let table_exists: i64 = result.get(0);
    
    if table_exists > 0 {
        // Check if setup_completed column exists
        let result = sqlx::query(
            r#"
            SELECT COUNT(*) AS count FROM pragma_table_info('app_settings') WHERE name = 'setup_completed'
            "#,
        )
        .fetch_one(pool)
        .await?;
        
        let column_exists: i64 = result.get(0);
        
        // Add setup_completed column if it doesn't exist
        if column_exists == 0 {
            info!("Adding setup_completed column to app_settings table");
            sqlx::query(
                r#"
                ALTER TABLE app_settings ADD COLUMN setup_completed BOOLEAN NOT NULL DEFAULT 0
                "#,
            )
            .execute(pool)
            .await?;
        }
    }
    
    // Add cpu_model column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'cpu_model'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding cpu_model column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN cpu_model TEXT").execute(pool).await?;
    }

    // Add cpu_cores column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'cpu_cores'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding cpu_cores column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN cpu_cores INTEGER").execute(pool).await?;
    }

    // Add total_ram_bytes column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'total_ram_bytes'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding total_ram_bytes column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN total_ram_bytes INTEGER").execute(pool).await?;
    }
    
    // Add proxmox_vmid column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'proxmox_vmid'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding proxmox_vmid column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN proxmox_vmid INTEGER").execute(pool).await?;
    }
    
    // Add proxmox_node column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'proxmox_node'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding proxmox_node column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN proxmox_node TEXT").execute(pool).await?;
    }
    
    // Add memorable_name column if it doesn't exist
    let result = sqlx::query("SELECT COUNT(*) FROM pragma_table_info('machines') WHERE name = 'memorable_name'").fetch_one(pool).await?;
    let column_exists: i64 = result.get(0);
    if column_exists == 0 {
        info!("Adding memorable_name column to machines table");
        sqlx::query("ALTER TABLE machines ADD COLUMN memorable_name TEXT").execute(pool).await?;
    }
    
    // Check if proxmox_cluster column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'proxmox_cluster'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add proxmox_cluster column if it doesn't exist
    if column_exists == 0 {
        info!("Adding proxmox_cluster column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN proxmox_cluster TEXT
            "#,
        )
        .execute(pool)
        .await?;
        // Note: No automatic backfill here, as we don't know the cluster name from existing data.
        // Cluster name will be populated during the next Proxmox import.
    }
    
    // Check if is_proxmox_host column exists (ensure this runs after cluster check)
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('machines') WHERE name = 'is_proxmox_host'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    if column_exists == 0 {
        info!("Adding is_proxmox_host column to machines table");
        sqlx::query(
            r#"
            ALTER TABLE machines ADD COLUMN is_proxmox_host BOOLEAN DEFAULT FALSE NOT NULL
            "#,
        )
        .execute(pool)
        .await?;

        info!("Backfilling is_proxmox_host flag for existing potential Proxmox hosts...");
        let backfill_result = sqlx::query(
            r#"
            UPDATE machines 
            SET is_proxmox_host = TRUE 
            WHERE proxmox_node IS NOT NULL AND proxmox_vmid IS NULL
            "#
        )
        .execute(pool)
        .await?;
        info!("Backfill complete for is_proxmox_host. Updated {} rows.", backfill_result.rows_affected());
    }
    
    Ok(())
}

// Get admin credentials from database
pub async fn get_admin_credentials() -> Result<Option<Credentials>> {
    let pool = get_pool().await?;
    
    let row = sqlx::query(
        r#"
        SELECT username, password_hash FROM admin_credentials ORDER BY id DESC LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;
    
    if let Some(row) = row {
        let username: String = row.get(0);
        let password_hash: String = row.get(1);
        
        Ok(Some(Credentials {
            username,
            password: None,
            password_hash,
        }))
    } else {
        Ok(None)
    }
}

// Save admin credentials to database
pub async fn save_admin_credentials(credentials: &Credentials) -> Result<()> {
    // Make sure the database pool is initialized
    let pool = get_pool().await?;
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    
    // Use a transaction to ensure atomicity
    let mut tx = pool.begin().await?;
    
    // Check if credentials already exist
    let existing = sqlx::query("SELECT COUNT(*) FROM admin_credentials")
        .fetch_one(&mut *tx)
        .await?;
    
    let count: i64 = existing.get(0);
    
    if count > 0 {
        // Update existing credentials
        sqlx::query(
            r#"
            UPDATE admin_credentials 
            SET username = ?, password_hash = ?, updated_at = ?
            WHERE id = (SELECT id FROM admin_credentials ORDER BY id DESC LIMIT 1)
            "#,
        )
        .bind(&credentials.username)
        .bind(&credentials.password_hash)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;
        
        info!("Updated existing admin credentials for user: {}", credentials.username);
    } else {
        // Insert new credentials
        sqlx::query(
            r#"
            INSERT INTO admin_credentials (username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&credentials.username)
        .bind(&credentials.password_hash)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;
        
        info!("Created new admin credentials for user: {}", credentials.username);
    }
    
    // Commit the transaction
    tx.commit().await?;
    
    // Verify the save worked by retrieving the credentials again
    match get_admin_credentials().await {
        Ok(Some(_)) => {
            info!("Successfully verified admin credentials were saved");
            Ok(())
        },
        _ => {
            error!("Failed to verify admin credentials were saved - this is a critical error!");
            Err(anyhow!("Failed to verify admin credentials were saved"))
        }
    }
}

// Get application settings from database
pub async fn get_app_settings() -> Result<Settings> {
    let pool = get_pool().await?;
    
    // First, make sure the settings table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1), -- Only one settings record allowed
            require_login BOOLEAN NOT NULL,
            default_os TEXT,
            setup_completed BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    
    // Try to get settings
    let row = sqlx::query(
        r#"
        SELECT require_login, default_os, setup_completed FROM app_settings WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;
    
    // Start with default settings and make it mutable
    let mut settings = Settings::default();
    
    if let Some(row) = row {
        // Update settings from the fetched row
        settings.require_login = row.get::<bool, _>("require_login");
        settings.default_os = row.get::<Option<String>, _>("default_os");
        settings.setup_completed = row.get::<bool, _>("setup_completed");
        
        // Load admin credentials separately to populate those fields in the default settings struct
        // Note: This might introduce a small inconsistency if DB ops fail between here and AppState creation,
        // but it resolves the immediate panic. A better approach might involve restructuring Settings.
        if let Ok(Some(creds)) = get_admin_credentials().await {
            settings.admin_username = creds.username;
            settings.admin_password_hash = creds.password_hash;
        }
    } else {
        // No settings found, insert defaults for app_settings table
        info!("No settings found in app_settings table, inserting defaults.");
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        sqlx::query(
            r#"
            INSERT INTO app_settings (id, require_login, default_os, setup_completed, created_at, updated_at)
            VALUES (1, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(settings.require_login)    // Use defaults (now accessible)
        .bind(&settings.default_os)       // Use defaults (now accessible)
        .bind(settings.setup_completed)  // Use defaults (now accessible)
        .bind(&now_str)
        .bind(&now_str)
        .execute(pool)
        .await?;
    }
    
    // Return the potentially modified settings struct
    Ok(settings)
}

// Save application settings to database
pub async fn save_app_settings(settings: &Settings) -> Result<()> {
    let pool = get_pool().await?;
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    
    // Update existing settings or insert if they don't exist (upsert pattern)
    sqlx::query(
        r#"
        INSERT INTO app_settings (id, require_login, default_os, setup_completed, created_at, updated_at)
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
        require_login = excluded.require_login,
        default_os = excluded.default_os,
        setup_completed = excluded.setup_completed,
        updated_at = excluded.updated_at
        "#,
    )
    .bind(settings.require_login)
    .bind(&settings.default_os)
    .bind(settings.setup_completed)
    .bind(&now_str)
    .bind(&now_str)
    .execute(pool)
    .await?;
    
    Ok(())
}

// ---- START TAGS FUNCTIONS ----

// Get all existing tags in the system
pub async fn get_all_tags() -> Result<Vec<String>> {
    let pool = DB_POOL.get().ok_or_else(|| anyhow!("Database not initialized"))?;
    
    // First, we need to create the tags table if it doesn't exist
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tags (
            name TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;
    
    // Then, we need to create the machine_tags table if it doesn't exist
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS machine_tags (
            machine_id TEXT NOT NULL,
            tag_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (machine_id, tag_name)
        )"
    )
    .execute(pool)
    .await?;
    
    // Query all distinct tags from both standalone tags and machine tags
    let rows = sqlx::query(
        "SELECT DISTINCT name FROM tags 
         UNION 
         SELECT DISTINCT tag_name FROM machine_tags
         ORDER BY name ASC"
    )
    .fetch_all(pool)
    .await?;
    
    // Convert rows to strings
    let tags = rows.iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();
    
    Ok(tags)
}

// Create a new standalone tag
pub async fn create_tag(tag_name: &str) -> Result<bool> {
    let pool = DB_POOL.get().ok_or_else(|| anyhow!("Database not initialized"))?;
    
    // First check if the tag already exists
    let existing_tag = sqlx::query("SELECT name FROM tags WHERE name = ?")
        .bind(tag_name)
        .fetch_optional(pool)
        .await?;
    
    if existing_tag.is_some() {
        // Tag already exists
        return Ok(false);
    }
    
    // Insert the new tag
    let now = Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO tags (name, created_at) VALUES (?, ?)")
        .bind(tag_name)
        .bind(now)
        .execute(pool)
        .await?;
    
    Ok(true)
}

// Delete a standalone tag
pub async fn delete_tag(tag_name: &str) -> Result<bool> {
    let pool = DB_POOL.get().ok_or_else(|| anyhow!("Database not initialized"))?;
    
    // First check if the tag exists
    let existing_tag = sqlx::query("SELECT name FROM tags WHERE name = ?")
        .bind(tag_name)
        .fetch_optional(pool)
        .await?;
    
    if existing_tag.is_none() {
        // Tag doesn't exist as a standalone tag
        // Check if it exists in machine_tags
        let machine_tag_count = sqlx::query("SELECT COUNT(*) as count FROM machine_tags WHERE tag_name = ?")
            .bind(tag_name)
            .fetch_one(pool)
            .await?;
        
        let count: i64 = machine_tag_count.get("count");
        
        if count == 0 {
            // Tag doesn't exist anywhere
            return Ok(false);
        }
    }
    
    // Delete the tag from the standalone tags table
    sqlx::query("DELETE FROM tags WHERE name = ?")
        .bind(tag_name)
        .execute(pool)
        .await?;
    
    // Delete the tag from all machines
    sqlx::query("DELETE FROM machine_tags WHERE tag_name = ?")
        .bind(tag_name)
        .execute(pool)
        .await?;
    
    Ok(true)
}

// ---- END TAGS FUNCTIONS ----

// Check if the database exists by checking the standard installation path
pub async fn database_exists() -> bool {
    let db_path = "/var/lib/dragonfly/sqlite.db";
    Path::new(db_path).exists()
}

// Add this to the structs section
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxmoxSettings {
    pub id: i64,
    pub host: String,
    pub port: i32,
    pub username: String, // We store the username but NEVER the password
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    pub ticket_timestamp: Option<i64>,
    pub skip_tls_verify: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // API tokens with different permissions (encrypted and stored)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_create_token: Option<String>, // Token for creating VMs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_power_token: Option<String>,  // Token for power operations (reboot/shutdown)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_config_token: Option<String>, // Token for changing VM config (boot order, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_sync_token: Option<String>,   // Token for synchronization operations (read access)
    // Note: We NEVER store the root password. It's only used transiently for creating API tokens.
}

// Migration function for Proxmox settings table
async fn migrate_add_proxmox_settings(pool: &SqlitePool) -> Result<()> {
    info!("Creating proxmox_settings table if it doesn't exist...");
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS proxmox_settings (
            id INTEGER PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 8006,
            username TEXT NOT NULL,
            auth_ticket TEXT,
            csrf_token TEXT,
            ticket_timestamp INTEGER,
            skip_tls_verify BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#
    )
    .execute(pool)
    .await?;
    
    info!("Created proxmox_settings table");
    
    // Check if vm_create_token column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('proxmox_settings') WHERE name = 'vm_create_token'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add vm_create_token column if it doesn't exist
    if column_exists == 0 {
        info!("Adding vm_create_token column to proxmox_settings table");
        sqlx::query(
            r#"
            ALTER TABLE proxmox_settings ADD COLUMN vm_create_token TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if vm_power_token column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('proxmox_settings') WHERE name = 'vm_power_token'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add vm_power_token column if it doesn't exist
    if column_exists == 0 {
        info!("Adding vm_power_token column to proxmox_settings table");
        sqlx::query(
            r#"
            ALTER TABLE proxmox_settings ADD COLUMN vm_power_token TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if vm_config_token column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('proxmox_settings') WHERE name = 'vm_config_token'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add vm_config_token column if it doesn't exist
    if column_exists == 0 {
        info!("Adding vm_config_token column to proxmox_settings table");
        sqlx::query(
            r#"
            ALTER TABLE proxmox_settings ADD COLUMN vm_config_token TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    // Check if vm_sync_token column exists
    let result = sqlx::query(
        r#"
        SELECT COUNT(*) AS count FROM pragma_table_info('proxmox_settings') WHERE name = 'vm_sync_token'
        "#,
    )
    .fetch_one(pool)
    .await?;
    
    let column_exists: i64 = result.get(0);
    
    // Add vm_sync_token column if it doesn't exist
    if column_exists == 0 {
        info!("Adding vm_sync_token column to proxmox_settings table");
        sqlx::query(
            r#"
            ALTER TABLE proxmox_settings ADD COLUMN vm_sync_token TEXT
            "#,
        )
        .execute(pool)
        .await?;
    }
    
    Ok(())
}

// Function to save a ProxmoxSettings object to the database
pub async fn save_proxmox_settings_object(settings: &ProxmoxSettings) -> Result<()> {
    let pool = get_pool().await?;
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    
    // Update existing settings or insert if they don't exist (upsert pattern)
    sqlx::query(
        r#"
        INSERT INTO proxmox_settings (
            id, host, port, username, auth_ticket, csrf_token, 
            ticket_timestamp, skip_tls_verify, created_at, updated_at
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            host = excluded.host,
            port = excluded.port,
            username = excluded.username,
            auth_ticket = excluded.auth_ticket,
            csrf_token = excluded.csrf_token,
            ticket_timestamp = excluded.ticket_timestamp,
            skip_tls_verify = excluded.skip_tls_verify,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&settings.host)
    .bind(settings.port)
    .bind(&settings.username)
    .bind(&settings.auth_ticket)
    .bind(&settings.csrf_token)
    .bind(settings.ticket_timestamp)
    .bind(settings.skip_tls_verify)
    .bind(&now_str)
    .bind(&now_str)
    .execute(pool)
    .await?;
    
    Ok(())
}

// Function to get Proxmox settings from the database
pub async fn get_proxmox_settings() -> Result<Option<ProxmoxSettings>> {
    let pool = get_pool().await?;
    
    // Use regular query instead of query macro to avoid SQLX prepare issues
    let row = sqlx::query(
        r#"
        SELECT id, host, port, username, auth_ticket, csrf_token, 
               ticket_timestamp, skip_tls_verify, created_at, updated_at,
               vm_create_token, vm_power_token, vm_config_token, vm_sync_token
        FROM proxmox_settings
        WHERE id = 1
        "#
    )
    .fetch_optional(pool)
    .await?;
    
    match row {
        Some(r) => {
            // Extract values manually
            let id: i64 = r.try_get("id")?;
            let host: String = r.try_get("host")?;
            let port: i32 = r.try_get("port")?;
            let username: String = r.try_get("username")?;
            let auth_ticket: Option<String> = r.try_get("auth_ticket")?;
            let csrf_token: Option<String> = r.try_get("csrf_token")?;
            let ticket_timestamp: Option<i64> = r.try_get("ticket_timestamp")?;
            let skip_tls_verify: i64 = r.try_get("skip_tls_verify")?;
            let created_at_str: String = r.try_get("created_at")?;
            let updated_at_str: String = r.try_get("updated_at")?;
            
            // Get token values
            let vm_create_token: Option<String> = r.try_get("vm_create_token").ok();
            let vm_power_token: Option<String> = r.try_get("vm_power_token").ok();
            let vm_config_token: Option<String> = r.try_get("vm_config_token").ok();
            let vm_sync_token: Option<String> = r.try_get("vm_sync_token").ok();
            
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)?
                .with_timezone(&chrono::Utc);
            let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)?
                .with_timezone(&chrono::Utc);
                
            Ok(Some(ProxmoxSettings {
                id,
                host,
                port,
                username,
                auth_ticket,
                csrf_token,
                ticket_timestamp,
                skip_tls_verify: skip_tls_verify != 0,
                created_at,
                updated_at,
                vm_create_token,
                vm_power_token,
                vm_config_token,
                vm_sync_token,
            }))
        },
        None => Ok(None),
    }
}

// New function that doesn't require or store password
pub async fn update_proxmox_connection_settings(
    host: &str, 
    port: i32, 
    username: &str, 
    skip_tls_verify: bool
) -> Result<ProxmoxSettings> {
    // Create a new ProxmoxSettings object with current time
    let now = Utc::now();
    
    // Start with a settings object without tickets or password
    let settings = ProxmoxSettings {
        id: 1,
        host: host.to_string(),
        port,
        username: username.to_string(),
        auth_ticket: None,
        csrf_token: None,
        ticket_timestamp: None,
        skip_tls_verify,
        created_at: now,
        updated_at: now,
        vm_create_token: None,
        vm_power_token: None,
        vm_config_token: None,
        vm_sync_token: None,
    };
    
    // Save initial settings without tickets or password
    save_proxmox_settings_object(&settings).await?;
    
    Ok(settings)
}

// Add a new function to update API tokens
pub async fn update_proxmox_api_tokens(
    token_type: &str,
    token_value: &str
) -> Result<bool> {
    use sqlx::query;
    use crate::encryption::{encrypt_string, decrypt_string};
    use tracing::info;

    // Get the existing settings
    let settings = match get_proxmox_settings().await? {
        Some(s) => s,
        None => {
            return Err(anyhow::anyhow!("Cannot update API tokens: No Proxmox settings exist").into());
        }
    };

    // Encrypt the token
    let encrypted_token = match encrypt_string(token_value) {
        Ok(token) => token,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to encrypt API token: {}", e).into());
        }
    };

    // Update the appropriate token field based on token type
    let update_result = match token_type {
        "create" => {
            info!("Updating Proxmox VM creation API token");
            sqlx::query(
                "UPDATE proxmox_settings 
                SET vm_create_token = ?, updated_at = ?
                WHERE id = 1"
            )
            .bind(encrypted_token)
            .bind(chrono::Utc::now())
            .execute(get_pool().await?)
            .await
        },
        "power" => {
            info!("Updating Proxmox VM power operations API token");
            sqlx::query(
                "UPDATE proxmox_settings 
                SET vm_power_token = ?, updated_at = ?
                WHERE id = 1"
            )
            .bind(encrypted_token)
            .bind(chrono::Utc::now())
            .execute(get_pool().await?)
            .await
        },
        "config" => {
            info!("Updating Proxmox VM configuration API token");
            sqlx::query(
                "UPDATE proxmox_settings 
                SET vm_config_token = ?, updated_at = ?
                WHERE id = 1"
            )
            .bind(encrypted_token)
            .bind(chrono::Utc::now())
            .execute(get_pool().await?)
            .await
        },
        "sync" => {
            info!("Updating Proxmox synchronization API token");
            sqlx::query(
                "UPDATE proxmox_settings 
                SET vm_sync_token = ?, updated_at = ?
                WHERE id = 1"
            )
            .bind(encrypted_token)
            .bind(chrono::Utc::now())
            .execute(get_pool().await?)
            .await
        },
        _ => {
            return Err(anyhow::anyhow!("Invalid token type: {}", token_type).into());
        }
    };

    match update_result {
        Ok(_) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

pub async fn update_proxmox_tokens(
    vm_create_token: String,
    vm_power_token: String,
    vm_config_token: String,
    vm_sync_token: String
) -> Result<bool> {
    info!("Updating Proxmox API tokens");
    let pool = get_pool().await?;
    
    let _settings = match get_proxmox_settings().await? {
        Some(s) => s,
        None => {
            // If no settings exist yet, create a default entry
            let now = chrono::Utc::now();
            ProxmoxSettings {
                id: 1, // We only ever have one settings entry
                host: "".to_string(),
                port: 8006,
                username: "".to_string(),
                auth_ticket: None,
                csrf_token: None,
                ticket_timestamp: None,
                skip_tls_verify: false,
                created_at: now,
                updated_at: now,
                vm_create_token: None,
                vm_power_token: None,
                vm_config_token: None,
                vm_sync_token: None,
            }
        }
    };
    
    // Update the tokens in one transaction
    let mut transaction = pool.begin().await?;
    
    sqlx::query(
        "UPDATE proxmox_settings SET 
            vm_create_token = ?,
            vm_power_token = ?,
            vm_config_token = ?,
            vm_sync_token = ?,
            updated_at = ?
         WHERE id = 1"
    )
    .bind(&vm_create_token)
    .bind(&vm_power_token)
    .bind(&vm_config_token)
    .bind(&vm_sync_token)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    
    transaction.commit().await?;
    
    Ok(true)
}