pub mod error;
pub mod mac_to_words;
pub mod machine;
pub mod network;

// Legacy models - keeping for API compatibility during migration
pub mod models;

pub use error::Error;
pub use machine::*;
pub use network::{Network, StaticLease};

pub type Result<T> = std::result::Result<T, Error>;
