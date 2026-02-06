pub mod error;
pub mod machine;
pub mod mac_to_words;
pub mod network;

// Legacy models - keeping for API compatibility during migration
pub mod models;

pub use error::Error;
pub use machine::*;
pub use network::Network;

pub type Result<T> = std::result::Result<T, Error>; 