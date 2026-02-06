//! Storage backends for Dragonfly
//!
//! This module provides storage implementations:
//!
//! ## v0.1.0 Storage
//! The `v1` module contains the new schema with:
//! - `Machine` as the central entity with UUIDv7 primary keys
//! - Deterministic identity hashing for machine re-identification
//! - Backend-agnostic `Store` trait for SQLite, etcd, and memory
//!
//! All types are imported from `dragonfly_common`.

// v0.1.0 Store trait and implementations
pub mod v1;

// Type conversion helpers for API
pub mod conversions;

// Re-export v1 Store as the primary interface
pub use v1::{create_store, MemoryStore, SqliteStore, Store, StoreConfig, StoreError, Result};
