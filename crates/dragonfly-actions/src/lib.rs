//! Dragonfly Native Action Engine
//!
//! This crate provides a native Rust action execution engine that replaces
//! Docker-based actions for better performance. Actions are small, focused
//! Rust implementations that execute directly without container overhead.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │            ActionEngine                  │
//! │  ┌─────────────────────────────────┐    │
//! │  │     Action Registry             │    │
//! │  │  image | writefile | kexec | ...│    │
//! │  └─────────────────────────────────┘    │
//! │                  │                       │
//! │                  ▼                       │
//! │  ┌─────────────────────────────────┐    │
//! │  │     ActionExecutor              │    │
//! │  │  - Execute actions sequentially │    │
//! │  │  - Report progress              │    │
//! │  │  - Handle timeouts              │    │
//! │  └─────────────────────────────────┘    │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use dragonfly_actions::{ActionEngine, ActionContext};
//!
//! let engine = ActionEngine::new();
//! let ctx = ActionContext::new(hardware, workflow);
//! let result = engine.execute("image", &ctx).await?;
//! ```

pub mod context;
pub mod engine;
pub mod error;
pub mod progress;
pub mod traits;

pub use context::*;
pub use engine::*;
pub use error::*;
pub use progress::*;
pub use traits::*;
