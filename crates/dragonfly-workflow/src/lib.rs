//! Dragonfly Workflow Engine
//!
//! This crate provides workflow orchestration for bare metal provisioning.
//! It executes workflows by coordinating action execution, managing state,
//! and reporting progress.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              WorkflowExecutor                        │
//! │  ┌─────────────────────────────────────────────┐    │
//! │  │          WorkflowStateStore                 │    │
//! │  │   Memory | ReDB | etcd (via k8s API)        │    │
//! │  └─────────────────────────────────────────────┘    │
//! │                      │                               │
//! │                      ▼                               │
//! │  ┌─────────────────────────────────────────────┐    │
//! │  │           ActionEngine                      │    │
//! │  │   Execute actions, report progress          │    │
//! │  └─────────────────────────────────────────────┘    │
//! │                      │                               │
//! │                      ▼                               │
//! │  ┌─────────────────────────────────────────────┐    │
//! │  │         WorkflowEvent Stream                │    │
//! │  │   Started | Progress | Completed            │    │
//! │  └─────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use dragonfly_workflow::{WorkflowExecutor, MemoryStateStore};
//! use dragonfly_actions::ActionEngine;
//! use std::sync::Arc;
//!
//! let store = Arc::new(MemoryStateStore::new());
//! let action_engine = ActionEngine::new();
//! let executor = WorkflowExecutor::new(action_engine, store);
//!
//! executor.execute("os-install-123").await?;
//! ```

pub mod error;
pub mod executor;
pub mod store;

pub use error::*;
pub use executor::*;
pub use store::*;
