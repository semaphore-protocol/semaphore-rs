//! Semaphore Rust Implementation
//!
//! Protocol specifications:
//! - https://github.com/zkspecs/zkspecs/tree/main/specs/3

pub mod baby_jubjub;
pub mod error;
pub mod group;
pub mod identity;
pub mod proof;
pub mod utils;

pub const MIN_TREE_DEPTH: u16 = 1;
pub const MAX_TREE_DEPTH: u16 = 32;
