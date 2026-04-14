//! nodeshift-core — Rust core for the NodeShift VPN protocol stack.
//!
//! Provides VLESS Reality protocol implementation, X25519 key management,
//! and packet processing primitives used by the Android JNI layer.

pub mod config;
pub mod crypto;
pub mod protocol;

pub use config::TunnelConfig;
pub use protocol::VlessClient;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Connection timeout")]
    Timeout,
    #[error("Authentication failed")]
    AuthFailed,
}

pub type Result<T> = std::result::Result<T, CoreError>;
