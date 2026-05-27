//! PROTEUS core — shared types for server and client.
//!
//! v0.3 research prototype. See `docs/PROTEUS-spec-v0.2.md` for scope.

pub mod aead;
pub mod auth;
pub mod config;
pub mod decoy;
pub mod frame;
pub mod metrics;
pub mod padding;
pub mod policy;
pub mod proxy;
pub mod ratelimit;
pub mod replay;
pub mod tls;
