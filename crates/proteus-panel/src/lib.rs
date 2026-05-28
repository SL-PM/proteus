//! PROTEUS Control — management-portal library (v0.6).
//!
//! Exposed as a library so the `proteus-panel` bin, integration tests,
//! and the forthcoming management API (M2.6) all share one surface.
//! M1.6 ships the [`db`] module (SQLite client store); auth, the HTTP
//! API, and the admin UI land in later milestones.
//!
//! Design + roadmap: `docs/PROTEUS-v0.6-control-plan.md`.

pub mod api;
pub mod auth;
pub mod db;
pub mod web;
