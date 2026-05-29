//! PROTEUS desktop client (Tauri v2).
//!
//! Thin GUI shell over [`proteus_client_core`]: paste a `proteus://`
//! subscription, connect, and watch live up/down throughput + ping. All
//! the real work (dial, auth, SOCKS5) lives in the shared client engine;
//! this file just wires three commands to the webview:
//!
//! - `connect(sub_url, socks5_port)` → import + dial, returns the bound
//!   SOCKS5 address as a string.
//! - `disconnect()` → tear the link down.
//! - `get_stats()` → a [`StatsDto`] snapshot (or `null` when idle), polled
//!   once a second by the UI.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::SocketAddr;
use std::sync::Mutex;

use proteus_client_core::{RunningClient, connect_subscription};
use serde::Serialize;
use tauri::State;

/// Holds the single active connection (the GUI is one-link-at-a-time).
#[derive(Default)]
struct AppState {
    client: Mutex<Option<RunningClient>>,
}

/// Serializable mirror of `proteus_client_core::Stats` for the webview.
#[derive(Serialize)]
struct StatsDto {
    connected: bool,
    socks5_addr: String,
    up_bytes: u64,
    down_bytes: u64,
    up_bps: f64,
    down_bps: f64,
    ping_ms: f64,
}

/// Import a `proteus://` subscription and connect, binding SOCKS5 on
/// `127.0.0.1:<socks5_port>`. Replaces any existing connection. Returns
/// the bound SOCKS5 address (host:port) on success.
#[tauri::command]
async fn connect(
    state: State<'_, AppState>,
    sub_url: String,
    socks5_port: u16,
) -> Result<String, String> {
    // Drop any prior connection first (take it out, then await stop with
    // no lock held).
    let prev = state.client.lock().expect("client lock").take();
    if let Some(c) = prev {
        c.stop().await;
    }

    let listen: SocketAddr = format!("127.0.0.1:{socks5_port}")
        .parse()
        .map_err(|e| format!("bad SOCKS5 port {socks5_port}: {e}"))?;

    let client = connect_subscription(sub_url.trim(), listen)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let addr = client.socks5_addr().to_string();

    *state.client.lock().expect("client lock") = Some(client);
    Ok(addr)
}

/// Disconnect and free the SOCKS5 listener. No-op when already idle.
#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client.lock().expect("client lock").take();
    if let Some(c) = client {
        c.stop().await;
    }
    Ok(())
}

/// Current link stats, or `None` (→ JS `null`) when not connected.
#[tauri::command]
fn get_stats(state: State<'_, AppState>) -> Option<StatsDto> {
    let guard = state.client.lock().expect("client lock");
    guard.as_ref().map(|c| {
        let s = c.stats();
        StatsDto {
            connected: s.connected,
            socks5_addr: s.socks5_addr.to_string(),
            up_bytes: s.up_bytes,
            down_bytes: s.down_bytes,
            up_bps: s.up_bps,
            down_bps: s.down_bps,
            ping_ms: s.ping_ms,
        }
    })
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![connect, disconnect, get_stats])
        .run(tauri::generate_context!())
        .expect("error while running PROTEUS app");
}
