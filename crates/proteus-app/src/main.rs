//! PROTEUS desktop client (Tauri v2).
//!
//! Thin GUI shell over [`proteus_client_core`]: paste a `proteus://`
//! subscription, connect, and watch live up/down throughput + ping. All
//! the real work (dial, auth, SOCKS5) lives in the shared client engine.
//!
//! Optional **system routing** (the `system_proxy` flag on [`connect`]):
//! on connect the app points the macOS system SOCKS proxy at its own
//! listener (and disables the HTTP/HTTPS web proxies, since PROTEUS only
//! speaks SOCKS5) so every app routes through the tunnel without the user
//! configuring anything; on disconnect / app-exit it restores the exact
//! prior proxy settings. Changing the system proxy needs admin rights, so
//! macOS prompts once (a signed privileged helper to make it prompt-free
//! is a later, signing-gated step).

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::SocketAddr;
use std::sync::Mutex;

use proteus_client_core::{RunningClient, connect_subscription};
use serde::Serialize;
use tauri::{Manager, RunEvent, State};

/// Holds the single active connection plus, while system routing is on,
/// the prior system-proxy state to restore on disconnect / exit.
#[derive(Default)]
struct AppState {
    client: Mutex<Option<RunningClient>>,
    /// `Some` while we've taken over the system proxy.
    proxy: Mutex<Option<sysproxy::Saved>>,
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

/// Result of a connect: the bound SOCKS5 address, whether we took over
/// the system proxy, and an optional note (e.g. auto-proxy declined).
#[derive(Serialize)]
struct ConnectResult {
    socks5_addr: String,
    system_proxy: bool,
    note: Option<String>,
}

/// Take the saved proxy snapshot out of state (so the caller can restore
/// it without holding the lock across an `.await`).
fn take_saved(state: &AppState) -> Option<sysproxy::Saved> {
    state.proxy.lock().expect("proxy lock").take()
}

/// Import a `proteus://` subscription and connect, binding SOCKS5 on
/// `127.0.0.1:<socks5_port>`. When `system_proxy` is set, also point the
/// OS proxy at our listener. Replaces any existing connection.
#[tauri::command]
async fn connect(
    state: State<'_, AppState>,
    sub_url: String,
    socks5_port: u16,
    system_proxy: bool,
) -> Result<ConnectResult, String> {
    // Undo any prior system-proxy takeover, then drop any prior link.
    if let Some(saved) = take_saved(&state) {
        let _ = tauri::async_runtime::spawn_blocking(move || sysproxy::restore(&saved)).await;
    }
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
    let addr = client.socks5_addr();
    *state.client.lock().expect("client lock") = Some(client);

    let mut res = ConnectResult {
        socks5_addr: addr.to_string(),
        system_proxy: false,
        note: None,
    };

    if system_proxy {
        let port = addr.port();
        match tauri::async_runtime::spawn_blocking(move || sysproxy::enable(port)).await {
            Ok(Ok(saved)) => {
                *state.proxy.lock().expect("proxy lock") = Some(saved);
                res.system_proxy = true;
            }
            Ok(Err(e)) => res.note = Some(format!("Auto-Proxy nicht gesetzt: {e}")),
            Err(e) => res.note = Some(format!("Auto-Proxy nicht gesetzt: {e}")),
        }
    }
    Ok(res)
}

/// Disconnect: restore the system proxy (if we changed it), then tear the
/// link down.
#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(saved) = take_saved(&state) {
        let _ = tauri::async_runtime::spawn_blocking(move || sysproxy::restore(&saved)).await;
    }
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
        .build(tauri::generate_context!())
        .expect("error building PROTEUS app")
        .run(|app, event| {
            // Never leave the OS proxy pointing at a dead listener: restore
            // it synchronously before the process exits.
            if let RunEvent::ExitRequested { .. } = event
                && let Some(saved) = take_saved(app.state::<AppState>().inner())
            {
                let _ = sysproxy::restore(&saved);
            }
        });
}

/// macOS system-proxy control via `networksetup` (privileged, so each
/// change is wrapped in one `osascript … with administrator privileges`).
#[cfg(target_os = "macos")]
mod sysproxy {
    use std::process::Command;

    /// Prior proxy settings for the primary network service, captured
    /// before we take over so [`restore`] can put them back exactly.
    pub struct Saved {
        service: String,
        socks_enabled: bool,
        socks_server: String,
        socks_port: String,
        web_enabled: bool,
        secure_enabled: bool,
    }

    /// Network service carrying the default route (e.g. "Wi-Fi").
    fn primary_service() -> Result<String, String> {
        let route = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| format!("route: {e}"))?;
        let rtxt = String::from_utf8_lossy(&route.stdout);
        let iface = rtxt
            .lines()
            .find_map(|l| l.trim().strip_prefix("interface:"))
            .map(|s| s.trim().to_string())
            .ok_or("kein Default-Interface")?;

        let order = Command::new("networksetup")
            .arg("-listnetworkserviceorder")
            .output()
            .map_err(|e| format!("networksetup: {e}"))?;
        let otxt = String::from_utf8_lossy(&order.stdout);
        // Blocks look like:  "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)"
        let mut name = String::new();
        for line in otxt.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix('(')
                && let Some(idx) = rest.find(") ")
            {
                name = rest[idx + 2..].trim().to_string();
            }
            if l.contains(&format!("Device: {iface})")) && !name.is_empty() {
                return Ok(name);
            }
        }
        Err(format!("kein Netzwerkdienst für {iface}"))
    }

    /// Read one proxy kind ("socksfirewall" | "web" | "secureweb").
    fn read(service: &str, kind: &str) -> Result<(bool, String, String), String> {
        let out = Command::new("networksetup")
            .arg(format!("-get{kind}proxy"))
            .arg(service)
            .output()
            .map_err(|e| format!("networksetup -get{kind}proxy: {e}"))?;
        let t = String::from_utf8_lossy(&out.stdout);
        let (mut en, mut srv, mut port) = (false, String::new(), String::new());
        for l in t.lines() {
            if let Some(v) = l.strip_prefix("Enabled:") {
                en = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = l.strip_prefix("Server:") {
                srv = v.trim().to_string();
            } else if let Some(v) = l.strip_prefix("Port:") {
                port = v.trim().to_string();
            }
        }
        Ok((en, srv, port))
    }

    /// Snapshot the primary service's proxies, then route everything
    /// through our SOCKS listener (web/secure proxies off).
    pub fn enable(port: u16) -> Result<Saved, String> {
        let service = primary_service()?;
        let (socks_enabled, socks_server, socks_port) = read(&service, "socksfirewall")?;
        let (web_enabled, _, _) = read(&service, "web")?;
        let (secure_enabled, _, _) = read(&service, "secureweb")?;

        let script = format!(
            "networksetup -setsocksfirewallproxy '{s}' 127.0.0.1 {p}; \
             networksetup -setsocksfirewallproxystate '{s}' on; \
             networksetup -setwebproxystate '{s}' off; \
             networksetup -setsecurewebproxystate '{s}' off",
            s = service,
            p = port,
        );
        run_admin(&script)?;
        Ok(Saved {
            service,
            socks_enabled,
            socks_server,
            socks_port,
            web_enabled,
            secure_enabled,
        })
    }

    /// Put the captured proxy settings back exactly.
    pub fn restore(s: &Saved) -> Result<(), String> {
        let mut script = String::new();
        if s.socks_enabled && !s.socks_server.is_empty() {
            script += &format!(
                "networksetup -setsocksfirewallproxy '{sv}' {srv} {pt}; \
                 networksetup -setsocksfirewallproxystate '{sv}' on; ",
                sv = s.service,
                srv = s.socks_server,
                pt = if s.socks_port.is_empty() { "0" } else { &s.socks_port },
            );
        } else {
            script += &format!(
                "networksetup -setsocksfirewallproxystate '{sv}' off; ",
                sv = s.service
            );
        }
        script += &format!(
            "networksetup -setwebproxystate '{sv}' {w}; \
             networksetup -setsecurewebproxystate '{sv}' {c}",
            sv = s.service,
            w = if s.web_enabled { "on" } else { "off" },
            c = if s.secure_enabled { "on" } else { "off" },
        );
        run_admin(&script)
    }

    /// Run a shell snippet once with an admin prompt (Touch ID / password).
    fn run_admin(script: &str) -> Result<(), String> {
        let esc = script.replace('\\', "\\\\").replace('"', "\\\"");
        let apple = format!("do shell script \"{esc}\" with administrator privileges");
        let out = Command::new("osascript")
            .arg("-e")
            .arg(apple)
            .output()
            .map_err(|e| format!("osascript: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
}

/// Non-macOS stub: system routing not wired yet (Windows/Linux later).
#[cfg(not(target_os = "macos"))]
mod sysproxy {
    pub struct Saved;
    pub fn enable(_port: u16) -> Result<Saved, String> {
        Err("Auto-Proxy ist derzeit nur auf macOS implementiert".into())
    }
    pub fn restore(_s: &Saved) -> Result<(), String> {
        Ok(())
    }
}
