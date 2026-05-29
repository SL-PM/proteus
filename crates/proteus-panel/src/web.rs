//! Server-rendered admin web UI (v0.6 M4.6 + M5.6).
//!
//! Plain HTML + form posts (no JS build chain): login, client list,
//! add-client (shows the generated private key once), enable/disable,
//! delete. M5.6 adds a settings page for the public server endpoint and,
//! on the client-created page, a one-click `proteus://` subscription link
//! plus an inline QR code. Sits alongside the JSON API ([`crate::api`])
//! and shares its session machinery.

use axum::{
    Form, async_trait,
    extract::{FromRequestParts, Path, State},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use proteus_core::subscription::Subscription;
use serde::Deserialize;

use crate::{
    api::{AppState, SESSION_COOKIE, generate_keypair, random_id, session_cookie},
    auth,
    db::{Client, SubEndpoint},
};

/// Web auth guard: redirects to `/login` instead of returning 401.
pub struct WebAuth;

#[async_trait]
impl FromRequestParts<AppState> for WebAuth {
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let valid = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .and_then(|t| state.validate_session(&t))
            .is_some();
        if valid {
            Ok(WebAuth)
        } else {
            Err(Redirect::to("/login"))
        }
    }
}

// ----------------- forms -----------------

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AddForm {
    label: String,
    /// Quota in GB (empty = unlimited).
    quota_gb: String,
    /// Expiry as `YYYY-MM-DD` (empty = never).
    expires: String,
}

#[derive(Deserialize)]
struct SettingsForm {
    server_addr: String,
    sni: String,
    cert_sha256: String,
}

// ----------------- handlers -----------------

async fn login_page() -> Markup {
    page_login(None)
}

async fn login_post(
    State(st): State<AppState>,
    jar: CookieJar,
    Form(f): Form<LoginForm>,
) -> Response {
    let stored = st.db.get_admin_hash(&f.username).await.ok().flatten();
    let ok = stored
        .map(|h| auth::verify_password(&f.password, &h).unwrap_or(false))
        .unwrap_or(false);
    if ok {
        let token = st.create_session(&f.username);
        (jar.add(session_cookie(token)), Redirect::to("/")).into_response()
    } else {
        page_login(Some("Falsche Zugangsdaten")).into_response()
    }
}

async fn logout_post(State(st): State<AppState>, jar: CookieJar) -> Response {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        st.destroy_session(c.value());
    }
    (
        jar.remove(axum_extra::extract::cookie::Cookie::from(SESSION_COOKIE)),
        Redirect::to("/login"),
    )
        .into_response()
}

async fn home(_: WebAuth, State(st): State<AppState>) -> Markup {
    let clients = st.db.list_clients().await.unwrap_or_default();
    page_clients(&clients)
}

async fn add_client(_: WebAuth, State(st): State<AppState>, Form(f): Form<AddForm>) -> Response {
    let id = random_id();
    let quota_bytes: Option<i64> = parse_gb(&f.quota_gb);
    let expires_at: Option<String> = parse_expiry(&f.expires);
    let (priv_b64, pub_b64) = generate_keypair();

    match st
        .db
        .add_client(
            &id,
            f.label.trim(),
            &pub_b64,
            quota_bytes,
            expires_at.as_deref(),
        )
        .await
    {
        Ok(()) => {
            // Stamp the stored endpoint into a one-click subscription link
            // (only possible once the endpoint is configured, M5.6).
            let ep = st.db.get_sub_endpoint().await.unwrap_or_default();
            let sub_url = ep.is_configured().then(|| {
                Subscription {
                    server_addr: ep.server_addr,
                    sni: ep.sni,
                    cert_sha256: ep.cert_sha256,
                    client_id: id.clone(),
                    private_key_b64: priv_b64.clone(),
                    label: f.label.trim().to_string(),
                }
                .to_url()
            });
            page_created(&id, &pub_b64, &priv_b64, sub_url.as_deref()).into_response()
        }
        Err(e) => page_error(&format!("Anlegen fehlgeschlagen: {e}")).into_response(),
    }
}

async fn settings_page(_: WebAuth, State(st): State<AppState>) -> Markup {
    let ep = st.db.get_sub_endpoint().await.unwrap_or_default();
    page_settings(&ep, false)
}

async fn settings_post(
    _: WebAuth,
    State(st): State<AppState>,
    Form(f): Form<SettingsForm>,
) -> Response {
    let ep = SubEndpoint {
        server_addr: f.server_addr,
        sni: f.sni,
        cert_sha256: f.cert_sha256,
    };
    match st.db.set_sub_endpoint(&ep).await {
        // Re-read so the form shows the trimmed, persisted values.
        Ok(()) => {
            let saved = st.db.get_sub_endpoint().await.unwrap_or(ep);
            page_settings(&saved, true).into_response()
        }
        Err(e) => page_error(&format!("Speichern fehlgeschlagen: {e}")).into_response(),
    }
}

async fn enable(_: WebAuth, State(st): State<AppState>, Path(id): Path<String>) -> Redirect {
    let _ = st.db.set_enabled(&id, true).await;
    Redirect::to("/")
}

async fn disable(_: WebAuth, State(st): State<AppState>, Path(id): Path<String>) -> Redirect {
    let _ = st.db.set_enabled(&id, false).await;
    Redirect::to("/")
}

async fn delete(_: WebAuth, State(st): State<AppState>, Path(id): Path<String>) -> Redirect {
    let _ = st.db.delete_client(&id).await;
    Redirect::to("/")
}

// ----------------- parsing helpers -----------------

fn parse_gb(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<f64>().ok().map(|g| (g * 1_000_000_000.0) as i64)
}

fn parse_expiry(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        // Store as an end-of-day UTC timestamp comparable to datetime('now').
        Some(format!("{t} 23:59:59"))
    }
}

fn human_bytes(n: i64) -> String {
    const GB: f64 = 1_000_000_000.0;
    const MB: f64 = 1_000_000.0;
    let f = n as f64;
    if f >= GB {
        format!("{:.2} GB", f / GB)
    } else if f >= MB {
        format!("{:.1} MB", f / MB)
    } else {
        format!("{n} B")
    }
}

/// Render `data` as an inline SVG QR code, or `None` if it won't encode.
/// Low EC level maximizes capacity for the long subscription URL.
fn qr_svg(data: &str) -> Option<String> {
    use qrcode::{EcLevel, QrCode, render::svg};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(220, 220)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

// ----------------- pages (maud) -----------------

const CSS: &str = "\
:root{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color-scheme:light dark}
body{max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
h1{font-size:1.4rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8884}
form.inline{display:inline}
input,button{font:inherit;padding:.35rem .5rem}
button{cursor:pointer;border-radius:.4rem;border:1px solid #8886;background:#8881}
.danger{color:#b00}
.card{border:1px solid #8884;border-radius:.6rem;padding:1rem;margin:1rem 0}
code{background:#8882;padding:.1rem .3rem;border-radius:.3rem;word-break:break-all}
.muted{opacity:.7;font-size:.9rem}
.addrow input{margin-right:.4rem}";

fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="de" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "PROTEUS Control — " (title) }
                style { (CSS) }
            }
            body { (body) }
        }
    }
}

fn page_login(err: Option<&str>) -> Markup {
    layout(
        "Login",
        html! {
            h1 { "PROTEUS Control" }
            @if let Some(e) = err { p .danger { (e) } }
            form method="post" action="/login" {
                p { input type="text" name="username" placeholder="Benutzer" autofocus; }
                p { input type="password" name="password" placeholder="Passwort"; }
                p { button type="submit" { "Anmelden" } }
            }
        },
    )
}

fn page_clients(clients: &[Client]) -> Markup {
    layout(
        "Clients",
        html! {
            div style="display:flex;justify-content:space-between;align-items:center" {
                h1 { "Clients (" (clients.len()) ")" }
                div {
                    a href="/settings" { "Einstellungen" }
                    "  "
                    form .inline method="post" action="/logout" {
                        button type="submit" { "Abmelden" }
                    }
                }
            }

            div .card {
                h2 style="font-size:1.1rem;margin-top:0" { "Neuen Client anlegen" }
                form method="post" action="/clients" .addrow {
                    input type="text" name="label" placeholder="Label (z.B. kunde-1)" required;
                    input type="text" name="quota_gb" placeholder="Quota GB (leer=∞)" size="14";
                    input type="text" name="expires" placeholder="Ablauf JJJJ-MM-TT" size="14";
                    button type="submit" { "Anlegen + Keygen" }
                }
                p .muted { "Beim Anlegen wird ein Schlüsselpaar erzeugt; der private Schlüssel wird genau einmal angezeigt." }
            }

            @if clients.is_empty() {
                p .muted { "Noch keine Clients." }
            } @else {
                table {
                    thead { tr {
                        th { "ID" } th { "Label" } th { "Status" }
                        th { "Verbrauch" } th { "Quota" } th { "Ablauf" } th { "Aktionen" }
                    } }
                    tbody {
                        @for c in clients {
                            tr {
                                td { code { (c.id) } }
                                td { (c.label) }
                                td {
                                    @if c.enabled { span { "aktiv" } }
                                    @else { span .danger { "deaktiviert" } }
                                }
                                td { (human_bytes(c.used_bytes)) }
                                td {
                                    @match c.quota_bytes {
                                        Some(q) => (human_bytes(q)),
                                        None => "∞",
                                    }
                                }
                                td {
                                    @match &c.expires_at {
                                        Some(e) => (e.split(' ').next().unwrap_or(e)),
                                        None => "—",
                                    }
                                }
                                td {
                                    @if c.enabled {
                                        form .inline method="post" action={ "/clients/" (c.id) "/disable" } {
                                            button type="submit" { "Deaktivieren" }
                                        }
                                    } @else {
                                        form .inline method="post" action={ "/clients/" (c.id) "/enable" } {
                                            button type="submit" { "Aktivieren" }
                                        }
                                    }
                                    " "
                                    form .inline method="post" action={ "/clients/" (c.id) "/delete" }
                                        onsubmit="return confirm('Client wirklich löschen?')" {
                                        button type="submit" .danger { "Löschen" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

fn page_created(id: &str, pub_b64: &str, priv_b64: &str, sub_url: Option<&str>) -> Markup {
    layout(
        "Client angelegt",
        html! {
            h1 { "Client angelegt" }

            @match sub_url {
                Some(url) => {
                    div .card {
                        h2 style="font-size:1.1rem;margin-top:0" { "Subscription — 1-Klick-Import" }
                        p .muted { "Im PROTEUS-Client einfügen oder QR scannen. Der Link enthält den privaten Schlüssel — wie ein Passwort behandeln." }
                        @if let Some(svg) = qr_svg(url) {
                            div style="background:#fff;display:inline-block;padding:10px;border-radius:.5rem;margin:.4rem 0" {
                                (PreEscaped(svg))
                            }
                        }
                        p { code { (url) } }
                    }
                }
                None => {
                    div .card {
                        p .danger { "Kein Subscription-Link: Server-Endpoint nicht konfiguriert." }
                        p { a href="/settings" { "→ Endpoint in den Einstellungen setzen" } }
                    }
                }
            }

            div .card {
                p { "Client-ID: " code { (id) } }
                p { "Public Key: " code { (pub_b64) } }
                p .danger { "Privater Schlüssel — wird nur jetzt angezeigt, jetzt sichern:" }
                p { code { (priv_b64) } }
                p .muted { "Diesen privaten Schlüssel dem Kunden geben; er wird nicht gespeichert." }
            }
            p { a href="/" { "← Zurück zur Liste" } }
        },
    )
}

fn page_settings(ep: &SubEndpoint, saved: bool) -> Markup {
    layout(
        "Einstellungen",
        html! {
            div style="display:flex;justify-content:space-between;align-items:center" {
                h1 { "Einstellungen" }
                p { a href="/" { "← Clients" } }
            }
            @if saved { p style="color:#0a0" { "Gespeichert." } }
            div .card {
                h2 style="font-size:1.1rem;margin-top:0" { "Server-Endpoint für Subscriptions" }
                p .muted { "Diese Werte werden in jeden proteus://-Link gestempelt, den der Client importiert." }
                form method="post" action="/settings" {
                    p {
                        label { "Server-Adresse (host:port)" } br;
                        input type="text" name="server_addr" style="width:100%" value=(ep.server_addr) placeholder="212.227.12.251:4433";
                    }
                    p {
                        label { "TLS SNI" } br;
                        input type="text" name="sni" style="width:100%" value=(ep.sni) placeholder="localhost";
                    }
                    p {
                        label { "Cert-SHA256-Pin (hex, leer = beliebig/Labor)" } br;
                        input type="text" name="cert_sha256" style="width:100%" value=(ep.cert_sha256) placeholder="2902a743b97e…";
                    }
                    p { button type="submit" { "Speichern" } }
                }
                p .muted { "Pin-Quelle: Server-Log beim Start bzw. client.yaml (cert_sha256). Hinweis: Das Server-Zertifikat wird derzeit bei jedem Neustart neu erzeugt — danach den Pin hier aktualisieren; bereits verteilte Links brechen dann (persistentes Zertifikat folgt später)." }
            }
        },
    )
}

fn page_error(msg: &str) -> Markup {
    layout(
        "Fehler",
        html! {
            h1 .danger { "Fehler" }
            p { (msg) }
            p { a href="/" { "← Zurück" } }
        },
    )
}

/// Add the HTML UI routes to the panel router (state attached by caller).
pub(crate) fn add_routes(router: axum::Router<AppState>) -> axum::Router<AppState> {
    router
        .route("/", get(home))
        .route("/login", get(login_page).post(login_post))
        .route("/logout", post(logout_post))
        .route("/settings", get(settings_page).post(settings_post))
        .route("/clients", post(add_client))
        .route("/clients/:id/enable", post(enable))
        .route("/clients/:id/disable", post(disable))
        .route("/clients/:id/delete", post(delete))
}
