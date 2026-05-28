//! Management HTTP API + session auth (v0.6 M2.6b).
//!
//! - `POST /api/login`  — username+password (JSON) → argon2 verify →
//!   sets an httponly session cookie.
//! - `POST /api/logout` — clears the session.
//! - Client CRUD (all require a valid session cookie):
//!   `GET /api/clients`, `POST /api/clients` (server-side keygen if no
//!   pubkey given), `GET|DELETE /api/clients/:id`,
//!   `POST /api/clients/:id/{enable,disable}`.
//!
//! Sessions are an in-memory token store (random 256-bit token → cookie).
//! They're lost on restart (re-login) — fine for a single-admin panel;
//! a persistent/DB-backed store can come later.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router, async_trait,
    extract::{FromRequestParts, Path, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    auth,
    db::{Client, Db},
};

pub(crate) const SESSION_COOKIE: &str = "psid";
const SESSION_TTL: Duration = Duration::from_secs(8 * 3600); // 8 hours

/// Shared application state: the client store + the live session map.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    username: String,
    expires: Instant,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn create_session(&self, username: &str) -> String {
        let token = random_b64(32, &URL_SAFE_NO_PAD);
        let now = Instant::now();
        let mut s = self.sessions.lock().expect("session lock");
        s.retain(|_, sess| sess.expires > now); // opportunistic GC
        s.insert(
            token.clone(),
            Session {
                username: username.to_string(),
                expires: now + SESSION_TTL,
            },
        );
        token
    }

    pub(crate) fn validate_session(&self, token: &str) -> Option<String> {
        let s = self.sessions.lock().expect("session lock");
        s.get(token)
            .filter(|sess| sess.expires > Instant::now())
            .map(|sess| sess.username.clone())
    }

    pub(crate) fn destroy_session(&self, token: &str) {
        self.sessions.lock().expect("session lock").remove(token);
    }
}

// ----------------- auth extractor -----------------

/// Present only if the request carries a valid session cookie. Used as
/// a guard on every protected handler.
pub struct AdminAuth {
    #[allow(dead_code)]
    pub username: String,
}

#[async_trait]
impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or(ApiError::Unauthorized)?;
        let username = state
            .validate_session(&token)
            .ok_or(ApiError::Unauthorized)?;
        Ok(AdminAuth { username })
    }
}

// ----------------- errors -----------------

pub enum ApiError {
    Unauthorized,
    NotFound,
    Conflict(String),
    BadRequest(String),
    Internal(String),
}

fn internal<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError::Internal(e.to_string())
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, msg).into_response()
    }
}

// ----------------- DTOs -----------------

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct CreateClientReq {
    /// Optional client_id; auto-generated if omitted.
    id: Option<String>,
    #[serde(default)]
    label: String,
    /// If omitted, the server generates a keypair and returns the
    /// private key once in the response.
    pubkey_b64: Option<String>,
    quota_bytes: Option<i64>,
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct CreateClientResp {
    id: String,
    pubkey_b64: String,
    /// Present only when the server generated the keypair — shown once;
    /// hand this to the customer, it is not stored.
    private_key_b64: Option<String>,
}

// ----------------- handlers -----------------

async fn login(
    State(st): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginReq>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    let stored = st
        .db
        .get_admin_hash(&req.username)
        .await
        .map_err(internal)?;
    let ok = match stored {
        Some(hash) => auth::verify_password(&req.password, &hash).unwrap_or(false),
        None => false,
    };
    if !ok {
        return Err(ApiError::Unauthorized);
    }
    let token = st.create_session(&req.username);
    Ok((jar.add(session_cookie(token)), StatusCode::NO_CONTENT))
}

async fn logout(State(st): State<AppState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        st.destroy_session(c.value());
    }
    (
        jar.remove(Cookie::from(SESSION_COOKIE)),
        StatusCode::NO_CONTENT,
    )
}

async fn list_clients(
    _: AdminAuth,
    State(st): State<AppState>,
) -> Result<Json<Vec<Client>>, ApiError> {
    let clients = st.db.list_clients().await.map_err(internal)?;
    Ok(Json(clients))
}

async fn create_client(
    _: AdminAuth,
    State(st): State<AppState>,
    Json(req): Json<CreateClientReq>,
) -> Result<(StatusCode, Json<CreateClientResp>), ApiError> {
    let id = req.id.filter(|s| !s.is_empty()).unwrap_or_else(random_id);

    if st.db.get_client(&id).await.map_err(internal)?.is_some() {
        return Err(ApiError::Conflict(format!("client '{id}' already exists")));
    }

    let (pubkey_b64, private_key_b64) = match req.pubkey_b64 {
        Some(pk) => (pk, None),
        None => {
            let (priv_b64, pub_b64) = generate_keypair();
            (pub_b64, Some(priv_b64))
        }
    };

    st.db
        .add_client(
            &id,
            &req.label,
            &pubkey_b64,
            req.quota_bytes,
            req.expires_at.as_deref(),
        )
        .await
        .map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateClientResp {
            id,
            pubkey_b64,
            private_key_b64,
        }),
    ))
}

async fn get_client(
    _: AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Client>, ApiError> {
    st.db
        .get_client(&id)
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn enable_client(
    _: AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    set_enabled(&st, &id, true).await
}

async fn disable_client(
    _: AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    set_enabled(&st, &id, false).await
}

async fn set_enabled(st: &AppState, id: &str, enabled: bool) -> Result<StatusCode, ApiError> {
    if st.db.set_enabled(id, enabled).await.map_err(internal)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn delete_client(
    _: AdminAuth,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if st.db.delete_client(&id).await.map_err(internal)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ----------------- router + helpers -----------------

/// Build the full panel router: `/health` + the JSON management API
/// (`/api/*`) plus the HTML admin UI (M4.6, added by [`crate::web`],
/// which owns `/`, `/login`, `/logout`, and the form-post routes).
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/clients", get(list_clients).post(create_client))
        .route("/api/clients/:id", get(get_client).delete(delete_client))
        .route("/api/clients/:id/enable", post(enable_client))
        .route("/api/clients/:id/disable", post(disable_client));
    crate::web::add_routes(api).with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// A fresh auto-generated client id (`c-<random>`), used when the
/// caller doesn't supply one.
pub(crate) fn random_id() -> String {
    format!("c-{}", random_b64(6, &URL_SAFE_NO_PAD))
}

/// Generate a fresh Ed25519 keypair, returning `(private_b64, public_b64)`
/// in the same standard-base64 form `proteus-tools keygen` produces.
pub(crate) fn generate_keypair() -> (String, String) {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    (B64.encode(sk.to_bytes()), B64.encode(pk.to_bytes()))
}

fn random_b64(n: usize, engine: &base64::engine::GeneralPurpose) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    engine.encode(buf)
}

/// Build the session cookie (httponly, SameSite=Strict, path=/). Shared
/// by the JSON login (api) and the HTML login (web).
pub(crate) fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}
