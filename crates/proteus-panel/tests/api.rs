//! Integration tests for the management API (v0.6 M2.6b).
//!
//! Drives the axum router in-process with `tower::ServiceExt::oneshot`
//! (no socket bind). Covers the auth gate (401 without/with-bad creds)
//! and the full client lifecycle through the HTTP surface.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use proteus_panel::{api, api::AppState, auth, db::Db};
use serde_json::Value;
use tower::ServiceExt; // oneshot

async fn test_app() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path().join("t.db").to_str().unwrap())
        .await
        .unwrap();
    db.set_admin("admin", &auth::hash_password("pw").unwrap())
        .await
        .unwrap();
    let app = api::router(AppState::new(db));
    (dir, app)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    serde_json::from_str(&body_string(resp).await).unwrap()
}

/// Log in as the test admin and return the `psid=...` cookie pair.
async fn login_cookie(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"pw"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "login should succeed"
    );
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie present")
        .to_str()
        .unwrap();
    // "psid=<token>; HttpOnly; SameSite=Strict; Path=/" → take the first pair.
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn wrong_password_is_401() {
    let (_d, app) = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"WRONG"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn clients_endpoint_requires_auth() {
    let (_d, app) = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_client_lifecycle() {
    let (_d, app) = test_app().await;
    let cookie = login_cookie(&app).await;

    // --- create (server-side keygen) ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/clients")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"label":"kunde1","quota_bytes":15000000000}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert!(!created["pubkey_b64"].as_str().unwrap().is_empty());
    // server generated the keypair → private key returned once
    assert!(
        created["private_key_b64"].as_str().is_some(),
        "expected a generated private key"
    );

    // --- list → exactly our client ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/clients")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"].as_str().unwrap(), id);
    assert!(list[0]["enabled"].as_bool().unwrap());
    assert_eq!(list[0]["quota_bytes"].as_i64().unwrap(), 15_000_000_000);

    // --- disable → get shows enabled=false ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/clients/{id}/disable"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/clients/{id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!body_json(resp).await["enabled"].as_bool().unwrap());

    // --- delete → then 404 ---
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/clients/{id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/clients/{id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_with_supplied_pubkey_has_no_private_key() {
    let (_d, app) = test_app().await;
    let cookie = login_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/clients")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"alice","label":"A","pubkey_b64":"Aiv/TbMjaI8STgiAstSoApoPPFAkLKYUyjNM74abrno="}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    assert_eq!(created["id"].as_str().unwrap(), "alice");
    assert!(
        created["private_key_b64"].is_null(),
        "no private key when caller supplies the pubkey"
    );
}
