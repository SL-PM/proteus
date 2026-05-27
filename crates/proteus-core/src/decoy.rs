//! Decoy-response snapshot format (M8.4.1).
//!
//! `proteus-tools fetch-decoy` writes the cover host's response into
//! two artifacts:
//! - body  — raw bytes, referenced from `decoy.static_page`
//! - headers — JSON in this format, referenced from `decoy.static_headers`
//!
//! The server's H3 decoy (in `proteus-server::lib::serve_h3_decoy`)
//! loads the JSON, then echoes the recorded status + headers when an
//! H3 prober hits it. A small allowlist of hop-by-hop / always-changing
//! headers is filtered out at *serve* time (not at snapshot time —
//! the snapshot stays faithful to what the cover host actually sent).
//!
//! The shape is intentionally simple — a `Vec` of `(name, value)` pairs
//! so header *order* is preserved (some HTTP/3 implementations key
//! fingerprints off the order rustls-pemfile or curl emits) and
//! repeated names (e.g. multiple `Set-Cookie`) survive the round-trip.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Snapshotted response shape. Just status + ordered headers — the body
/// lives in a separate file (`decoy.static_page`) because it's typically
/// orders of magnitude larger and benefits from being viewable with
/// `cat`/`less` without JSON-decoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecoyHeaders {
    /// HTTP status code recorded at snapshot time (e.g. 200).
    pub status: u16,
    /// Ordered list of (name, value) pairs as they appeared on the
    /// wire. Names are stored lowercase (per HTTP/2+ convention).
    pub headers: Vec<(String, String)>,
}

impl DecoyHeaders {
    /// Build from an iterator of `(name, value)` pairs. Lowercases
    /// names; preserves order + duplicates.
    pub fn from_iter<I, N, V>(status: u16, iter: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let headers = iter
            .into_iter()
            .map(|(n, v)| (n.as_ref().to_ascii_lowercase(), v.as_ref().to_string()))
            .collect();
        Self { status, headers }
    }

    /// Pretty-print the JSON snapshot — operators eyeball this file
    /// when they want to confirm the snapshot landed sanely.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize DecoyHeaders to JSON")
    }

    /// Read + parse a snapshot from disk.
    pub fn from_json_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read decoy headers {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("parse decoy headers {}", path.display()))
    }
}

/// Lowercase header names that the server REWRITES or DROPS at serve
/// time, regardless of what the snapshot says. These cause real
/// problems if echoed verbatim:
/// - `content-length` MUST match the body the server actually sends;
///   if the snapshot is from a body of different size (e.g. operator
///   re-snapshotted body without re-snapshotting headers), the prober
///   gets a corrupted response. Server recomputes.
/// - `transfer-encoding` is hop-by-hop and meaningless in H2/H3.
/// - `connection`, `keep-alive`, `proxy-*`, `upgrade`, `te`, `trailer`
///   are HTTP/1.1-only hop-by-hop headers (RFC 7230 §6.1).
/// - `date` would freeze at snapshot time — a prober that hits the
///   server six months later sees an absurd date. Server regenerates.
pub const REWRITTEN_OR_DROPPED_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "upgrade",
    "te",
    "trailer",
    "date",
];

/// True if `header_name` (case-insensitive) is one the server will
/// replace or drop at serve time.
pub fn is_rewritten_or_dropped(header_name: &str) -> bool {
    let lower = header_name.to_ascii_lowercase();
    REWRITTEN_OR_DROPPED_HEADERS.iter().any(|h| *h == lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn from_iter_lowercases_names_and_preserves_order() {
        let h = DecoyHeaders::from_iter(
            200,
            vec![
                ("Server", "nginx"),
                ("Content-Type", "text/html"),
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
            ],
        );
        assert_eq!(h.status, 200);
        assert_eq!(
            h.headers,
            vec![
                ("server".to_string(), "nginx".to_string()),
                ("content-type".to_string(), "text/html".to_string()),
                ("set-cookie".to_string(), "a=1".to_string()),
                ("set-cookie".to_string(), "b=2".to_string()),
            ]
        );
    }

    #[test]
    fn json_roundtrip() {
        let h = DecoyHeaders::from_iter(
            200,
            vec![("server", "nginx/1.27.0"), ("content-type", "text/html")],
        );
        let json = h.to_json_pretty().unwrap();
        let parsed: DecoyHeaders = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn from_json_file_reads_what_was_written() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("headers.json");
        let h = DecoyHeaders::from_iter(200, vec![("server", "nginx")]);
        std::fs::write(&path, h.to_json_pretty().unwrap()).unwrap();
        let loaded = DecoyHeaders::from_json_file(&path).unwrap();
        assert_eq!(loaded, h);
    }

    #[test]
    fn from_json_file_missing_errors_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let err = DecoyHeaders::from_json_file(&path).unwrap_err();
        assert!(err.to_string().contains("read decoy headers"));
    }

    #[test]
    fn is_rewritten_or_dropped_matches_case_insensitively() {
        assert!(is_rewritten_or_dropped("content-length"));
        assert!(is_rewritten_or_dropped("Content-Length"));
        assert!(is_rewritten_or_dropped("DATE"));
        assert!(is_rewritten_or_dropped("Transfer-Encoding"));
        assert!(!is_rewritten_or_dropped("server"));
        assert!(!is_rewritten_or_dropped("cache-control"));
        assert!(!is_rewritten_or_dropped("strict-transport-security"));
    }
}
