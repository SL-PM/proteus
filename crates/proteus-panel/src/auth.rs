//! Admin password hashing + verification (v0.6 M2.6).
//!
//! Uses **argon2id** (the OWASP-recommended default) via the
//! `password-hash` PHC string format, so the stored value carries its
//! own salt + parameters. Plaintext passwords never touch the DB or
//! the repo.

use anyhow::{Result, anyhow};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

/// Hash a password with a fresh random salt. Returns a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) safe to store.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored PHC hash. Returns `Ok(false)` for
/// a wrong password, `Err` only if the stored hash string is malformed.
pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| anyhow!("parse stored hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let h = hash_password("s3cret-pw").unwrap();
        assert!(h.starts_with("$argon2id$"), "got: {h}");
        assert!(verify_password("s3cret-pw", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn same_password_yields_distinct_hashes() {
        // Random salt → different PHC strings, both verify.
        let a = hash_password("pw").unwrap();
        let b = hash_password("pw").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("pw", &a).unwrap());
        assert!(verify_password("pw", &b).unwrap());
    }

    #[test]
    fn malformed_stored_hash_errors() {
        assert!(verify_password("pw", "not-a-phc-hash").is_err());
    }
}
