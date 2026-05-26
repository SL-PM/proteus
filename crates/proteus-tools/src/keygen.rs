//! `proteus-tools keygen` — generate Ed25519 keypairs for named clients.
//!
//! File format (both .key and .pub):
//! - single line of standard base64 of the 32-byte raw key
//! - trailing newline
//!
//! Private key files are written with mode `0600` on Unix.
//!
//! Workflow (M2):
//! ```text
//! $ proteus-tools keygen --name alice --out-dir keys
//! wrote keys/alice.key (private; mode 0600)
//! wrote keys/alice.pub (public)
//!
//! add to server config under `clients:`:
//!   alice: "BASE64..."
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Client identifier (used as filename stem).
    #[arg(short, long)]
    pub name: String,

    /// Output directory for `<name>.key` and `<name>.pub`.
    #[arg(short, long, default_value = "keys")]
    pub out_dir: PathBuf,

    /// Overwrite existing files if present.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: Args) -> Result<()> {
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;

    let key_path = args.out_dir.join(format!("{}.key", args.name));
    let pub_path = args.out_dir.join(format!("{}.pub", args.name));

    if !args.force {
        if key_path.exists() {
            bail!("{} exists; use --force to overwrite", key_path.display());
        }
        if pub_path.exists() {
            bail!("{} exists; use --force to overwrite", pub_path.display());
        }
    }

    let signing = SigningKey::generate(&mut OsRng);
    let secret_b64 = B64.encode(signing.to_bytes());
    let public_b64 = B64.encode(signing.verifying_key().to_bytes());

    write_text(&key_path, &secret_b64)?;
    set_private_perms(&key_path)?;
    write_text(&pub_path, &public_b64)?;

    println!("wrote {} (private; mode 0600)", key_path.display());
    println!("wrote {} (public)", pub_path.display());
    println!();
    println!("add to server config under `clients:`:");
    println!("  {}: \"{}\"", args.name, public_b64);

    Ok(())
}

fn write_text(path: &Path, body: &str) -> Result<()> {
    std::fs::write(path, format!("{body}\n")).with_context(|| format!("write {}", path.display()))
}

#[cfg(unix)]
fn set_private_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
    use tempfile::tempdir;

    fn args_for(name: &str, dir: &Path, force: bool) -> Args {
        Args {
            name: name.into(),
            out_dir: dir.to_path_buf(),
            force,
        }
    }

    #[test]
    fn generates_keypair_and_public_matches_secret() {
        let dir = tempdir().unwrap();
        run(args_for("alice", dir.path(), false)).unwrap();

        let secret_b64 = std::fs::read_to_string(dir.path().join("alice.key"))
            .unwrap()
            .trim()
            .to_string();
        let pub_b64 = std::fs::read_to_string(dir.path().join("alice.pub"))
            .unwrap()
            .trim()
            .to_string();

        let secret_bytes = B64.decode(&secret_b64).unwrap();
        let pub_bytes = B64.decode(&pub_b64).unwrap();
        assert_eq!(secret_bytes.len(), SECRET_KEY_LENGTH);
        assert_eq!(pub_bytes.len(), PUBLIC_KEY_LENGTH);

        let mut arr = [0u8; SECRET_KEY_LENGTH];
        arr.copy_from_slice(&secret_bytes);
        let signing = SigningKey::from_bytes(&arr);
        assert_eq!(&signing.verifying_key().to_bytes()[..], &pub_bytes[..]);
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let dir = tempdir().unwrap();
        run(args_for("alice", dir.path(), false)).unwrap();
        let err = run(args_for("alice", dir.path(), false)).unwrap_err();
        assert!(
            err.to_string().contains("exists"),
            "expected 'exists', got: {err}"
        );
    }

    #[test]
    fn force_overwrites_existing() {
        let dir = tempdir().unwrap();
        run(args_for("alice", dir.path(), false)).unwrap();
        let first = std::fs::read_to_string(dir.path().join("alice.key")).unwrap();
        run(args_for("alice", dir.path(), true)).unwrap();
        let second = std::fs::read_to_string(dir.path().join("alice.key")).unwrap();
        assert_ne!(first, second, "regenerated key should differ");
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        run(args_for("alice", dir.path(), false)).unwrap();
        let mode = std::fs::metadata(dir.path().join("alice.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn two_runs_produce_different_keys() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        run(args_for("alice", dir1.path(), false)).unwrap();
        run(args_for("alice", dir2.path(), false)).unwrap();
        let k1 = std::fs::read_to_string(dir1.path().join("alice.key")).unwrap();
        let k2 = std::fs::read_to_string(dir2.path().join("alice.key")).unwrap();
        assert_ne!(k1, k2);
    }
}
