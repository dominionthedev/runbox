//! box.lock: a fingerprint for verification, not a replay script. Runbox
//! never installs anything, so there is nothing to replay.
//!
//! One config_hash over the whole spec, not split by category — [run]
//! vs [hooks] vs [network] as "policy" or "behavior" only gets more
//! arbitrary as sections accumulate. setup_assets_hash stays separate
//! because it catches something config_hash structurally can't: box.toml
//! byte-identical while a referenced .runbox/setup/ template's CONTENTS
//! silently changed.
//!
//! config_hash is computed over a re-serialized canonical form (the
//! parsed struct via toml::to_string), not raw file bytes — hashing raw
//! text would flag a reformat or an added comment as drift, which is
//! noise, not signal.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Matches config::CURRENT_BOX_SPEC_VERSION in spirit, tracked separately
/// — the lock format and the spec format can version independently.
pub const CURRENT_LOCK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct BoxLock {
    pub schema_version: u32,
    pub box_name: String,
    pub account_name: String,
    /// Which Runbox version produced this lock — a restore mismatch is
    /// only attributable to "the config changed" if this also matches;
    /// otherwise Runbox's own compilation logic may be what moved.
    pub runbox_version: String,
    pub created_at: String,
    /// This lock's own generation time — distinct from created_at, which
    /// stays fixed at first build even across re-locks.
    pub locked_at: String,
    pub lifecycle: String,
    pub interactive: bool,
    pub config_hash: String,
    pub setup_assets_hash: String,
    pub archive_hash: Option<String>,
}

impl BoxLock {
    pub fn verify_against(&self, _restored_path: &Path) -> anyhow::Result<bool> {
        anyhow::bail!("lock::verify_against not yet implemented — depends on archive::restore")
    }

    pub fn write(&self, project_dir: &Path) -> anyhow::Result<std::path::PathBuf> {
        let path = project_dir.join("box.lock");
        let toml_str = toml::to_string_pretty(self)?;
        std::fs::write(&path, toml_str)?;
        Ok(path)
    }

    pub fn load(project_dir: &Path) -> anyhow::Result<Option<BoxLock>> {
        let path = project_dir.join("box.lock");
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let lock: BoxLock = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        Ok(Some(lock))
    }
}

fn unix_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn hash_str(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

/// Hashes .runbox/setup/ contents (sorted by relative path, so ordering
/// doesn't affect the result). No directory, or an empty one, hashes to
/// a fixed sentinel rather than erroring — nothing to hash isn't a
/// failure.
fn hash_setup_assets(setup_dir: &Path) -> anyhow::Result<String> {
    if !setup_dir.exists() {
        return Ok(hash_str(""));
    }
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![setup_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();

    let mut hasher = Sha256::new();
    for path in paths {
        let rel = path.strip_prefix(setup_dir).unwrap_or(&path);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(std::fs::read(&path)?);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Generates a fresh lock, preserving `created_at` from an existing one
/// at the same path if present — first-build time stays fixed across
/// re-locks, only `locked_at` moves.
pub fn generate(
    config: &crate::config::BoxToml,
    account_name: &str,
    project_dir: &Path,
) -> anyhow::Result<BoxLock> {
    let setup_dir = project_dir.join(".runbox").join("setup");
    let config_hash = hash_str(&toml::to_string(config)?);
    let setup_assets_hash = hash_setup_assets(&setup_dir)?;

    let created_at = BoxLock::load(project_dir)?
        .map(|existing| existing.created_at)
        .unwrap_or_else(unix_timestamp);

    Ok(BoxLock {
        schema_version: CURRENT_LOCK_SCHEMA_VERSION,
        box_name: config.box_.name.clone(),
        account_name: account_name.to_string(),
        runbox_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at,
        locked_at: unix_timestamp(),
        lifecycle: format!("{:?}", config.box_.lifecycle),
        interactive: config.box_.interactive,
        config_hash,
        setup_assets_hash,
        archive_hash: None,
    })
}
