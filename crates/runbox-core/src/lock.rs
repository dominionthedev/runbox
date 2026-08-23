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
//! config_hash must be computed over a CANONICAL form (the parsed struct
//! re-serialized, not raw file bytes) — hashing raw text would flag a
//! reformat or an added comment as drift, which is noise, not signal.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BoxLock {
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
    pub fn verify_against(&self, _restored_path: &std::path::Path) -> anyhow::Result<bool> {
        anyhow::bail!("lock::verify_against not yet implemented")
    }
}

/// TODO: depends on setup.rs/archive.rs landing first — config_hash needs
/// a canonical serialization strategy decided (likely: re-serialize the
/// parsed BoxToml to a normalized TOML string, hash that), and
/// setup_assets_hash needs .runbox/setup/ walked and hashed the same way
/// diff.rs's snapshot_tree does.
pub fn generate(_config: &crate::config::BoxToml, _account_name: &str) -> anyhow::Result<BoxLock> {
    anyhow::bail!("lock::generate not yet implemented")
}

