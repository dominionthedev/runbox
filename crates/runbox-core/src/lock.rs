//! box.lock: a fingerprint for verification, not a replay script. Runbox
//! never installs anything, so there is nothing to replay.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BoxLock {
    pub box_name: String,
    pub account_name: String,
    pub created_at: String,
    pub lifecycle: String,
    pub interactive: bool,
    pub policy_hash: String,
    pub setup_hash: String,
    pub archive_hash: Option<String>,
}

impl BoxLock {
    pub fn verify_against(&self, _restored_path: &std::path::Path) -> anyhow::Result<bool> {
        anyhow::bail!("lock::verify_against not yet implemented")
    }
}
