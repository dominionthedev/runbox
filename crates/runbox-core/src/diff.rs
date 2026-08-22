//! Pre/post-exec tree diff, replacing continuous watching. Records what
//! changed, not why — a static boundary can't attribute cause.
//!
//! Also owns the scoped +x strip: deny +x on writes outside an allowlist
//! of expected-executable paths, neutralizing hook-injection into
//! `.git/hooks` without breaking legitimate tool output.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct FileFingerprint {
    pub size: u64,
    pub mtime: SystemTime,
}

pub struct RunLog {
    pub new_files: Vec<PathBuf>,
    pub modified_files: Vec<PathBuf>,
    pub stripped_exec: Vec<PathBuf>,
    pub flagged_unexpected: Vec<PathBuf>,
    pub summarized_expected_count: usize,
}

pub fn snapshot_tree(_root: &Path) -> anyhow::Result<BTreeMap<PathBuf, FileFingerprint>> {
    anyhow::bail!("diff::snapshot_tree not yet implemented")
}

pub fn diff_and_strip(
    _before: &BTreeMap<PathBuf, FileFingerprint>,
    _after: &BTreeMap<PathBuf, FileFingerprint>,
    _exec_allowlist: &[String],
) -> anyhow::Result<RunLog> {
    anyhow::bail!("diff::diff_and_strip not yet implemented")
}
