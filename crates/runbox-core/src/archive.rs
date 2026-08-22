//! .box snapshot/restore. Project is explicitly excluded — it's already
//! git-tracked on host. Scope: state [setup] can't deterministically
//! regenerate (generated secrets, seeded data) plus explicit extra paths.

use std::path::{Path, PathBuf};

pub struct ArchiveScope {
    pub setup_produced_paths: Vec<PathBuf>,
    pub explicit_extra_paths: Vec<PathBuf>,
}

pub fn snapshot(_box_home: &Path, _scope: &ArchiveScope, _dest: &Path) -> anyhow::Result<String> {
    anyhow::bail!("archive::snapshot not yet implemented")
}

pub fn restore(_archive: &Path, _dest_box_home: &Path) -> anyhow::Result<()> {
    anyhow::bail!("archive::restore not yet implemented")
}
