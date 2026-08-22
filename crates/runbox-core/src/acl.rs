//! ACL grant/revoke on the real, in-place project directory. Chosen over
//! a POSIX group for per-box precision without shared-group proliferation.
//! Inheritance must be on, or the box's writes lock the host account out
//! of its own output.
//!
//! Grant is lazy — on first exec/shell touching a path, not required at
//! build time.

use std::path::Path;

/// TODO: `chmod +a "<account> allow read,write,execute,delete,file_inherit,directory_inherit" <path>`
/// or native `acl_set_file` — not yet decided.
pub fn grant(_project_dir: &Path, _account_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("acl::grant not yet implemented")
}

pub fn revoke(_project_dir: &Path, _account_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("acl::revoke not yet implemented")
}

pub fn is_granted(_project_dir: &Path, _account_name: &str) -> anyhow::Result<bool> {
    anyhow::bail!("acl::is_granted not yet implemented")
}
