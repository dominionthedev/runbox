//! ACL grant/revoke on real host paths — the project directory and any
//! [permissions] extra paths. Chosen over a POSIX group for per-box
//! precision without shared-group proliferation. Inheritance must be on,
//! or the box's writes lock the host account out of its own output.
//!
//! Uses `chmod +a`/`-a` rather than native `acl_set_file` — no unsafe
//! FFI, and the ACE string is symmetric between grant and revoke so
//! `chmod -a` reliably matches what `chmod +a` added — as long as the
//! same GrantMode is used for both. Revoking with the wrong mode won't
//! match the ACE and silently no-ops; callers must track which mode a
//! path was granted with.
//!
//! Runs unprivileged, deliberately — the project directory is normally
//! owned by the invoking host user, who can already modify its own ACL
//! without sudo. Declaring a [permissions] path the host user doesn't own
//! will fail here with a permission error rather than silently escalating
//! to sudo.

use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMode {
    ReadOnly,
    ReadWrite,
}

fn ace_string(account_name: &str, mode: GrantMode) -> String {
    match mode {
        GrantMode::ReadOnly => {
            format!("{account_name} allow read,execute,file_inherit,directory_inherit")
        }
        GrantMode::ReadWrite => {
            format!("{account_name} allow read,write,execute,delete,file_inherit,directory_inherit")
        }
    }
}

pub fn grant(path: &Path, account_name: &str, mode: GrantMode) -> anyhow::Result<()> {
    if is_granted(path, account_name, mode)? {
        return Ok(()); // idempotent — chmod +a would otherwise duplicate the ACE
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path"))?;
    let status = Command::new("chmod")
        .args(["+a", &ace_string(account_name, mode), path_str])
        .status()?;
    if !status.success() {
        anyhow::bail!("chmod +a failed for {path_str}");
    }
    Ok(())
}

pub fn revoke(path: &Path, account_name: &str, mode: GrantMode) -> anyhow::Result<()> {
    if !is_granted(path, account_name, mode)? {
        return Ok(());
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path"))?;
    let status = Command::new("chmod")
        .args(["-a", &ace_string(account_name, mode), path_str])
        .status()?;
    if !status.success() {
        anyhow::bail!("chmod -a failed for {path_str}");
    }
    Ok(())
}

pub fn is_granted(path: &Path, account_name: &str, mode: GrantMode) -> anyhow::Result<bool> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path"))?;
    let output = Command::new("ls").args(["-le", path_str]).output()?;
    if !output.status.success() {
        anyhow::bail!("ls -le failed for {path_str} — does it exist?");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let marker = match mode {
        GrantMode::ReadOnly => "read,execute",
        GrantMode::ReadWrite => "read,write",
    };
    Ok(text
        .lines()
        .any(|line| line.contains(account_name) && line.contains(marker) && line.contains("allow")))
}
