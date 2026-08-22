//! [setup] execution: copy provisioned files, run commands or a script.
//! Content and correctness are the user's responsibility.

use crate::config::SetupSection;
use std::path::Path;

pub fn run(
    setup: &SetupSection,
    setup_dir: &Path,
    box_home: &Path,
    account_name: &str,
) -> anyhow::Result<()> {
    for entry in &setup.provision {
        let src = setup_dir.join(&entry.src);
        let dest = box_home.join(&entry.dest);
        copy_owned(&src, &dest, account_name)?;
    }

    if let Some(script) = &setup.script {
        run_via_helper(&setup_dir.join(script), &[], account_name)?;
    } else {
        for cmd in &setup.commands {
            run_via_helper_shell(cmd, account_name)?;
        }
    }
    Ok(())
}

/// Copy, never symlink — a symlink would point back at a host-owned file.
fn copy_owned(_src: &Path, _dest: &Path, _account_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("setup::copy_owned not yet implemented")
}

fn run_via_helper(_binary: &Path, _args: &[String], _account_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("setup::run_via_helper not yet implemented")
}

fn run_via_helper_shell(_cmd: &str, _account_name: &str) -> anyhow::Result<()> {
    anyhow::bail!("setup::run_via_helper_shell not yet implemented")
}
