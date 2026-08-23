//! Headless box supervision via launchd — not a persistent runboxd.
//! `runbox start` writes a LaunchAgent plist whose ProgramArguments
//! re-invoke `runbox exec` itself, then hands supervision to launchd;
//! `runbox stop` unloads it. launchd is the daemon; Runbox never runs one
//! of its own, consistent with the earlier decision against a runboxd.
//!
//! Unverified on real hardware — plist shape and launchctl invocation
//! follow documented conventions, not yet run, unlike the sandbox_init
//! work which was actually tested.

use std::path::PathBuf;
use std::process::Command;

pub fn label_for(box_name: &str) -> String {
    format!("dev.dominionthe.runbox.{box_name}")
}

pub fn plist_path(box_name: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", label_for(box_name))))
}

/// `runbox_binary` re-invokes the CLI itself (`runbox exec`) under
/// launchd's supervision — the same path as a manual invocation, not a
/// separate mechanism.
pub fn write_plist(
    box_name: &str,
    runbox_binary: &str,
    project_dir: &str,
    log_dir: &std::path::Path,
) -> anyhow::Result<PathBuf> {
    let label = label_for(box_name);
    let stdout_log = log_dir.join(format!("{box_name}.stdout.log"));
    let stderr_log = log_dir.join(format!("{box_name}.stderr.log"));

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{runbox_binary}</string>
        <string>run-headless</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{project_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        stdout_log.display(),
        stderr_log.display()
    );

    let path = plist_path(box_name)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(log_dir)?;
    std::fs::write(&path, plist)?;
    Ok(path)
}

fn gui_target() -> anyhow::Result<String> {
    let uid = unsafe { libc::getuid() };
    Ok(format!("gui/{uid}"))
}

pub fn bootstrap(box_name: &str) -> anyhow::Result<()> {
    let path = plist_path(box_name)?;
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 plist path"))?;
    let target = gui_target()?;
    let status = Command::new("launchctl")
        .args(["bootstrap", &target, path_str])
        .status()?;
    if !status.success() {
        anyhow::bail!("launchctl bootstrap failed for {box_name}");
    }
    Ok(())
}

/// A non-loaded target is not an error here — "already stopped" is a
/// valid outcome of `runbox stop`, not a failure.
pub fn bootout(box_name: &str) -> anyhow::Result<()> {
    let target = format!("{}/{}", gui_target()?, label_for(box_name));
    let _ = Command::new("launchctl")
        .args(["bootout", &target])
        .status()?;
    Ok(())
}

pub fn is_running(box_name: &str) -> anyhow::Result<bool> {
    let target = format!("{}/{}", gui_target()?, label_for(box_name));
    let status = Command::new("launchctl")
        .args(["print", &target])
        .output()?;
    Ok(status.status.success())
}
