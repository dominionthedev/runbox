//! PF anchor generation and load/unload. User-scoped via PF's `user`
//! keyword against the box account's uid.
//!
//! Rule files passed to `pfctl -a <name> -f <file>` must contain raw rule
//! lines only, no `anchor { }` wrapper — the wrapper is for pf.conf, `-a`
//! already sets the anchor context.

use crate::config::NetworkSection;
use std::path::PathBuf;
use std::process::Command;

const PF_CONF: &str = "/etc/pf.conf";
const ANCHOR_STUB: &str = "anchor \"runbox/*\"";
const RULES_DIR: &str = "/private/var/db/runbox/pf";

pub fn generate_rules(account_name: &str, net: &NetworkSection) -> anyhow::Result<String> {
    net.validate().map_err(|e| anyhow::anyhow!(e))?;

    let mut b = String::new();
    match net.mode.as_str() {
        "deny" => {
            b.push_str(&format!(
                "block out proto {{tcp udp}} user {account_name}\n"
            ));
            for entry in &net.allowlist {
                b.push_str(&format!(
                    "pass out proto tcp to {entry} user {account_name}\n"
                ));
            }
            if net.dns == "localhost-only" {
                b.push_str(&format!(
                    "pass out proto udp to 127.0.0.1 port 53 user {account_name}\n"
                ));
            }
        }
        "allow" => {
            b.push_str(&format!("pass out proto {{tcp udp}} user {account_name}\n"));
            for entry in &net.denylist {
                b.push_str(&format!(
                    "block out proto tcp to {entry} user {account_name}\n"
                ));
            }
        }
        other => anyhow::bail!("unreachable: validated network mode was {other:?}"),
    }
    Ok(b)
}

/// Idempotent — safe to call on every build.
pub fn ensure_pf_conf_stub_installed() -> anyhow::Result<()> {
    let current = std::fs::read_to_string(PF_CONF).unwrap_or_default();
    if current.lines().any(|l| l.trim() == ANCHOR_STUB) {
        return Ok(());
    }
    run_sudo(&["cp", PF_CONF, &format!("{PF_CONF}.runbox-backup")])?;
    run_sudo(&["sh", "-c", &format!("echo '{ANCHOR_STUB}' >> {PF_CONF}")])?;
    run_sudo(&["pfctl", "-f", PF_CONF])?;
    Ok(())
}

pub fn load_anchor(box_name: &str, account_name: &str, net: &NetworkSection) -> anyhow::Result<()> {
    ensure_pf_conf_stub_installed()?;

    let rules = generate_rules(account_name, net)?;
    let rules_path = rules_path_for(box_name);
    let rules_path_str = rules_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 rules path"))?;

    run_sudo(&["mkdir", "-p", RULES_DIR])?;
    run_sudo(&[
        "sh",
        "-c",
        &format!("cat > {rules_path_str} << 'PFEOF'\n{rules}PFEOF"),
    ])?;

    let enable = Command::new("sudo").args(["pfctl", "-e"]).output()?;
    let stderr = String::from_utf8_lossy(&enable.stderr);
    if !enable.status.success() && !stderr.contains("already enabled") {
        anyhow::bail!("pfctl -e failed: {stderr}");
    }

    run_sudo(&[
        "pfctl",
        "-a",
        &format!("runbox/{box_name}"),
        "-f",
        rules_path_str,
    ])?;
    Ok(())
}

pub fn unload_anchor(box_name: &str) -> anyhow::Result<()> {
    run_sudo(&["pfctl", "-a", &format!("runbox/{box_name}"), "-F", "all"])?;
    let rules_path = rules_path_for(box_name);
    if rules_path.exists() {
        run_sudo(&["rm", "-f", rules_path.to_str().unwrap()])?;
    }
    Ok(())
}

fn rules_path_for(box_name: &str) -> PathBuf {
    PathBuf::from(RULES_DIR).join(format!("{box_name}.rules"))
}

fn run_sudo(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("sudo").args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: sudo {}", args.join(" "));
    }
    Ok(())
}
