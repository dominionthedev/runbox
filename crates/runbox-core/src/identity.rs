//! Dedicated macOS user provisioning. Naming scheme must match
//! runbox-helper's `is_valid_account_name`: `_runbox_<8 lowercase hex>`.
//!
//! Uses `dscl` directly, not `sysadminctl` — need a hidden, no-login
//! service account, not an interactive one under /Users.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

pub const HOMES_ROOT: &str = "/private/var/db/runbox/homes";

/// Root-owned, 0600. One account name per line. Cross-checked by
/// runbox-helper's `is_runbox_managed_account`. Path is duplicated (not
/// shared via a crate dependency) to keep runbox-helper's dependency tree
/// minimal — update both copies together if this changes.
pub const REGISTRY_PATH: &str = "/private/var/db/runbox/managed_accounts";

/// Where runbox-helper must be installed: root-owned, setuid bit set.
/// `cargo build` alone never produces this state — see `make
/// install-helper`. Not yet automated end-to-end; flagged, not hidden.
pub const HELPER_INSTALL_PATH: &str = "/usr/local/libexec/runbox-helper";

const UID_RANGE: std::ops::Range<u32> = 620..700;
const GID_RANGE: std::ops::Range<u32> = 620..700;

pub fn account_name_for_box(box_name: &str) -> String {
    let hash = Sha256::digest(box_name.as_bytes());
    format!(
        "_runbox_{:08x}",
        u32::from_be_bytes(hash[0..4].try_into().unwrap())
    )
}

pub struct ProvisionedAccount {
    pub account_name: String,
    pub group_name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

pub fn provision(box_name: &str, shell: &str) -> anyhow::Result<ProvisionedAccount> {
    let account_name = account_name_for_box(box_name);
    let group_name = account_name.clone();

    if account_exists(&account_name)? {
        anyhow::bail!(
            "account {account_name} already exists — run `runbox destroy` or `runbox doctor`"
        );
    }

    let uid = find_available_uid()?;
    let gid = find_available_gid()?;
    let home = PathBuf::from(HOMES_ROOT).join(&account_name);

    create_group(&group_name, gid)?;
    create_user(&account_name, &group_name, uid, gid, &home, box_name)?;
    create_home_dir(&home, uid, gid)?;
    write_default_rc(&home, uid, gid, box_name, shell)?;
    register_managed_account(&account_name)?;

    Ok(ProvisionedAccount {
        account_name,
        group_name,
        uid,
        gid,
        home,
    })
}

pub fn deprovision(account_name: &str) -> anyhow::Result<()> {
    if !account_exists(account_name)? {
        anyhow::bail!("account {account_name} does not exist");
    }

    let home = PathBuf::from(HOMES_ROOT).join(account_name);

    run_sudo(&["dscl", ".", "-delete", &format!("/Users/{account_name}")])?;
    run_sudo(&["dscl", ".", "-delete", &format!("/Groups/{account_name}")])?;
    if home.exists() {
        run_sudo(&["rm", "-rf", home.to_str().unwrap()])?;
    }
    unregister_managed_account(account_name)?;

    Ok(())
}

/// Detects accounts registered but missing from the directory service
/// (interrupted build). Does not detect the reverse case (account exists,
/// unregistered) — needs a full /Users scan, not yet implemented.
pub fn find_orphans() -> anyhow::Result<Vec<String>> {
    let registered = read_registry()?;
    let mut orphans = Vec::new();
    for name in &registered {
        if !account_exists(name)? {
            orphans.push(name.clone());
        }
    }
    Ok(orphans)
}

pub fn account_exists(account_name: &str) -> anyhow::Result<bool> {
    let status = Command::new("dscl")
        .args([".", "-read", &format!("/Users/{account_name}")])
        .output()?;
    Ok(status.status.success())
}

fn find_available_uid() -> anyhow::Result<u32> {
    let output = Command::new("dscl")
        .args([".", "-list", "/Users", "UniqueID"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let used: std::collections::HashSet<u32> = text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|id| id.parse::<u32>().ok())
        .collect();
    UID_RANGE
        .into_iter()
        .find(|uid| !used.contains(uid))
        .ok_or_else(|| anyhow::anyhow!("no free UID in {UID_RANGE:?}"))
}

fn find_available_gid() -> anyhow::Result<u32> {
    let output = Command::new("dscl")
        .args([".", "-list", "/Groups", "PrimaryGroupID"])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let used: std::collections::HashSet<u32> = text
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|id| id.parse::<u32>().ok())
        .collect();
    GID_RANGE
        .into_iter()
        .find(|gid| !used.contains(gid))
        .ok_or_else(|| anyhow::anyhow!("no free GID in {GID_RANGE:?}"))
}

fn create_group(group_name: &str, gid: u32) -> anyhow::Result<()> {
    let path = format!("/Groups/{group_name}");
    run_sudo(&["dscl", ".", "-create", &path])?;
    run_sudo(&[
        "dscl",
        ".",
        "-create",
        &path,
        "PrimaryGroupID",
        &gid.to_string(),
    ])?;
    run_sudo(&[
        "dscl",
        ".",
        "-create",
        &path,
        "RealName",
        &format!("Runbox group: {group_name}"),
    ])?;
    Ok(())
}

fn create_user(
    account_name: &str,
    group_name: &str,
    uid: u32,
    gid: u32,
    home: &std::path::Path,
    box_name: &str,
) -> anyhow::Result<()> {
    let path = format!("/Users/{account_name}");
    let home_str = home
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 home path"))?;

    run_sudo(&["dscl", ".", "-create", &path])?;
    run_sudo(&["dscl", ".", "-create", &path, "UserShell", "/usr/bin/false"])?;
    run_sudo(&[
        "dscl",
        ".",
        "-create",
        &path,
        "RealName",
        &format!("Runbox: {box_name}"),
    ])?;
    run_sudo(&["dscl", ".", "-create", &path, "UniqueID", &uid.to_string()])?;
    run_sudo(&[
        "dscl",
        ".",
        "-create",
        &path,
        "PrimaryGroupID",
        &gid.to_string(),
    ])?;
    run_sudo(&["dscl", ".", "-create", &path, "NFSHomeDirectory", home_str])?;
    run_sudo(&["dscl", ".", "-create", &path, "IsHidden", "1"])?;
    run_sudo(&[
        "dscl",
        ".",
        "-create",
        &path,
        "AuthenticationAuthority",
        ";DisabledUser;",
    ])?;
    run_sudo(&[
        "dscl",
        ".",
        "-append",
        &format!("/Groups/{group_name}"),
        "GroupMembership",
        account_name,
    ])?;
    Ok(())
}

fn create_home_dir(home: &std::path::Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    let home_str = home
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 home path"))?;
    run_sudo(&["mkdir", "-p", home_str])?;
    run_sudo(&["chown", &format!("{uid}:{gid}"), home_str])?;
    run_sudo(&["chmod", "700", home_str])?;
    Ok(())
}

/// Idempotent prompt injection ported from the pre-rebuild implementation
/// — strip-then-prepend, so it survives repeated sourcing rather than
/// accumulating duplicate prefixes. The box's own rc file; edit it
/// freely, it's not regenerated after provisioning.
///
/// [box].shell was previously ignored entirely here — this always wrote
/// .zshrc regardless of what shell was actually configured, so setting
/// shell = "/bin/bash" got a working shell with zero customization
/// (bash reads .bashrc, never touches .zshrc). Dispatches on the shell's
/// basename now. Unrecognized shells get no rc file at all, on purpose —
/// writing syntax for a shell we haven't actually verified is worse than
/// silently doing nothing; a plain, uncustomized shell is at least
/// correct.
fn write_default_rc(
    home: &std::path::Path,
    uid: u32,
    gid: u32,
    box_name: &str,
    shell: &str,
) -> anyhow::Result<()> {
    let shell_name = std::path::Path::new(shell)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let (rc_filename, content) = match shell_name {
        "zsh" => (
            ".zshrc",
            format!(
                r#"# Written by runbox at provision time. Yours to customize —
# not regenerated after this.
export RUNBOX_BOX_NAME="{box_name}"
__RUNBOX_PREFIX='[runbox:{box_name}] '

__runbox_prompt() {{
    PS1="${{PS1#"$__RUNBOX_PREFIX"}}"
    PS1="${{__RUNBOX_PREFIX}}${{PS1}}"
}}
if (( ! ${{precmd_functions[(Ie)__runbox_prompt]:-0}} )); then
    precmd_functions+=(__runbox_prompt)
fi
"#
            ),
        ),
        "bash" => (
            // Interactive non-login shell (which is what `runbox shell`
            // execs) reads .bashrc, not .bash_profile/.profile.
            // macOS ships bash 3.2 (GPLv3, never upgraded) — this stays
            // 3.2-compatible on purpose: PROMPT_COMMAND as a plain
            // string, `case` instead of anything newer.
            ".bashrc",
            format!(
                r#"# Written by runbox at provision time. Yours to customize —
# not regenerated after this.
export RUNBOX_BOX_NAME="{box_name}"
__RUNBOX_PREFIX='[runbox:{box_name}] '

__runbox_prompt() {{
    case "$PS1" in
        "$__RUNBOX_PREFIX"*) ;;
        *) PS1="${{__RUNBOX_PREFIX}}${{PS1}}" ;;
    esac
}}

case "$PROMPT_COMMAND" in
    *__runbox_prompt*) ;;
    "") PROMPT_COMMAND="__runbox_prompt" ;;
    *) PROMPT_COMMAND="__runbox_prompt; $PROMPT_COMMAND" ;;
esac
"#
            ),
        ),
        other => {
            println!(
                "note: no rc/prompt customization for shell {other:?} yet (only zsh, bash) — \
                 shell will work, just without the [runbox:{box_name}] prompt prefix"
            );
            return Ok(());
        }
    };

    let path = home.join(rc_filename);
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 rc path"))?;

    run_sudo(&[
        "sh",
        "-c",
        &format!("cat > {path_str} << 'RCEOF'\n{content}RCEOF"),
    ])?;
    run_sudo(&["chown", &format!("{uid}:{gid}"), path_str])?;
    Ok(())
}

fn register_managed_account(account_name: &str) -> anyhow::Result<()> {
    run_sudo(&["mkdir", "-p", "/private/var/db/runbox"])?;
    run_sudo(&["touch", REGISTRY_PATH])?;
    run_sudo(&["chmod", "600", REGISTRY_PATH])?;
    run_sudo(&[
        "sh",
        "-c",
        &format!("echo {account_name} >> {REGISTRY_PATH}"),
    ])?;
    Ok(())
}

fn unregister_managed_account(account_name: &str) -> anyhow::Result<()> {
    if !std::path::Path::new(REGISTRY_PATH).exists() {
        return Ok(());
    }
    // Not `&&` — grep -v exits 1 when it finds zero non-matching lines,
    // which is the normal/expected case when the registry has exactly
    // one account and it's the one being removed. `&&` would then skip
    // `mv` entirely and report the whole thing as failed even though
    // nothing went wrong. `;` runs mv regardless of grep's match count —
    // the redirect still produces a valid (possibly empty) tmp file.
    let cmd = format!(
        "grep -v '^{account_name}$' {REGISTRY_PATH} > {REGISTRY_PATH}.tmp; mv {REGISTRY_PATH}.tmp {REGISTRY_PATH}"
    );
    run_sudo(&["sh", "-c", &cmd])?;
    Ok(())
}

/// Root-owned 0600 by design. Tries unprivileged read first; on
/// permission denial, retries narrowly via `sudo cat` rather than
/// requiring the whole `runbox doctor` invocation to run as root.
fn read_registry() -> anyhow::Result<Vec<String>> {
    if !std::path::Path::new(REGISTRY_PATH).exists() {
        return Ok(Vec::new());
    }
    let contents = match std::fs::read_to_string(REGISTRY_PATH) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let output = Command::new("sudo").args(["cat", REGISTRY_PATH]).output()?;
            if !output.status.success() {
                anyhow::bail!(
                    "permission denied reading {REGISTRY_PATH}, and sudo cat also failed"
                );
            }
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Err(e) => anyhow::bail!("reading {REGISTRY_PATH}: {e}"),
    };
    Ok(contents
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn run_sudo(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("sudo").args(args).status()?;
    if !status.success() {
        anyhow::bail!("command failed: sudo {}", args.join(" "));
    }
    Ok(())
}
