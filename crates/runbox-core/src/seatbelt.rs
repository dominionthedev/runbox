//! Seatbelt profile compiler. Primary enforcement boundary alongside DAC.
//!
//! Imports Apple's own bsd.sb/system.sb baseline rather than hand-listing
//! system essentials — that baseline already covers dyld, sysctl-read,
//! symlink resolution, and core mach-lookup plumbing, verified against
//! /System/Library/Sandbox/Profiles/{bsd,system}.sb directly. Apple marks
//! these files as private interface subject to change without notice;
//! importing tracks whatever's actually on the machine at run time instead
//! of embedding a snapshot that can drift from it.

pub const MACH_LOOKUP_DENY: &[&str] = &[
    "com.apple.securityd",
    "com.apple.SecurityAgent",
    "com.apple.locationd",
    "com.apple.bluetoothd",
    "com.apple.distnoted",
    "com.apple.pboard",
    "com.apple.windowserver",
    // com.apple.cfprefsd deliberately excluded: system.sb grants
    // com.apple.cfprefsd.agent/.daemon as baseline plumbing. Scoping
    // access to other apps' preference domains is a job for
    // user-preference-read/write with a preference-domain filter, not
    // mach-lookup denial of the service itself.
];

pub struct ProfileInputs<'a> {
    pub project_dir: &'a str,
    /// The box account's own home — must be granted explicitly. Not
    /// automatic; missing this blocks .zshrc, shell history, any dotfile.
    /// Found on real hardware: `.zsh_history` locking failed with EPERM
    /// because nothing granted this at all, not a locking-specific issue.
    pub home_dir: &'a str,
    pub extra_read: &'a [String],
    pub extra_write: &'a [String],
    pub network_allowed: bool,
}

pub fn compile(inputs: &ProfileInputs) -> String {
    let mut b = String::new();
    b.push_str("(version 1)\n(deny default)\n(debug deny)\n(import \"/System/Library/Sandbox/Profiles/bsd.sb\")\n\n");

    for rule in [
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow signal)",
    ] {
        b.push_str(rule);
        b.push('\n');
    }
    b.push('\n');

    b.push_str("(allow mach-lookup)\n");
    for svc in MACH_LOOKUP_DENY {
        b.push_str(&format!("(deny mach-lookup (global-name \"{svc}\"))\n"));
    }
    b.push('\n');

    // /bin, /sbin, /private/etc: not covered by bsd.sb/system.sb (which
    // grant only specific literals under /etc, e.g. passwd, protocols) —
    // box use needs broader /etc access (resolv.conf, hosts) than Apple's
    // minimal daemon-oriented set.
    //
    // /usr/bin, /usr/sbin: confirmed on real hardware — zsh denied
    // file-read-data on both. process-exec is unconditionally allowed
    // separately, so binaries under these still ran; this is specifically
    // about listing directory CONTENTS (tab completion, `ls`), a
    // different operation from executing something already known by
    // name.
    for p in ["/bin", "/sbin", "/private/etc", "/usr/bin", "/usr/sbin"] {
        b.push_str(&format!("(allow file-read* (subpath \"{p}\"))\n"));
    }
    b.push('\n');

    // /private/tmp: the SYSTEM-WIDE /tmp (real path; /tmp is a symlink),
    // distinct from TMPDIR (the per-account dir below) — confirmed on
    // real hardware via tmux failing to create /private/tmp/tmux-<uid>,
    // a well-known convention many tools use directly rather than the
    // per-account temp dir. Deliberately shared/world-writable, same as
    // it already is for every other process on the host — sticky-bit
    // protected at the OS level, not a new isolation boundary; the box
    // gets the same /tmp access anything else on the machine already has.
    b.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");

    // /dev/fd: synthetic directory exposing a process's OWN open file
    // descriptors as pseudo-files (process substitution, stdin/stdout
    // introspection). Confirmed denied for Python on real hardware.
    // Exposing a process's own fds to itself isn't a new access grant in
    // any meaningful sense.
    b.push_str("(allow file-read* (subpath \"/dev/fd\"))\n");

    // /private/var/run/utmpx: world-readable session-tracking file (who's
    // logged in on which tty) that plenty of shell/prompt tooling reads.
    // Confirmed denied for zsh on real hardware.
    b.push_str("(allow file-read* (literal \"/private/var/run/utmpx\"))\n\n");

    // user-preference-read for the generic, not-app-specific preference
    // domain — confirmed denied for diskutil and Python on real hardware.
    // Narrow: only this one domain, not a blanket preference-read allow.
    b.push_str(
        "(allow user-preference-read (preference-domain \"kCFPreferencesAnyApplication\"))\n\n",
    );

    // bsd.sb/system.sb's baseline grants sysctl-read unconditionally and
    // sysctl-write narrowly for exactly one name (kern.grade_cputype) —
    // same pattern followed here, not a blanket sysctl-write allow.
    // Confirmed on real hardware: Python/psutil's CPU-count probing
    // writes hw.logicalcpu, and denying it silently desynced bpytop's
    // internal per-core tracking, causing an IndexError crash downstream
    // — the sandbox denial was the root cause, not a bpytop bug.
    b.push_str("(allow sysctl-write (sysctl-name \"hw.logicalcpu\"))\n\n");

    b.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{}\"))\n",
        inputs.home_dir
    ));
    b.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{}\"))\n",
        inputs.project_dir
    ));
    b.push_str(&format!(
        "(allow file-read-metadata (path-ancestors \"{}\"))\n",
        inputs.project_dir
    ));
    for p in inputs.extra_read {
        b.push_str(&format!("(allow file-read* (subpath \"{p}\"))\n"));
    }
    for p in inputs.extra_write {
        b.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{p}\"))\n"
        ));
    }
    b.push('\n');

    b.push_str("(allow file-read* file-write* (subpath (param \"TMPDIR\")))\n\n");

    if inputs.network_allowed {
        b.push_str("(allow network-outbound)\n");
    } else {
        b.push_str("(deny network-outbound)\n");
    }
    b.push('\n');

    for p in [
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        b.push_str(&format!(
            "(allow file-read* file-write* (literal \"{p}\"))\n"
        ));
    }
    // Literal, not subpath — confirmed zsh denied file-read-data on the
    // bare /dev directory (listing), but subpath would recursively grant
    // read access to raw device data under /dev (disk devices etc.),
    // which is a very different and much bigger grant than "can list
    // what's in this directory."
    b.push_str("(allow file-read-data (literal \"/dev\"))\n");
    // /dev/tty alone (from the loop above) only ever covered read/write —
    // confirmed on real hardware via (debug deny) log output that less
    // and fzf both explicitly open("/dev/tty") fresh (bypassing inherited
    // stdin entirely) and then ioctl() it directly. TTY_DEVICE below
    // covers the inherited-fd path; this covers the "open the alias
    // directly" path — two different ways programs reach the terminal,
    // both needed.
    b.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
    b.push('\n');

    // TTY_DEVICE is the box's actual controlling terminal (/dev/ttysNNN),
    // resolved by runbox-helper via ttyname_r after the privilege drop —
    // same reasoning as TMPDIR, unpredictable per session. Missing this
    // specifically (file-ioctl, not just read/write) was confirmed on
    // real hardware to break zsh's own internal tcsetpgrp call —
    // /dev/tty above covers read/write, not the ioctls interactive shells
    // and REPLs need for job control and raw terminal mode.
    b.push_str("(allow file-ioctl file-read* file-write* (literal (param \"TTY_DEVICE\")))\n");

    b
}

pub const PROFILES_DIR: &str = "/private/var/db/runbox/profiles";

/// Deterministic profile path for a box — the same rule runbox-helper
/// validates a passed-in --seatbelt-profile path against, so both sides
/// agree on where profiles live without duplicating the join logic.
pub fn profile_path_for(box_name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(PROFILES_DIR).join(format!("{box_name}.sb"))
}

/// Compiles and persists the profile. Applied later, at exec time, via
/// sandbox_init_with_parameters() with TMPDIR bound to the box account's
/// real (symlink-resolved) per-account temp directory — resolved by
/// runbox-helper after the privilege drop, not before; TMPDIR is
/// per-account, confirmed on real hardware, not assumed.
pub fn write_profile(box_name: &str, inputs: &ProfileInputs) -> anyhow::Result<std::path::PathBuf> {
    use std::process::Command;

    let profile = compile(inputs);
    let path = profile_path_for(box_name);
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 profile path"))?;

    let status = Command::new("sudo")
        .args(["mkdir", "-p", PROFILES_DIR])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to create {PROFILES_DIR}");
    }

    let status = Command::new("sudo")
        .args([
            "sh",
            "-c",
            &format!("cat > {path_str} << 'SBEOF'\n{profile}SBEOF"),
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to write profile to {path_str}");
    }

    Ok(path)
}

/// Removes the compiled profile — root-owned, so this needs sudo, same
/// as write_profile. Missing entry is not an error; there's nothing to
/// clean up if it was never written.
pub fn remove_profile(box_name: &str) -> anyhow::Result<()> {
    use std::process::Command;

    let path = profile_path_for(box_name);
    if !path.exists() {
        return Ok(());
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 profile path"))?;

    let status = Command::new("sudo").args(["rm", "-f", path_str]).status()?;
    if !status.success() {
        anyhow::bail!("failed to remove {path_str}");
    }
    Ok(())
}
