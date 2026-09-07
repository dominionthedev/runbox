//! Seatbelt profile compiler. Primary enforcement boundary alongside DAC.
//!
//! Imports Apple's own bsd.sb/system.sb baseline rather than hand-listing
//! system essentials — that baseline already covers dyld, sysctl-read,
//! symlink resolution, and core mach-lookup plumbing, verified against
//! /System/Library/Sandbox/Profiles/{bsd,system}.sb directly. Apple marks
//! these files as private interface subject to change without notice;
//! importing tracks whatever's actually on the machine at run time instead
//! of embedding a snapshot that can drift from it.
//!
//! [execution] mode controls file-category tightness only. Every real
//! bug found during real-hardware testing was file-category (/usr/bin
//! listing, /dev/fd, tmux's socket dir, TTY ioctls) — none were
//! mach-lookup, sysctl, or preference-category. That's not a coincidence:
//! DAC (the dedicated account) is already the real boundary protecting
//! secrets, independent of how tight Seatbelt's file grants are — a box
//! can't read ~/.ssh/id_rsa because it doesn't own it, regardless of this
//! setting. So the file axis is the one worth making adjustable; the
//! mach-lookup deny list, the narrow sysctl-write/user-preference-read
//! grants, and (deny default) as the GLOBAL fallback for every other
//! operation category stay identical in both modes — those have been
//! doing real protective work and this setting doesn't touch them.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// File operations (file-read*, file-write*, file-ioctl) allowed
    /// unconditionally — DAC is the real boundary there, not enumerated
    /// Seatbelt grants. process-exec stays unconditional too. Default.
    Normal,
    /// Today's original behavior: narrow, enumerated file grants per
    /// path. process-exec is ALSO restricted here to the same granted
    /// subpaths — closing the "any world-executable binary can run"
    /// finding from earlier, deliberately EXCLUDING TMPDIR/tmp from the
    /// exec-allowed set (download-to-tmp-then-execute is a real hardening
    /// target, not an oversight).
    Strict,
}

impl ExecutionMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "normal" => Ok(Self::Normal),
            "strict" => Ok(Self::Strict),
            other => Err(format!(
                "[execution] mode must be \"normal\" or \"strict\", got {other:?}"
            )),
        }
    }
}

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
    /// The box account's own home — must be granted explicitly in strict
    /// mode. Not automatic; missing this blocks .zshrc, shell history,
    /// any dotfile. Found on real hardware: .zsh_history locking failed
    /// with EPERM because nothing granted this at all, not a
    /// locking-specific issue.
    pub home_dir: &'a str,
    pub extra_read: &'a [String],
    pub extra_write: &'a [String],
    pub network_allowed: bool,
    pub mode: ExecutionMode,
}

/// Strict mode's exec-allowed paths — deliberately NOT including
/// TMPDIR/tmp. Everything here also gets file-read* for the same reason
/// both are needed together: Seatbelt allowing exec doesn't help if the
/// file itself can't be opened to be exec'd.
fn strict_exec_and_read_paths<'a>(inputs: &ProfileInputs<'a>) -> Vec<&'a str> {
    let mut paths = vec![
        inputs.project_dir,
        inputs.home_dir,
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
    ];
    paths.extend(inputs.extra_read.iter().map(String::as_str));
    paths.extend(inputs.extra_write.iter().map(String::as_str));
    paths
}

pub fn compile(inputs: &ProfileInputs) -> String {
    let mut b = String::new();
    b.push_str("(version 1)\n(deny default)\n(debug deny)\n(import \"/System/Library/Sandbox/Profiles/bsd.sb\")\n\n");

    b.push_str("(allow process-fork)\n(allow signal)\n");
    match inputs.mode {
        ExecutionMode::Normal => b.push_str("(allow process-exec)\n"),
        ExecutionMode::Strict => {
            for p in strict_exec_and_read_paths(inputs) {
                b.push_str(&format!("(allow process-exec (subpath \"{p}\"))\n"));
            }
        }
    }
    b.push('\n');

    // Shared in both modes — mach-lookup, sysctl, preference-read have
    // never been the source of a real gap; this setting doesn't touch
    // them.
    b.push_str("(allow mach-lookup)\n");
    for svc in MACH_LOOKUP_DENY {
        b.push_str(&format!("(deny mach-lookup (global-name \"{svc}\"))\n"));
    }
    b.push('\n');

    b.push_str(
        "(allow user-preference-read (preference-domain \"kCFPreferencesAnyApplication\"))\n\n",
    );

    // bsd.sb/system.sb's baseline grants sysctl-read unconditionally and
    // sysctl-write narrowly for exactly one name (kern.grade_cputype) —
    // same pattern followed here, not a blanket sysctl-write allow.
    // Confirmed on real hardware: Python/psutil's CPU-count probing
    // writes hw.logicalcpu, and denying it silently desynced bpytop's
    // internal per-core tracking, causing an IndexError crash downstream.
    b.push_str("(allow sysctl-write (sysctl-name \"hw.logicalcpu\"))\n\n");

    if inputs.network_allowed {
        b.push_str("(allow network-outbound)\n");
    } else {
        b.push_str("(deny network-outbound)\n");
    }
    b.push('\n');

    match inputs.mode {
        ExecutionMode::Normal => {
            // Every real bug found this session was file-category — DAC
            // is the actual boundary for the thing that matters
            // (secrets), so enumerating every path here has been pure
            // friction. mach-lookup/sysctl/preference above are
            // unaffected by this.
            b.push_str("(allow file-read* file-write* file-ioctl)\n");
        }
        ExecutionMode::Strict => {
            for p in strict_exec_and_read_paths(inputs) {
                b.push_str(&format!("(allow file-read* (subpath \"{p}\"))\n"));
            }
            // home_dir and project_dir additionally need write, not just
            // read — extra_write already covered above for read, add
            // write here too.
            b.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                inputs.home_dir
            ));
            b.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                inputs.project_dir
            ));
            b.push_str(&format!(
                "(allow file-read-metadata (path-ancestors \"{}\"))\n",
                inputs.project_dir
            ));
            for p in inputs.extra_write {
                b.push_str(&format!("(allow file-write* (subpath \"{p}\"))\n"));
            }
            b.push('\n');

            // /private/etc: needs broader access (resolv.conf, hosts)
            // than bsd.sb/system.sb's minimal daemon-oriented literals.
            b.push_str("(allow file-read* (subpath \"/private/etc\"))\n\n");

            // /private/tmp: system-wide /tmp (real path), distinct from
            // TMPDIR below — tmux's socket dir convention. Deliberately
            // shared/world-writable, same as every other process on the
            // host already has, sticky-bit protected at the OS level.
            b.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");
            b.push_str("(allow file-read* (subpath \"/dev/fd\"))\n");
            b.push_str("(allow file-read* (literal \"/private/var/run/utmpx\"))\n\n");

            b.push_str("(allow file-read* file-write* (subpath (param \"TMPDIR\")))\n\n");

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
            b.push_str("(allow file-read-data (literal \"/dev\"))\n");
            b.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n\n");

            b.push_str(
                "(allow file-ioctl file-read* file-write* (literal (param \"TTY_DEVICE\")))\n",
            );
        }
    }

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
