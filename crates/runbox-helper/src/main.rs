// runbox-helper — the only privileged component in Runbox.
//
// Usage: runbox-helper <box-account-name> [--seatbelt-profile <path>]
//        [--env KEY=VALUE ...] [--path-extra <dir> ...] -- <binary-path> [args...]
//
// Installed setuid-root. Order, verified on real hardware before this was
// written (not assumed):
//   1. validate account name + managed-account registry
//   2. setgid/setuid — drop privilege, irreversible
//   3. confstr(_CS_DARWIN_USER_TEMP_DIR) — per-account; must run AFTER
//      the drop, since it resolves the CALLING process's own temp dir,
//      not an arbitrary target account's. Confirmed different values for
//      two different accounts on real hardware.
//   4. canonicalize the resolved path — /var/folders/... is a symlink to
//      /private/var/folders/...; Seatbelt's subpath matching operates on
//      the real path, not the symlinked alias. Confirmed: using the
//      symlinked form as the TMPDIR sandbox parameter caused every write
//      inside it to be denied; using the canonicalized form fixed it.
//   5. sandbox_init_with_parameters(profile, {TMPDIR: real_path}) — this
//      is the box's own unprivileged account sandboxing itself; not a
//      privilege-relevant step, no elevated capability involved.
//   6. --env pairs applied
//   7. execv
//
// No shell. No third-party crates beyond libc. sandbox_init_with_parameters
// has no public binding in the libc crate (private/deprecated Apple API,
// header not reliably installed) — declared manually below.

use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::process::ExitCode;

const REGISTRY_PATH: &str = "/private/var/db/runbox/managed_accounts";

/// Must match runbox_core::seatbelt::PROFILES_DIR exactly. A passed-in
/// --seatbelt-profile path outside this directory is refused — the
/// profile is applied after the privilege drop so a malicious profile
/// can't itself escalate privilege, but validating the path still keeps
/// this binary from ever loading an arbitrary, non-Runbox-managed policy.
const PROFILES_DIR: &str = "/private/var/db/runbox/profiles";

extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

fn is_valid_account_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("_runbox_") else {
        return false;
    };
    suffix.len() == 8
        && suffix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_runbox_managed_account(name: &str) -> bool {
    let Ok(contents) = std::fs::read_to_string(REGISTRY_PATH) else {
        return false;
    };
    contents.lines().any(|line| line.trim() == name)
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("runbox-helper: {msg}");
    ExitCode::FAILURE
}

struct ParsedArgs {
    account_name: String,
    seatbelt_profile: Option<String>,
    env_pairs: Vec<(String, String)>,
    path_extra: Vec<String>,
    binary_path: String,
    binary_args: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, &'static str> {
    if args.len() < 2 {
        return Err(
            "usage: runbox-helper <account> [--seatbelt-profile <path>] [--env KEY=VALUE ...] [--path-extra <dir> ...] -- <binary> [args...]",
        );
    }

    let account_name = args[1].clone();
    let mut i = 2;
    let mut seatbelt_profile = None;
    let mut env_pairs = Vec::new();
    let mut path_extra = Vec::new();

    while i < args.len() {
        match args[i].as_str() {
            "--seatbelt-profile" => {
                let path = args
                    .get(i + 1)
                    .ok_or("--seatbelt-profile requires a path argument")?;
                seatbelt_profile = Some(path.clone());
                i += 2;
            }
            "--env" => {
                let pair = args
                    .get(i + 1)
                    .ok_or("--env requires a KEY=VALUE argument")?;
                let (key, value) = pair
                    .split_once('=')
                    .ok_or("--env argument must be KEY=VALUE")?;
                if key.is_empty() {
                    return Err("--env key cannot be empty");
                }
                // Belt-and-suspenders: runbox-core already rejects PATH in
                // [env].set at config-parse time, but this binary doesn't
                // trust its caller blindly — reject it here too.
                if key == "PATH" {
                    return Err("--env cannot set PATH — use --path-extra to append instead");
                }
                env_pairs.push((key.to_string(), value.to_string()));
                i += 2;
            }
            "--path-extra" => {
                let dir = args
                    .get(i + 1)
                    .ok_or("--path-extra requires a directory argument")?;
                path_extra.push(dir.clone());
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            _ => return Err(
                "expected --seatbelt-profile, --env, --path-extra, or -- before the target binary",
            ),
        }
    }

    let binary_path = args.get(i).ok_or("missing target binary path")?.clone();
    let binary_args = args[i..].to_vec();

    Ok(ParsedArgs {
        account_name,
        seatbelt_profile,
        env_pairs,
        path_extra,
        binary_path,
        binary_args,
    })
}

/// Resolves this (already-dropped-privilege) process's real per-account
/// temp directory, canonicalized past the /var/folders symlink. Must be
/// called after setuid — see module docs.
fn resolve_real_tmpdir() -> Result<String, String> {
    let mut buf = vec![0u8; 1024];
    let len = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if len == 0 {
        return Err("confstr(_CS_DARWIN_USER_TEMP_DIR) failed".to_string());
    }
    buf.truncate(len.saturating_sub(1));
    let symlinked = String::from_utf8(buf).map_err(|_| "confstr returned non-UTF8".to_string())?;
    let symlinked = symlinked.trim_end_matches('/');

    std::fs::canonicalize(symlinked)
        .map_err(|e| format!("canonicalize({symlinked}) failed: {e}"))
        .map(|p| p.to_string_lossy().into_owned())
}

/// TMPDIR-style resolution but for the box's actual controlling terminal
/// device (/dev/ttysNNN — unpredictable per session, same reasoning as
/// TMPDIR). Missing this grant is what caused zsh's own internal
/// tcsetpgrp/ioctl call to fail with EPERM — separate from the terminal
/// handoff runbox itself does; zsh does its own on interactive startup
/// regardless. No real tty (piped/non-interactive exec) resolves to
/// /dev/null, which is already unconditionally granted — a safe no-op
/// bind rather than leaving the profile's referenced param unbound.
fn resolve_tty_device() -> String {
    let mut buf = vec![0u8; 256];
    let ret = unsafe {
        libc::ttyname_r(
            libc::STDIN_FILENO,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if ret != 0 {
        return "/dev/null".to_string();
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) };
    cstr.to_string_lossy().into_owned()
}

fn apply_sandbox(profile_path: &str, real_tmpdir: &str, tty_device: &str) -> Result<(), String> {
    if !profile_path.starts_with(PROFILES_DIR) {
        return Err(format!(
            "refusing profile outside {PROFILES_DIR}: {profile_path}"
        ));
    }

    let profile_text = std::fs::read_to_string(profile_path)
        .map_err(|e| format!("reading {profile_path}: {e}"))?;

    let c_profile =
        CString::new(profile_text).map_err(|_| "profile contains interior NUL".to_string())?;
    let tmpdir_key = CString::new("TMPDIR").unwrap();
    let tmpdir_val =
        CString::new(real_tmpdir).map_err(|_| "tmpdir path contains interior NUL".to_string())?;
    let tty_key = CString::new("TTY_DEVICE").unwrap();
    let tty_val = CString::new(tty_device)
        .map_err(|_| "tty device path contains interior NUL".to_string())?;
    let params: [*const c_char; 5] = [
        tmpdir_key.as_ptr(),
        tmpdir_val.as_ptr(),
        tty_key.as_ptr(),
        tty_val.as_ptr(),
        std::ptr::null(),
    ];

    let mut errorbuf: *mut c_char = std::ptr::null_mut();
    let ret = unsafe {
        sandbox_init_with_parameters(c_profile.as_ptr(), 0, params.as_ptr(), &mut errorbuf)
    };

    if ret != 0 {
        let msg = unsafe {
            if errorbuf.is_null() {
                "(no error message)".to_string()
            } else {
                let s = CStr::from_ptr(errorbuf).to_string_lossy().into_owned();
                sandbox_free_error(errorbuf);
                s
            }
        };
        return Err(format!("sandbox_init_with_parameters failed: {msg}"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(msg) => return fail(msg),
    };

    if !is_valid_account_name(&parsed.account_name) {
        return fail("account name does not match Runbox's managed naming scheme");
    }
    if !is_runbox_managed_account(&parsed.account_name) {
        return fail("account is not registered as Runbox-managed");
    }

    // SAFETY: documented libc entry points. gid must be set before uid,
    // or the process loses the privilege needed to set it.
    unsafe {
        let c_name = CString::new(parsed.account_name.as_str()).expect("no interior NUL");
        let pw = libc::getpwnam(c_name.as_ptr());
        if pw.is_null() {
            return fail("getpwnam failed — account does not exist");
        }
        let uid = (*pw).pw_uid;
        let gid = (*pw).pw_gid;

        // TERM must be captured BEFORE the clearing loop below — it's
        // terminal-emulator capability info (how to move the cursor,
        // clear a line), not sensitive, and safe to carry through
        // unconditionally, unlike arbitrary [env].pass_through entries.
        // Missing this is what caused zsh's line editor to garble every
        // redraw: it had no terminfo data to know how to issue the
        // escape sequences a backspace or history-recall redraw needs.
        // TERM/LANG captured before the clearing loop below — locale and
        // terminal-capability info, not sensitive, safe to carry through
        // unconditionally. Confirmed via shelldoctor: LANG was unset
        // entirely inside the box, same category of gap as TERM.
        let term = env::var("TERM").ok();
        let lang = env::var("LANG").ok();

        for (k, _) in env::vars() {
            env::remove_var(k);
        }
        let home = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        env::set_var("HOME", home);
        env::set_var("USER", &parsed.account_name);
        env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        if let Some(t) = term {
            env::set_var("TERM", t);
        }
        if let Some(l) = lang {
            env::set_var("LANG", l);
        }

        if libc::setgroups(1, &gid) != 0 {
            return fail("setgroups failed");
        }
        if libc::setgid(gid) != 0 {
            return fail("setgid failed");
        }
        if libc::setuid(uid) != 0 {
            return fail("setuid failed");
        }
    }

    // Everything below runs as the unprivileged box account — no elevated
    // capability left to lose.
    if let Some(profile_path) = &parsed.seatbelt_profile {
        let real_tmpdir = match resolve_real_tmpdir() {
            Ok(t) => t,
            Err(e) => return fail(&e),
        };
        env::set_var("TMPDIR", &real_tmpdir);

        let tty_device = resolve_tty_device();
        if let Err(e) = apply_sandbox(profile_path, &real_tmpdir, &tty_device) {
            return fail(&e);
        }
    }

    for (key, value) in &parsed.env_pairs {
        env::set_var(key, value);
    }

    // Additive only — appends to the baseline set above, never replaces
    // it. The one sanctioned way to extend PATH; --env rejects PATH
    // outright (see parse_args).
    if !parsed.path_extra.is_empty() {
        let current = env::var("PATH").unwrap_or_default();
        let extended = format!("{current}:{}", parsed.path_extra.join(":"));
        env::set_var("PATH", extended);
    }

    let c_binary = CString::new(parsed.binary_path.as_str()).expect("no interior NUL");
    let c_args: Vec<CString> = parsed
        .binary_args
        .iter()
        .map(|a| CString::new(a.as_str()).expect("no interior NUL"))
        .collect();
    let mut c_argv: Vec<*const c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    c_argv.push(std::ptr::null());

    unsafe {
        libc::execv(c_binary.as_ptr(), c_argv.as_ptr());
    }

    fail("execv failed")
}
