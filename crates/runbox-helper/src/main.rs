// runbox-helper — the only privileged component in Runbox.
//
// Usage: runbox-helper <box-account-name> [--env KEY=VALUE ...] -- <binary-path> [args...]
//
// Installed setuid-root. Validates the target account against Runbox's
// naming scheme and managed-account registry, drops privilege
// irreversibly, execs. Does not decide what runs — only who it can
// become. If the calling process is compromised upstream, the blast
// radius stays "arbitrary code as the box account," never root or any
// other account.
//
// --env pairs are set on the process AFTER privilege is dropped — this
// is the box's own unprivileged account configuring its own exec, not a
// privilege-relevant operation. No shell. No config parsing beyond the
// registry lookup below. No third-party crates beyond libc.

use std::env;
use std::ffi::CString;
use std::process::ExitCode;

/// Must match runbox_core::identity::REGISTRY_PATH exactly. Duplicated as
/// a literal rather than pulling in runbox-core, to keep this crate's
/// dependency tree at libc only.
const REGISTRY_PATH: &str = "/private/var/db/runbox/managed_accounts";

fn is_valid_account_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("_runbox_") else {
        return false;
    };
    suffix.len() == 8
        && suffix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Exact line match against the registry file. Fails closed on any I/O
/// error or missing file.
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
    env_pairs: Vec<(String, String)>,
    binary_path: String,
    binary_args: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, &'static str> {
    if args.len() < 2 {
        return Err("usage: runbox-helper <box-account-name> [--env KEY=VALUE ...] -- <binary-path> [args...]");
    }

    let account_name = args[1].clone();
    let mut i = 2;
    let mut env_pairs = Vec::new();

    while i < args.len() {
        match args[i].as_str() {
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
                env_pairs.push((key.to_string(), value.to_string()));
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            _ => return Err("expected --env or -- before the target binary"),
        }
    }

    let binary_path = args.get(i).ok_or("missing target binary path")?.clone();
    let binary_args = args[i..].to_vec();

    Ok(ParsedArgs {
        account_name,
        env_pairs,
        binary_path,
        binary_args,
    })
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

        for (k, _) in env::vars() {
            env::remove_var(k);
        }
        let home = std::ffi::CStr::from_ptr((*pw).pw_dir)
            .to_string_lossy()
            .into_owned();
        env::set_var("HOME", home);
        env::set_var("USER", &parsed.account_name);
        env::set_var("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

        if libc::setgroups(1, &gid) != 0 {
            return fail("setgroups failed");
        }
        if libc::setgid(gid) != 0 {
            return fail("setgid failed");
        }
        if libc::setuid(uid) != 0 {
            return fail("setuid failed");
        }

        // Applied after the privilege drop above — see module docs.
        for (key, value) in &parsed.env_pairs {
            env::set_var(key, value);
        }

        let c_binary = CString::new(parsed.binary_path.as_str()).expect("no interior NUL");
        let c_args: Vec<CString> = parsed
            .binary_args
            .iter()
            .map(|a| CString::new(a.as_str()).expect("no interior NUL"))
            .collect();
        let mut c_argv: Vec<*const libc::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
        c_argv.push(std::ptr::null());

        libc::execv(c_binary.as_ptr(), c_argv.as_ptr());
    }

    fail("execv failed")
}
