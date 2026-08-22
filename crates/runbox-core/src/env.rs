//! [env] resolution. Nothing crosses from host to box by default — `set`
//! is literal, `pass_through` reads named vars from the invoking (host)
//! process's own environment. `pass_through` is a real hole by design: it
//! moves whatever's named straight past the DAC boundary. No masking, no
//! silent filtering — if a secret is named, it crosses.
//!
//! Output is `--env KEY=VALUE` argv pairs for runbox-helper, not
//! inherited process env — the helper clears its environment
//! unconditionally before dropping privilege, so vars must be passed
//! explicitly as arguments to survive that.

use crate::config::EnvSection;

pub fn build_helper_args(env: &EnvSection) -> anyhow::Result<Vec<String>> {
    let mut args = Vec::new();

    for (key, value) in &env.set {
        validate_key(key)?;
        args.push("--env".to_string());
        args.push(format!("{key}={value}"));
    }

    for name in &env.pass_through {
        validate_key(name)?;
        match std::env::var(name) {
            Ok(value) => {
                args.push("--env".to_string());
                args.push(format!("{name}={value}"));
            }
            Err(_) => {
                // Not set on host — skipped, not an error. A declared
                // pass_through name that happens to be absent shouldn't
                // block a build.
            }
        }
    }

    Ok(args)
}

fn validate_key(key: &str) -> anyhow::Result<()> {
    if key.is_empty() {
        anyhow::bail!("[env] key cannot be empty");
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        anyhow::bail!("[env] key {key:?} must start with a letter or underscore");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("[env] key {key:?} must be alphanumeric/underscore only");
    }
    Ok(())
}
