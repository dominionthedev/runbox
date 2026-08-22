use clap::{Parser, Subcommand};
use runbox_core::config::BoxToml;
use runbox_core::seatbelt::ProfileInputs;
use std::env;

/// Runbox — macOS-only dev-box isolation.
#[derive(Parser)]
#[command(name = "runbox", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Provision the box account, compile the Seatbelt profile, load the PF anchor.
    Build,
    /// Run a command in the box. No args falls back to [run].cmd. A single
    /// quoted argument is shell-form (runs via $SHELL -c inside the box);
    /// multiple arguments are exec-form (no shell). See config::resolve_argv.
    Exec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Enter an interactive shell in the box.
    Shell,
    /// Run [setup] against the box account.
    Setup,
    /// Revoke ACL, delete the box account, unload the PF anchor.
    Destroy,
    /// Start a headless box as a launchd-supervised background service.
    Start,
    /// Stop a running headless box.
    Stop,
    /// Show whether a headless box's service is currently running.
    Status,
    /// Show a headless box's stdout log.
    Logs {
        #[arg(long, default_value_t = 50)]
        lines: usize,
        #[arg(long)]
        follow: bool,
    },
    /// Archive setup-produced state.
    Snapshot,
    /// Restore from a .box archive and verify against box.lock.
    Restore,
    /// List processes running under this box's account.
    Ps,
    /// Clean up orphaned box accounts from interrupted builds.
    Doctor,
}

fn load_config() -> anyhow::Result<BoxToml> {
    let cwd = env::current_dir()?;
    runbox_core::config::load(&cwd)
}

fn require_built(box_name: &str, account_name: &str) -> anyhow::Result<()> {
    if !runbox_core::identity::account_exists(account_name)? {
        anyhow::bail!("box {box_name} is not built — run `runbox build` first");
    }
    Ok(())
}

/// Resolves the CLI's own trailing args or falls back to [run].cmd,
/// applying the same shell-form/exec-form convention either way — see
/// config::resolve_argv and config::CommandSpec.
fn resolve_final_command(
    explicit: &[String],
    run: &Option<runbox_core::config::RunSection>,
    shell: &str,
) -> anyhow::Result<Vec<String>> {
    if !explicit.is_empty() {
        return Ok(runbox_core::config::resolve_argv(explicit, shell));
    }
    match run {
        Some(r) => Ok(r.cmd.resolve(shell)),
        None => anyhow::bail!("no command given and no [run].cmd configured in box.toml"),
    }
}

/// Invokes runbox-helper directly — no `sudo` prefix. The setuid bit on
/// the installed binary is what grants elevated privilege for the
/// duration of the call. Requires `make install-helper` to have actually
/// installed it with that bit set — see identity::HELPER_INSTALL_PATH.
///
/// stdio is inherited (`Command::status`, not `.output()`), not piped —
/// required for readline, job control, and interactive shell behavior.
fn run_in_box(
    config: &BoxToml,
    account_name: &str,
    command: &[String],
    dir: Option<&str>,
) -> anyhow::Result<()> {
    let profile_path = runbox_core::seatbelt::profile_path_for(&config.box_.name);
    let profile_path_str = profile_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 profile path"))?;

    let env_args = runbox_core::env::build_helper_args(&config.env)?;

    let mut cmd = std::process::Command::new(runbox_core::identity::HELPER_INSTALL_PATH);
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    cmd.arg(account_name);
    cmd.arg("--seatbelt-profile").arg(profile_path_str);
    cmd.args(&env_args);
    cmd.arg("--");
    cmd.args(command);

    let status = cmd.status().map_err(|e| {
        anyhow::anyhow!(
            "failed to invoke {}: {e} — is runbox-helper installed? (make install-helper)",
            runbox_core::identity::HELPER_INSTALL_PATH
        )
    })?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Wraps the main command with on_enter/on_exit hooks — global config's
/// hooks first (outer), then the box's own (inner) on entry; reversed on
/// exit. Each hook is a separate runbox-helper invocation, not sourced
/// into the same shell session — see config::HooksSection docs. on_exit
/// hooks run best-effort even if the main command failed; their own
/// failure never masks the main command's result.
fn run_with_hooks(
    config: &BoxToml,
    account_name: &str,
    command: &[String],
    dir: Option<&str>,
) -> anyhow::Result<()> {
    let global = runbox_core::global_config::load().unwrap_or_default();

    if let Some(hook) = &global.hooks.on_enter {
        run_in_box(config, account_name, std::slice::from_ref(hook), dir)?;
    }

    if let Some(hook) = &config.hooks.on_enter {
        run_in_box(config, account_name, std::slice::from_ref(hook), dir)?;
    }

    let result = run_in_box(config, account_name, command, dir);

    if let Some(hook) = &config.hooks.on_exit {
        let _ = run_in_box(config, account_name, std::slice::from_ref(hook), dir);
    }

    if let Some(hook) = &global.hooks.on_exit {
        let _ = run_in_box(config, account_name, std::slice::from_ref(hook), dir);
    }

    result
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build => {
            let config = load_config()?;
            let box_name = &config.box_.name;

            let account = runbox_core::identity::provision(box_name)?;
            println!(
                "provisioned {} (uid {}, gid {}, home {})",
                account.account_name,
                account.uid,
                account.gid,
                account.home.display()
            );

            let project_dir = env::current_dir()?;
            let inputs = ProfileInputs {
                project_dir: project_dir
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 project path"))?,
                extra_read: &config.permissions.read,
                extra_write: &config.permissions.write,
                network_allowed: config.network.mode == "allow"
                    || !config.network.allowlist.is_empty(),
            };
            let profile_path = runbox_core::seatbelt::write_profile(box_name, &inputs)?;
            println!("compiled seatbelt profile: {}", profile_path.display());

            runbox_core::pf::load_anchor(box_name, &account.account_name, &config.network)?;
            println!("loaded pf anchor: runbox/{box_name}");

            runbox_core::acl::grant(
                &project_dir,
                &account.account_name,
                runbox_core::acl::GrantMode::ReadWrite,
            )?;
            println!(
                "granted acl: {} -> {}",
                project_dir.display(),
                account.account_name
            );

            for path in &config.permissions.read {
                runbox_core::acl::grant(
                    std::path::Path::new(path),
                    &account.account_name,
                    runbox_core::acl::GrantMode::ReadOnly,
                )?;
                println!(
                    "granted acl (read-only): {path} -> {}",
                    account.account_name
                );
            }
            for path in &config.permissions.write {
                runbox_core::acl::grant(
                    std::path::Path::new(path),
                    &account.account_name,
                    runbox_core::acl::GrantMode::ReadWrite,
                )?;
                println!(
                    "granted acl (read-write): {path} -> {}",
                    account.account_name
                );
            }

            if !config.box_.interactive {
                println!("headless box built — use `runbox start` to run it as a service");
            }
            println!("build complete for {box_name}");
            Ok(())
        }

        Commands::Exec { command } => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name)?;

            let final_command = resolve_final_command(&command, &config.run, &config.box_.shell)?;
            let dir = config.run.as_ref().and_then(|r| r.dir.as_deref());
            run_with_hooks(&config, &account_name, &final_command, dir)
        }

        Commands::Shell => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name)?;

            let shell = config.box_.shell.clone();
            let dir = config.run.as_ref().and_then(|r| r.dir.as_deref());
            run_with_hooks(&config, &account_name, &[shell], dir)
        }

        Commands::Setup => {
            let config = load_config()?;
            let Some(setup) = &config.setup else {
                println!("no [setup] section in box.toml");
                return Ok(());
            };
            let account_name = runbox_core::identity::account_name_for_box(&config.box_.name);
            let box_home =
                std::path::PathBuf::from(runbox_core::identity::HOMES_ROOT).join(&account_name);
            let setup_dir = env::current_dir()?.join(".runbox").join("setup");

            runbox_core::setup::run(setup, &setup_dir, &box_home, &account_name)?;
            println!("setup complete for {account_name}");
            Ok(())
        }

        Commands::Destroy => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            let project_dir = env::current_dir()?;

            if !config.box_.interactive {
                let _ = runbox_core::launchd::bootout(box_name);
                let plist = runbox_core::launchd::plist_path(box_name)?;
                if plist.exists() {
                    std::fs::remove_file(&plist)?;
                }
                println!("stopped and removed launchd service");
            }

            // ACL revoke must happen before deprovisioning the account —
            // chmod -a matches an ACE by resolving the account name, and
            // that resolution can fail once the account no longer exists.
            runbox_core::acl::revoke(
                &project_dir,
                &account_name,
                runbox_core::acl::GrantMode::ReadWrite,
            )?;
            for path in &config.permissions.read {
                runbox_core::acl::revoke(
                    std::path::Path::new(path),
                    &account_name,
                    runbox_core::acl::GrantMode::ReadOnly,
                )?;
            }
            for path in &config.permissions.write {
                runbox_core::acl::revoke(
                    std::path::Path::new(path),
                    &account_name,
                    runbox_core::acl::GrantMode::ReadWrite,
                )?;
            }
            println!("revoked acl grants");

            runbox_core::pf::unload_anchor(box_name)?;
            println!("unloaded pf anchor: runbox/{box_name}");

            runbox_core::identity::deprovision(&account_name)?;
            println!("deprovisioned {account_name}");

            Ok(())
        }

        Commands::Start => {
            let config = load_config()?;
            if config.box_.interactive {
                anyhow::bail!(
                    "`runbox start` is for headless boxes only ([box] interactive = false)"
                );
            }
            let box_name = &config.box_.name;
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name)?;

            let runbox_binary = env::current_exe()?;
            let project_dir = env::current_dir()?;
            let log_dir = project_dir.join(".runbox").join("logs");

            let plist = runbox_core::launchd::write_plist(
                box_name,
                runbox_binary
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 runbox path"))?,
                project_dir
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 project path"))?,
                &log_dir,
            )?;
            println!("wrote {}", plist.display());

            runbox_core::launchd::bootstrap(box_name)?;
            println!(
                "started {box_name} (label {})",
                runbox_core::launchd::label_for(box_name)
            );
            Ok(())
        }

        Commands::Stop => {
            let config = load_config()?;
            runbox_core::launchd::bootout(&config.box_.name)?;
            println!("stopped {}", config.box_.name);
            Ok(())
        }

        Commands::Status => {
            let config = load_config()?;
            let running = runbox_core::launchd::is_running(&config.box_.name)?;
            println!(
                "{}: {}",
                config.box_.name,
                if running { "running" } else { "not running" }
            );
            Ok(())
        }

        Commands::Logs { lines, follow } => {
            let config = load_config()?;
            let log_path = env::current_dir()?
                .join(".runbox")
                .join("logs")
                .join(format!("{}.stdout.log", config.box_.name));

            let mut cmd = std::process::Command::new("tail");
            if follow {
                cmd.arg("-f");
            } else {
                cmd.arg("-n").arg(lines.to_string());
            }
            cmd.arg(&log_path);
            cmd.status()?;
            Ok(())
        }

        Commands::Snapshot => todo!("runbox_core::archive::snapshot"),
        Commands::Restore => todo!("runbox_core::archive::restore + lock::verify_against"),
        Commands::Ps => todo!("uid-scoped proc_listpids"),

        Commands::Doctor => {
            let orphans = runbox_core::identity::find_orphans()?;
            if orphans.is_empty() {
                println!("no orphaned accounts found");
            } else {
                println!("orphaned accounts:");
                for name in orphans {
                    println!("  {name}");
                }
            }
            Ok(())
        }
    }
}
