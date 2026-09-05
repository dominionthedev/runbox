use clap::{Parser, Subcommand};
use runbox_core::config::BoxToml;
use runbox_core::seatbelt::ProfileInputs;
use std::env;
use std::os::unix::process::CommandExt;

/// Runbox — macOS-only dev-box isolation.
#[derive(Parser)]
#[command(name = "runbox", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an initial box.toml in the current directory.
    Init {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        headless: bool,
        /// Required with --headless — [run].cmd, shell-form (one string).
        #[arg(long)]
        run_cmd: Option<String>,
    },
    /// View or edit the current project's box.toml.
    Spec {
        #[command(subcommand)]
        action: SpecAction,
    },
    /// View or edit Runbox's own config (~/.config/runbox/config.toml).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
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
    /// Internal — invoked by the launchd plist, not meant to be run
    /// directly. Runs [run].cmd with no foreground/interactive semantics.
    /// Distinct from Exec, which is deliberately blocked on headless
    /// boxes: this is launchd starting the box's own declared service,
    /// not a human attaching to one.
    #[command(hide = true)]
    RunHeadless,
    /// Archive setup-produced state.
    Snapshot,
    /// Restore from a .box archive and verify against box.lock.
    Restore,
    /// List processes running under this box's account.
    Ps,
    /// Check whether box.lock still matches the current box.toml and
    /// .runbox/setup/ contents — drift detection, not enforcement.
    Verify,
    /// Clean up orphaned box accounts from interrupted builds.
    Doctor,
}

#[derive(Subcommand)]
enum SpecAction {
    /// Print the raw box.toml content.
    Show,
    /// Open box.toml in $EDITOR.
    Edit,
    /// Print the path to box.toml.
    Path,
    /// Parse and validate box.toml without provisioning anything.
    Validate,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the raw config content, or note that none exists (defaults apply).
    Show,
    /// Open the config in $EDITOR — creates an empty file first if missing.
    Edit,
    /// Print the path to the config file.
    Path,
}

fn load_config() -> anyhow::Result<BoxToml> {
    let cwd = env::current_dir()?;
    let config = runbox_core::config::load(&cwd)?;
    for warning in config.env.warnings() {
        eprintln!("warning: {warning}");
    }
    Ok(config)
}

fn open_in_editor(path: &std::path::Path) -> anyhow::Result<()> {
    let editor = env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor).arg(path).status()?;
    if !status.success() {
        anyhow::bail!("{editor} exited with a non-zero status");
    }
    Ok(())
}

fn require_built(
    box_name: &str,
    account_name: &str,
    project_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if !runbox_core::identity::account_exists(account_name)? {
        anyhow::bail!("box {box_name} is not built — run `runbox build` first");
    }
    // box.lock's own security-relevant checks (drift verification via
    // `runbox verify`) aren't real yet — that's blocked on lock content
    // canonicalization being settled. This is presence-only: the account
    // existing isn't enough, the lock generated alongside it must exist
    // too, since exec/shell are meant to depend on the box actually
    // having completed a real `build`, not just having an account.
    if runbox_core::lock::BoxLock::load(project_dir)?.is_none() {
        anyhow::bail!("box.lock missing for {box_name} — run `runbox build` first");
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
    // SHELL reflects [box].shell — what the box declares as its shell,
    // not whatever the host happens to use. Confirmed missing entirely
    // via shelldoctor. Set here (not inside runbox-helper like TERM/LANG)
    // because box.toml's parsed config is only available on the CLI
    // side; SHELL is treated as a protected key, same as HOME/USER/PATH
    // — [env].set cannot override it, see config::PROTECTED_KEYS.
    cmd.arg("--env").arg(format!("SHELL={}", config.box_.shell));
    cmd.arg("--");
    cmd.args(command);

    // The child ONLY sets its own new process group here — it must NOT
    // call tcsetpgrp itself. Doing so was the bug in the previous fix:
    // once the child leaves the foreground group via setpgid, it is by
    // definition a background process relative to the terminal, and
    // tcsetpgrp() from a background process sends SIGTTOU to the CALLER
    // — default action STOP. The child would freeze silently before ever
    // reaching exec, which is exactly the observed hang (no output, no
    // error, just Ctrl-C required). The terminal handoff has to be done
    // by the PARENT (below), which — at the moment it calls tcsetpgrp —
    // is still the actual foreground group and so isn't stopped by it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        anyhow::anyhow!(
            "failed to invoke {}: {e} — is runbox-helper installed? (make install-helper)",
            runbox_core::identity::HELPER_INSTALL_PATH
        )
    })?;
    let child_pid = child.id() as libc::pid_t;
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };

    if is_tty {
        unsafe {
            // Ignore SIGTTOU on this (parent) process for the rest of its
            // lifetime — runbox exits right after this call regardless,
            // so there's nothing to restore. Without this, the reclaim
            // tcsetpgrp call below (after the child group may no longer
            // be the actual foreground group) could stop US instead of
            // just succeeding, which is not what a non-interactive
            // wrapper process wants.
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            // Redundant with the child's own pre_exec setpgid — closes
            // the fork/exec race. Whichever runs first wins; the other
            // is a harmless no-op (or a benign EPERM if the child has
            // already exec'd by the time this runs).
            libc::setpgid(child_pid, child_pid);
            // We are still the terminal's foreground group at this exact
            // point — nothing has changed it yet — so this succeeds and
            // hands control to the child's new group without SIGTTOU.
            libc::tcsetpgrp(libc::STDIN_FILENO, child_pid);
        }
    }

    let status = child
        .wait()
        .map_err(|e| anyhow::anyhow!("waiting on runbox-helper: {e}"))?;

    if is_tty {
        // Reclaim foreground control before exiting, so the shell that
        // launched `runbox` gets clean control back rather than being
        // left pointed at a now-exited process group.
        unsafe {
            libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp());
        }
    }

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
        Commands::Init {
            name,
            headless,
            run_cmd,
        } => {
            let cwd = env::current_dir()?;
            let toml_path = cwd.join("box.toml");
            if toml_path.exists() {
                anyhow::bail!(
                    "box.toml already exists at {} — not overwriting",
                    toml_path.display()
                );
            }
            if headless && run_cmd.is_none() {
                anyhow::bail!("--headless requires --run-cmd — a headless box needs [run].cmd or it can't be started");
            }

            let box_name = name.unwrap_or_else(|| {
                cwd.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "box".to_string())
            });

            let mut content = format!(
                "schema_version = {}\n\n[box]\nname = \"{box_name}\"\nlifecycle = \"persistent\"\ninteractive = {}\nshell = \"/bin/zsh\"\n\n[network]\nmode = \"deny\"\nallowlist = []\n",
                runbox_core::config::CURRENT_BOX_SPEC_VERSION,
                !headless
            );
            if let Some(cmd) = run_cmd {
                content.push_str(&format!("\n[run]\ncmd = \"{cmd}\"\n"));
            }

            std::fs::write(&toml_path, content)?;
            println!("wrote {}", toml_path.display());
            Ok(())
        }

        Commands::Spec { action } => {
            let cwd = env::current_dir()?;
            let toml_path = cwd.join("box.toml");
            match action {
                SpecAction::Show => {
                    let content = std::fs::read_to_string(&toml_path)
                        .map_err(|e| anyhow::anyhow!("reading {}: {e}", toml_path.display()))?;
                    print!("{content}");
                    Ok(())
                }
                SpecAction::Edit => {
                    if !toml_path.exists() {
                        anyhow::bail!("no box.toml here — run `runbox init` first");
                    }
                    open_in_editor(&toml_path)
                }
                SpecAction::Path => {
                    println!("{}", toml_path.display());
                    Ok(())
                }
                SpecAction::Validate => match load_config() {
                    Ok(config) => {
                        println!(
                            "OK — {} ({})",
                            config.box_.name,
                            if config.box_.interactive {
                                "interactive"
                            } else {
                                "headless"
                            }
                        );
                        Ok(())
                    }
                    Err(e) => {
                        println!("INVALID: {e}");
                        std::process::exit(1);
                    }
                },
            }
        }

        Commands::Config { action } => {
            let path = runbox_core::global_config::config_path()?;
            match action {
                ConfigAction::Show => {
                    if path.exists() {
                        print!("{}", std::fs::read_to_string(&path)?);
                    } else {
                        println!("no config file at {} — using defaults", path.display());
                    }
                    Ok(())
                }
                ConfigAction::Edit => {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    if !path.exists() {
                        std::fs::write(&path, "")?;
                    }
                    open_in_editor(&path)
                }
                ConfigAction::Path => {
                    println!("{}", path.display());
                    Ok(())
                }
            }
        }

        Commands::Build => {
            let config = load_config()?;
            let box_name = &config.box_.name;

            let account = runbox_core::identity::provision(box_name, &config.box_.shell)?;
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
                home_dir: account
                    .home
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 home path"))?,
                extra_read: &config.permissions.read,
                extra_write: &config.permissions.write,
                network_allowed: config.network.mode == "allow"
                    || !config.network.allowlist.is_empty(),
                mode: runbox_core::seatbelt::ExecutionMode::parse(&config.execution.mode)
                    .map_err(|e| anyhow::anyhow!(e))?,
            };
            let profile_path = runbox_core::seatbelt::write_profile(box_name, &inputs)?;
            println!(
                "compiled seatbelt profile ({}): {}",
                config.execution.mode,
                profile_path.display()
            );

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

            let lock = runbox_core::lock::generate(&config, &account.account_name, &project_dir)?;
            let lock_path = lock.write(&project_dir)?;
            println!("wrote {}", lock_path.display());

            if !config.box_.interactive {
                println!("headless box built — use `runbox start` to run it as a service");
            }
            println!("build complete for {box_name}");
            Ok(())
        }

        Commands::Exec { command } => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            if !config.box_.interactive {
                anyhow::bail!(
                    "{box_name} is headless — no foreground interaction. Use `runbox start`/`stop`/`status`/`logs`."
                );
            }
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name, &env::current_dir()?)?;

            let final_command = resolve_final_command(&command, &config.run, &config.box_.shell)?;
            let dir = config.run.as_ref().and_then(|r| r.dir.as_deref());
            run_with_hooks(&config, &account_name, &final_command, dir)
        }

        Commands::Shell => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            if !config.box_.interactive {
                anyhow::bail!(
                    "{box_name} is headless — no foreground interaction. Use `runbox start`/`stop`/`status`/`logs`."
                );
            }
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name, &env::current_dir()?)?;

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

            runbox_core::seatbelt::remove_profile(box_name)?;
            println!("removed seatbelt profile");

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
            require_built(box_name, &account_name, &env::current_dir()?)?;

            let runbox_binary = env::current_exe()?;
            let project_dir = env::current_dir()?;
            let log_dir = project_dir.join(".runbox").join("logs");

            // WorkingDirectory must stay at project_dir, not [run].dir —
            // this is the cwd of the `runbox exec` process launchd spawns,
            // and config::load only looks for box.toml in its own cwd, no
            // parent search. [run].dir is applied one layer down, by
            // run_in_box's current_dir() on the runbox-helper invocation
            // that `runbox exec` makes after loading config correctly.
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

        Commands::RunHeadless => {
            let config = load_config()?;
            let box_name = &config.box_.name;
            let account_name = runbox_core::identity::account_name_for_box(box_name);
            require_built(box_name, &account_name, &env::current_dir()?)?;

            let Some(run) = &config.run else {
                anyhow::bail!(
                    "{box_name}: no [run].cmd — should have been caught at config parse time"
                );
            };
            let command = run.cmd.resolve(&config.box_.shell);
            let dir = run.dir.as_deref();
            run_with_hooks(&config, &account_name, &command, dir)
        }

        Commands::Snapshot => todo!("runbox_core::archive::snapshot"),
        Commands::Restore => todo!("runbox_core::archive::restore + lock::verify_against"),
        Commands::Ps => todo!("uid-scoped proc_listpids"),

        Commands::Verify => todo!(
            "compare box.lock's config_hash/setup_assets_hash against a freshly computed hash of \
             the current box.toml/.runbox/setup — blocked on lock::generate, which needs Serialize \
             on the config structs and a canonicalization strategy decided first"
        ),

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
