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
    /// Run a single command in the box.
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

            todo!("acl::grant for project_dir and config.permissions read/write paths")
        }

        Commands::Exec { command } => {
            let _ = command;
            todo!("fork, apply seatbelt (bind TMPDIR param via confstr(_CS_DARWIN_USER_TEMP_DIR)), build --env args via runbox_core::env::build_helper_args, invoke runbox-helper, exec")
        }

        Commands::Shell => todo!("same path as Exec with an interactive shell as target"),

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

            runbox_core::pf::unload_anchor(box_name)?;
            println!("unloaded pf anchor: runbox/{box_name}");

            runbox_core::identity::deprovision(&account_name)?;
            println!("deprovisioned {account_name}");

            todo!("acl::revoke")
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
