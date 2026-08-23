//! Runbox's own configuration — `~/.config/runbox/config.toml`. Distinct
//! from `box.toml`, which is a per-project box spec. This is Runbox
//! itself: personal defaults applied to every box, and tool behavior
//! (doctor scheduling) that has no place in a per-project file.
//!
//! `defaults.setup` is applied at account provisioning, before a
//! project's own `[setup]` runs. It is NOT part of box.lock — personal
//! shell/editor preferences aren't project requirements, and hashing them
//! into reproduction fingerprints would make every box "drift" the moment
//! this file changes, for reasons that have nothing to do with the
//! project.

use crate::config::{HooksSection, SetupSection, CURRENT_BOX_SPEC_VERSION};
use serde::Deserialize;
use std::path::PathBuf;

/// Tracks config::CURRENT_BOX_SPEC_VERSION for now — global config and
/// box.toml happen to share a schema generation, but this is tracked
/// separately since there's no structural reason they must stay in sync
/// going forward.
pub const CURRENT_CONFIG_SCHEMA_VERSION: u32 = CURRENT_BOX_SPEC_VERSION;

#[derive(Debug, Default, Deserialize)]
pub struct RunboxConfig {
    /// Required only when the file exists at all — see `load`. No file
    /// means defaults apply and this is never checked.
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub defaults: DefaultsSection,
    #[serde(default)]
    pub doctor: DoctorSection,
    /// Applied to every box by default. Ordering with a project's own
    /// [hooks]: on_enter runs global-then-box (outer wraps inner);
    /// on_exit runs box-then-global (unwinds in reverse) — same
    /// convention as middleware/setup-teardown ordering generally.
    #[serde(default)]
    pub hooks: HooksSection,
}

#[derive(Debug, Default, Deserialize)]
pub struct DefaultsSection {
    pub setup: Option<SetupSection>,
}

#[derive(Debug, Deserialize)]
pub struct DoctorSection {
    /// Cheap, cheap enough to be on by default: check for orphans right
    /// after every `runbox destroy`.
    #[serde(default = "default_true")]
    pub after_destroy: bool,

    /// A scheduled sweep. Off by default — implemented as a launchd
    /// StartInterval invocation of `runbox doctor`, not a persistent
    /// daemon; consistent with there being no runboxd.
    #[serde(default)]
    pub scheduled: bool,

    #[serde(default = "default_interval")]
    pub interval: String,
}

impl Default for DoctorSection {
    fn default() -> Self {
        Self {
            after_destroy: true,
            scheduled: false,
            interval: default_interval(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_interval() -> String {
    "24h".to_string()
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map_err(|_| anyhow::anyhow!("neither XDG_CONFIG_HOME nor HOME is set"))?;
    Ok(base.join("runbox").join("config.toml"))
}

/// Missing file is not an error — Runbox works with no global config,
/// falling back to every field's default.
pub fn load() -> anyhow::Result<RunboxConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(RunboxConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let parsed: RunboxConfig =
        toml::from_str(&raw).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    if parsed.schema_version != CURRENT_CONFIG_SCHEMA_VERSION {
        anyhow::bail!(
            "{} schema_version {} is not supported — this Runbox expects {}",
            path.display(),
            parsed.schema_version,
            CURRENT_CONFIG_SCHEMA_VERSION
        );
    }
    Ok(parsed)
}
