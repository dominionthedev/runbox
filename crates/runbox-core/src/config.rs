//! box.toml schema.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct BoxToml {
    #[serde(rename = "box")]
    pub box_: BoxSection,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub env: EnvSection,
    #[serde(default)]
    pub setup: Option<SetupSection>,
    #[serde(default)]
    pub audit: AuditSection,
}

#[derive(Debug, Deserialize)]
pub struct BoxSection {
    pub name: String,
    #[serde(default)]
    pub lifecycle: Lifecycle,
    #[serde(default = "default_true")]
    pub interactive: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    #[default]
    Persistent,
    Stateless,
    Ephemeral,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionSection {
    #[serde(default = "default_execution_mode")]
    pub mode: String,
    #[serde(default = "default_deny")]
    pub default: String,
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            mode: default_execution_mode(),
            default: default_deny(),
        }
    }
}

fn default_execution_mode() -> String {
    "enforce".to_string()
}
fn default_deny() -> String {
    "deny".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct NetworkSection {
    #[serde(default = "default_deny")]
    pub mode: String,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub denylist: Vec<String>,
    #[serde(default = "default_dns")]
    pub dns: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            mode: default_deny(),
            allowlist: Vec::new(),
            denylist: Vec::new(),
            dns: default_dns(),
            timeout: default_timeout(),
        }
    }
}

fn default_dns() -> String {
    "localhost-only".to_string()
}
fn default_timeout() -> String {
    "30s".to_string()
}

impl NetworkSection {
    /// mode=deny+denylist and mode=allow+allowlist are both rejected —
    /// each mode only accepts the list that has an effect.
    pub fn validate(&self) -> Result<(), String> {
        match self.mode.as_str() {
            "deny" if !self.denylist.is_empty() => {
                Err("`denylist` is only valid when network mode = \"allow\"".into())
            }
            "allow" if !self.allowlist.is_empty() => {
                Err("`allowlist` is only valid when network mode = \"deny\"".into())
            }
            "deny" | "allow" => Ok(()),
            other => Err(format!(
                "network mode must be \"deny\" or \"allow\", got {other:?}"
            )),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct EnvSection {
    #[serde(default)]
    pub set: HashMap<String, String>,
    #[serde(default)]
    pub pass_through: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetupSection {
    #[serde(default)]
    pub provision: Vec<ProvisionEntry>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub script: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionEntry {
    pub src: PathBuf,
    pub dest: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct AuditSection {
    #[serde(default = "default_true")]
    pub record: bool,
    #[serde(default = "default_retention")]
    pub retention: String,
}

impl Default for AuditSection {
    fn default() -> Self {
        Self {
            record: true,
            retention: default_retention(),
        }
    }
}
fn default_retention() -> String {
    "30d".to_string()
}

pub fn parse(raw: &str) -> anyhow::Result<BoxToml> {
    let parsed: BoxToml = toml::from_str(raw)?;
    parsed
        .network
        .validate()
        .map_err(|e| anyhow::anyhow!("box.toml [network]: {e}"))?;
    if let Some(setup) = &parsed.setup {
        if !setup.commands.is_empty() && setup.script.is_some() {
            anyhow::bail!("box.toml [setup]: `commands` and `script` are mutually exclusive");
        }
    }
    Ok(parsed)
}

/// Looks for box.toml in `dir` only — no parent-directory search.
pub fn load(dir: &std::path::Path) -> anyhow::Result<BoxToml> {
    let path = dir.join("box.toml");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    parse(&raw)
}

pub type ExecutionRules = HashMap<String, String>;
