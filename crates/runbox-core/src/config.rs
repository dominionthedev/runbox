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
    pub permissions: PermissionsSection,
    #[serde(default)]
    pub run: Option<RunSection>,
    #[serde(default)]
    pub hooks: HooksSection,
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
    /// The account's own UserShell is deliberately /usr/bin/false — never
    /// consulted for interactivity, on purpose. `runbox shell` execs this
    /// path directly instead.
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_shell() -> String {
    "/bin/zsh".to_string()
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

/// Extra host paths beyond the project directory. Each entry needs both a
/// Seatbelt allow (this section) and an ACL grant (acl::grant, same as the
/// project directory) — Seatbelt allowing a path doesn't override DAC; the
/// box account still needs real OS permission to open something it
/// doesn't own. The ACL side isn't wired yet — see acl.rs.
#[derive(Debug, Default, Deserialize)]
pub struct PermissionsSection {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

impl PermissionsSection {
    pub fn validate(&self) -> Result<(), String> {
        for path in self.read.iter().chain(self.write.iter()) {
            if !path.starts_with('/') {
                return Err(format!(
                    "[permissions] path {path:?} must be absolute — relative paths are ambiguous against a Seatbelt subpath rule"
                ));
            }
        }
        Ok(())
    }
}

/// A command declared either as a single shell-form string (interpreted
/// via the box's own $SHELL -c — env expansion, pipes, && all happen
/// INSIDE the box) or an explicit argv list (exec form — no shell
/// involved, run directly). Same convention `runbox exec`'s own trailing
/// arguments follow — see `resolve_argv`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CommandSpec {
    Shell(String),
    Exec(Vec<String>),
}

impl CommandSpec {
    pub fn resolve(&self, shell: &str) -> Vec<String> {
        match self {
            CommandSpec::Shell(s) => vec![shell.to_string(), "-c".to_string(), s.clone()],
            CommandSpec::Exec(argv) => argv.clone(),
        }
    }
}

/// Same shell-form/exec-form convention as CommandSpec, applied to
/// already-tokenized CLI arguments: a single token is treated as a shell
/// command line (wrapped in `$SHELL -c`), more than one token is treated
/// as a literal argv with no shell involved.
///
/// This is why quoting matters on the command line: `runbox exec 'echo
/// $HOME'` (single-quoted) is ONE token — the host shell never expands
/// `$HOME`, so it resolves as shell-form and `$HOME` expands inside the
/// box. `runbox exec "echo $HOME"` (double-quoted) is expanded by the
/// HOST shell before runbox ever sees it — the box receives an
/// already-resolved host path baked into a literal string, which usually
/// isn't what's intended. `runbox exec npm install` (unquoted, two
/// tokens) is exec-form — no shell, no expansion concern either way.
pub fn resolve_argv(tokens: &[String], shell: &str) -> Vec<String> {
    if tokens.len() == 1 {
        vec![shell.to_string(), "-c".to_string(), tokens[0].clone()]
    } else {
        tokens.to_vec()
    }
}

#[derive(Debug, Deserialize)]
pub struct RunSection {
    pub cmd: CommandSpec,
    /// cwd for `runbox exec` (no args) and `runbox shell`'s starting
    /// directory — relative to the project root.
    #[serde(default)]
    pub dir: Option<String>,
}

/// Deliberately just two string fields, always shell-form — a hook is
/// inherently one command line, no exec-form ambiguity worth adding.
/// Hooks run as SEPARATE runbox-helper invocations before/after the main
/// command, not sourced into the same shell session — a hook's `cd` or
/// exported vars do not carry over to the command that follows it. Real
/// limitation, stated here rather than left to be discovered.
#[derive(Debug, Default, Deserialize)]
pub struct HooksSection {
    pub on_enter: Option<String>,
    pub on_exit: Option<String>,
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
    parsed
        .permissions
        .validate()
        .map_err(|e| anyhow::anyhow!("box.toml [permissions]: {e}"))?;
    if !parsed.box_.interactive && parsed.run.is_none() {
        anyhow::bail!(
            "box.toml: [box] interactive = false (headless) requires a [run] section with `cmd` — \
             otherwise there is nothing for `runbox start` to run and no way to reach it afterward"
        );
    }
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
