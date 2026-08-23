# Runbox

macOS-only dev-box isolation. Not a container, not a VM. Local dev use only.

Each project gets a dedicated macOS user account, a compiled Seatbelt
sandbox profile, and a user-scoped PF firewall anchor. Code run inside a
box cannot read host credentials, cannot reach the network except where
explicitly allowed, and cannot write outside the project directory.

## Building

```sh
cargo build --workspace
```

Requires Xcode Command Line Tools. Run `scripts/check_env.py` to verify.

`exec`/`shell`/`start` additionally require `runbox-helper` installed
setuid-root — separate from `make install` deliberately, since this is
the one privileged, security-relevant step `cargo build` alone can't do:

```sh
make install-helper
```

## Commands

| Command                                             | Does                                                                                                                                                      |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runbox init [--name] [--headless --run-cmd <cmd>]` | Create an initial `box.toml` in the current directory.                                                                                                    |
| `runbox spec show/edit/path/validate`               | View, edit, locate, or validate the current project's `box.toml`.                                                                                         |
| `runbox config show/edit/path`                      | View, edit, or locate Runbox's own config (`~/.config/runbox/config.toml`).                                                                               |
| `runbox build`                                      | Provision the box account, compile the Seatbelt profile, load the PF anchor, write box.lock. `exec`/`shell`/headless start all require box.lock to exist. |
| `runbox exec [cmd...]`                              | Run a command in the box. No args falls back to `[run].cmd`. Interactive boxes only — headless boxes reject this, see below.                              |
| `runbox shell`                                      | Enter an interactive shell (`[box].shell`) in the box. Interactive boxes only.                                                                            |
| `runbox setup`                                      | Run `[setup]` (provisioning files + commands/script) against the box account.                                                                             |
| `runbox destroy`                                    | Revoke ACL, delete the box account, unload the PF anchor. Stops any running headless service first.                                                       |
| `runbox start`                                      | Headless boxes only — register and load a launchd service running `[run].cmd`.                                                                            |
| `runbox stop`                                       | Stop a running headless box's launchd service.                                                                                                            |
| `runbox status`                                     | Show whether a headless box's service is currently running.                                                                                               |
| `runbox logs [--follow] [--lines N]`                | Show a headless box's stdout log.                                                                                                                         |
| `runbox doctor`                                     | Detect orphaned box accounts from interrupted builds.                                                                                                     |
| `runbox snapshot` / `restore`                       | Not yet implemented.                                                                                                                                      |
| `runbox ps`                                         | Not yet implemented.                                                                                                                                      |

### Command quoting — this matters

`runbox exec` and `[run].cmd` both follow a shell-form / exec-form
convention:

- **One argument** → shell-form. Wrapped as `$SHELL -c '<arg>'` and run
  inside the box, so env expansion happens there.
- **More than one argument** → exec-form. Run directly via `execv`, no
  shell involved.

This means quoting choice changes behavior, not just readability:

```sh
runbox exec 'echo $HOME'     # ONE arg (single-quoted) — shell-form.
                              # Host shell never touches $HOME; it expands
                              # inside the box, against the box's own HOME.

runbox exec "echo $HOME"     # Host shell expands $HOME BEFORE runbox ever
                              # sees it — the box receives an already-
                              # resolved HOST path baked into a literal
                              # string. Usually not what you want.

runbox exec npm install      # TWO args, unquoted — exec-form. No shell,
                              # no expansion concern either way.
```

Prefer single quotes for anything with `$VARS`, pipes, or `&&` that
should evaluate inside the box.

## Configuration

Two separate files, not one:

- **`box.toml`** — per-project box spec. Lives in the project, committed.
- **`~/.config/runbox/config.toml`** — Runbox's own config: personal
  defaults applied to every box, doctor scheduling. Not project-specific.

### `box.toml`

```toml
schema_version = 1   # versions the format, not the tool — see box.lock's runbox_version

[box]
name = "myproject"
lifecycle = "persistent"   # persistent | stateless | ephemeral
interactive = true          # false = headless — see below
shell = "/bin/zsh"          # what `runbox shell` execs

[network]
mode = "deny"                # deny | allow — each accepts only its own list
allowlist = ["registry.npmjs.org:443"]
denylist = []                 # valid only when mode = "allow"
dns = "localhost-only"
timeout = "30s"

[env]
set = { NODE_ENV = "development" }
pass_through = []             # host env vars carried in by name — a real
                               # hole by design, not masked or filtered
path_extra = []                # appends to PATH, never replaces it — see
                                # "Toolchain access" below

[permissions]
read = []                     # extra host paths, absolute, beyond the project dir
write = []

[run]
cmd = "npm run dev"           # or ["npm", "run", "dev"] — see quoting rules above
dir = "src"                   # optional cwd, relative to project root

[hooks]
on_enter = "echo entering box"
on_exit = "echo leaving box"

[setup]
provision = [{ src = "npmrc.template", dest = ".npmrc" }]
commands = ["npm ci"]         # mutually exclusive with `script`

[audit]
record = true
retention = "30d"
```

### `~/.config/runbox/config.toml`

```toml
[defaults.setup]              # applied to every box, before the project's
provision = []                 # own [setup]. NOT part of box.lock —
commands = []                  # personal preference, not a project requirement

[doctor]
after_destroy = true
scheduled = false              # opt-in periodic sweep via launchd, not a daemon
interval = "24h"

[hooks]                        # wraps every box's own [hooks] — see below
on_enter = ""
on_exit = ""
```

## Headless boxes

`[box] interactive = false` requires `[run].cmd` — box.toml fails to
parse otherwise. Without it there's nothing for `runbox start` to run and
no way to reach the box afterward.

```sh
runbox build
runbox start     # writes ~/Library/LaunchAgents/dev.dominionthe.runbox.<name>.plist,
                  # loads it via launchctl — launchd supervises it, Runbox
                  # doesn't run a daemon of its own
runbox status
runbox logs --follow
runbox stop
```

`runbox exec` and `runbox shell` are rejected outright on a headless box —
no foreground interaction, by definition. stdout/stderr go to
`.runbox/logs/`, read via `runbox logs`. There's no way to attach a
terminal to a headless box; that's what makes it headless.

**Unverified on real hardware** — the plist shape and `launchctl`
invocation follow documented conventions, not yet run, unlike the rest of
this project's security-relevant paths.

## Toolchain access

rustup, nvm, pyenv all install per-user by convention, into the host
account's home. A box account has no access to that by default — no ACL
grant, no Seatbelt allow, and `runbox-helper` hardcodes a minimal `PATH`.
A fresh box has no `cargo`, no `node`, nothing, until one of:

**Recommended: install the toolchain inside the box, via `[setup]`.**
Runs as the box account, lands in the box's own home — fully
self-contained, no bridge into host territory. Slower first build, disk
duplicated per box, nothing shared across boxes — but it's also exactly
the kind of state `.box` archives are meant to capture, so the cost is
paid once per box, not once per run.

**Escape hatch: bridge to the host's existing install.** Pair a
`[permissions].read` grant with `[env].path_extra` on the same directory:

```toml
[permissions]
read = ["/Users/dominion/.cargo", "/Users/dominion/.rustup"]

[env]
path_extra = ["/Users/dominion/.cargo/bin"]
```

`path_extra` only appends to `PATH` — `[env].set` rejects `PATH` outright,
specifically so a config can't silently shadow trusted binaries.

## Hooks

`on_enter`/`on_exit` run as separate `runbox-helper` invocations
before/after the main command — not sourced into the same shell session,
so a `cd` or export in a hook does not carry into the command that
follows it. Global config's hooks wrap the box's own: `on_enter` runs
global-then-box, `on_exit` runs box-then-global.

## Architecture

- **Identity** — dedicated macOS user per box (`_runbox_<hash>`). File
  ownership is the DAC boundary.
- **Seatbelt** — static, default-deny profile compiled per box, built on
  Apple's own `bsd.sb`/`system.sb` baseline. Explicit mach-lookup deny
  list beyond that baseline. `dslocal` stays unreachable by omission.
  `TMPDIR` is resolved and canonicalized by `runbox-helper` AFTER the
  privilege drop — verified per-account and symlink-sensitive on real
  hardware, not assumed.
- **PF** — independent kernel backstop, scoped to the box's uid via PF's
  `user` keyword.
- **Project bridge** — the project directory stays on host; the box
  account gets an ACL grant on it (`GrantMode::ReadOnly`/`ReadWrite`), not
  a copy.
- **`runbox-helper`** — the only privileged component. Validates the
  target account, drops privilege irreversibly, resolves `TMPDIR`,
  applies the Seatbelt profile, sets `--env` pairs, execs. `libc`
  dependency only — see `CONTRIBUTING.md` for why that's enforced in CI.

## Guarantees and limits

Guaranteed: DAC boundary, static Seatbelt enforcement, PF backstop,
uid-based process attribution regardless of fork depth.

Not guaranteed: no real-time behavioral enforcement (Seatbelt is fixed at
spawn), no audit trail for permitted actions (only denials are logged;
best-effort pre/post-exec diff mitigates this partially), not
adversarial-grade isolation, no payload-level network inspection.

## Layout

```
crates/
  runbox/         CLI
  runbox-core/    config, global_config, identity, seatbelt, pf, env, acl,
                  lock, setup, diff, archive, launchd
  runbox-helper/  setuid privilege-drop binary — libc dependency only
```

## License

MIT.
