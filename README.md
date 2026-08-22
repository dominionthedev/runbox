# Runbox

MacOS-only dev-box isolation. Not a container, not a VM. Local dev use only.

Each project gets a dedicated macOS user account, a compiled Seatbelt
sandbox profile, and a user-scoped PF firewall anchor. Code run inside a
box cannot read host credentials, cannot reach the network except where
explicitly allowed, and cannot write outside the project directory.

## Status

Early. Identity, execution, and network model are implemented; not yet
verified on real hardware. See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Configuration

Two separate files, not one:

- **`box.toml`** — per-project box spec: execution policy, network
  allow/deny, `[env]`, `[setup]`. Lives in the project, committed.
- **`~/.config/runbox/config.toml`** — Runbox's own config: personal
  defaults applied to every box (`defaults.setup`, not part of
  reproduction), doctor scheduling. Not project-specific, not committed
  with any project.

## Architecture

- **Identity** — dedicated macOS user per box (`_runbox_<hash>`). File
  ownership is the DAC boundary.
- **Seatbelt** — static, default-deny profile compiled per box, built on
  Apple's own `bsd.sb`/`system.sb` baseline. Explicit mach-lookup deny
  list beyond that baseline. `dslocal` stays unreachable by omission —
  nothing grants it, not a blanket `/private/var/db` deny.
- **PF** — independent kernel backstop, scoped to the box's uid via PF's
  `user` keyword.
- **Project bridge** — the project directory stays on host; the box
  account gets an ACL grant on it, not a copy.
- **`[env]`** — default-deny, same posture as `[network]`. `set` is
  literal; `pass_through` names host env vars to carry into the box —
  a real hole by design, not masked or filtered.
- **`[setup]`** — user-declared provisioning (files + commands/script).
  Runbox never installs anything on its own.

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
  runbox-core/    config, global_config, identity, seatbelt, pf, env, acl, lock, setup, diff, archive
  runbox-helper/  setuid privilege-drop binary — libc dependency only
```

## Building

```sh
cargo build --workspace
```

Requires Xcode Command Line Tools. Run `scripts/check_env.py` to verify.

## License

MIT.
