# Runbox

MacOS-only dev-box isolation. Not a container, not a VM. Local dev use only.

Each project gets a dedicated macOS user account, a compiled Seatbelt
sandbox profile, and a user-scoped PF firewall anchor. Code run inside a
box cannot read host credentials, cannot reach the network except where
explicitly allowed, and cannot write outside the project directory.

## Status

Early. Identity, execution, and network model are implemented; not yet
verified on real hardware. See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Architecture

- **Identity** — dedicated macOS user per box (`_runbox_<hash>`). File
  ownership is the DAC boundary.
- **Seatbelt** — static, default-deny profile compiled per box. Explicit
  mach-lookup deny list. No shared system temp. No `/private/var/db` read
  access.
- **PF** — independent kernel backstop, scoped to the box's uid via PF's
  `user` keyword.
- **Project bridge** — the project directory stays on host; the box
  account gets an ACL grant on it, not a copy.
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
  runbox-core/    config, identity, seatbelt, pf, acl, lock, setup, diff, archive
  runbox-helper/  setuid privilege-drop binary — libc dependency only
```

## Building

```sh
cargo build --workspace
```

Requires Xcode Command Line Tools. Run `scripts/check_env.py` to verify.

## License

MIT.
