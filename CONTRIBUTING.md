# Contributing

## Verification bar

Claims about behavior (a denied syscall, a blocked connection, a stripped
executable bit) must be confirmed on real macOS hardware before being
treated as working. `cargo build` succeeding is not verification.

## Scope discipline

A fix-only change must not introduce new directory structures, config
sections, or architectural concepts. If a change requires new
architecture, state that explicitly rather than folding it into an
unrelated fix.

## Privileged code

`crates/runbox-helper` runs setuid-root. Any change to it requires
justification: does it change what the binary is allowed to become, or
only what it does before dropping privilege. New dependencies in that
crate require deliberate review, not a routine `cargo add`.
