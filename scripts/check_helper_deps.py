#!/usr/bin/env python3
"""Fails if runbox-helper's dependencies leave the reviewed allowlist.

Usage:
    python3 scripts/check_helper_deps.py
"""

import sys
from pathlib import Path

import tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
HELPER_MANIFEST = REPO_ROOT / "crates" / "runbox-helper" / "Cargo.toml"
ALLOWED_DEPENDENCIES = {"libc"}


def main() -> int:
    if not HELPER_MANIFEST.exists():
        print(f"FAIL: {HELPER_MANIFEST} not found", file=sys.stderr)
        return 1

    with open(HELPER_MANIFEST, "rb") as f:
        manifest = tomllib.load(f)

    deps = set(manifest.get("dependencies", {}).keys())
    unexpected = deps - ALLOWED_DEPENDENCIES

    if unexpected:
        print(
            f"FAIL: unexpected dependencies in runbox-helper: {sorted(unexpected)}\n"
            f"allowed: {sorted(ALLOWED_DEPENDENCIES)}\n"
            "Update ALLOWED_DEPENDENCIES here as a deliberate, reviewed change if needed.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: runbox-helper dependencies = {sorted(deps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
