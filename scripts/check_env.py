#!/usr/bin/env python3
"""Preflight check for required macOS tooling.

Usage:
    python3 scripts/check_env.py
    python3 scripts/check_env.py --ci
"""

import argparse
import platform
import shutil
import sys

REQUIRED_TOOLS = [
    ("sysadminctl", "account provisioning"),
    ("dscl", "directory-service lookups"),
    ("dseditgroup", "group management"),
    ("pfctl", "PF anchor load/unload"),
    ("chmod", "ACL grant/revoke"),
    ("sandbox-exec", "manual Seatbelt profile verification"),
]


def check_platform() -> tuple[bool, str]:
    if platform.system() != "Darwin":
        return False, f"Runbox is macOS-only. Detected: {platform.system()}"
    return True, f"macOS ({platform.mac_ver()[0] or 'version unknown'})"


def check_tool(name: str) -> tuple[bool, str]:
    path = shutil.which(name)
    if path is None:
        return False, "not found on PATH"
    return True, path


def check_cargo() -> tuple[bool, str]:
    path = shutil.which("cargo")
    if path is None:
        return False, "cargo not found — install via rustup"
    return True, path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci", action="store_true")
    args = parser.parse_args()

    failures = []

    ok, detail = check_platform()
    if not ok:
        failures.append(detail)
    if not args.ci:
        print(f"{'OK  ' if ok else 'FAIL'} platform: {detail}")

    ok, detail = check_cargo()
    if not ok:
        failures.append(f"cargo: {detail}")
    if not args.ci:
        print(f"{'OK  ' if ok else 'FAIL'} cargo: {detail}")

    for tool, reason in REQUIRED_TOOLS:
        ok, detail = check_tool(tool)
        if not ok:
            failures.append(f"{tool}: {detail} ({reason})")
        if not args.ci:
            print(f"{'OK  ' if ok else 'FAIL'} {tool}: {detail} ({reason})")

    if failures:
        if args.ci:
            for f in failures:
                print(f"FAIL: {f}", file=sys.stderr)
        else:
            print(f"\n{len(failures)} check(s) failed.")
        return 1

    if not args.ci:
        print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
