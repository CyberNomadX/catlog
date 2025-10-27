#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import sys
from typing import Optional


BANNER = """
==========================================================
..######.....###....########.##........#######...######...
.##....##...##.##......##....##.......##.....##.##....##..
.##........##...##.....##....##.......##.....##.##........
.##.......##.....##....##....##.......##.....##.##...####.
.##.......#########....##....##.......##.....##.##....##..
.##....##.##.....##....##....##.......##.....##.##....##..
..######..##.....##....##....########..#######...######...
==========================================================
""".strip("\n")


def print_banner() -> None:
    print(BANNER)


def pretty_os_name() -> str:
    # Prefer the human-friendly name on Linux
    try:
        if platform.system() == "Linux":
            osr = platform.freedesktop_os_release()
            return osr.get("PRETTY_NAME") or osr.get("NAME") or "Linux"
    except Exception:
        pass
    return platform.system()


def is_wsl() -> bool:
    # Heuristic WSL detection
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="ignore") as f:
            return "Microsoft" in f.read()
    except Exception:
        return False


def run_linux_parser() -> int:
    try:
        from parsers.linux import analyze_linux_logs
    except ModuleNotFoundError as e:
        print(f"[!] Linux parser not found: {e}. Ensure 'parsers/linux.py' exists.", file=sys.stderr)
        return 2
    try:
        analyze_linux_logs()
        return 0
    except Exception as e:
        print(f"[!] Linux parser error: {e}", file=sys.stderr)
        return 1


def run_windows_parser() -> int:
    try:
        from parsers.windows import analyze_windows_logs
    except ModuleNotFoundError as e:
        print(f"[!] Windows parser not found: {e}. Ensure 'parsers/windows.py' exists.", file=sys.stderr)
        return 2
    try:
        analyze_windows_logs()
        return 0
    except Exception as e:
        print(f"[!] Windows parser error: {e}", file=sys.stderr)
        return 1


def dispatch_by_os() -> int:
    os_name = platform.system()

    # Print a nice detected name
    detected = pretty_os_name()
    if os_name == "Linux" and is_wsl():
        detected += " (WSL)"
    print(f"Detected OS: {detected}")

    if os_name == "Linux":
        return run_linux_parser()
    elif os_name == "Windows":
        return run_windows_parser()
    else:
        print(f"Operating system not supported: {os_name}")
        print("This script currently only supports Linux and Windows.")
        return 3


def main() -> int:
    print_banner()
    print()
    code = dispatch_by_os()
    print()
    return code


if __name__ == "__main__":
    sys.exit(main())
