from __future__ import annotations

import csv
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
from typing import Iterable, Iterator, List, Optional, Dict

Event = Dict[str, str]

# ---- Colors ----
class C:
    RESET = "\033[0m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
    CYAN="\033[36m"; MAGENTA="\033[35m"; BOLD="\033[1m"

def colorize(etype: str, s: str, enabled: bool) -> str:
    if not enabled: return s
    if etype.startswith("ssh-failed"): return f"{C.RED}{s}{C.RESET}"
    if etype.startswith("ssh-accepted"): return f"{C.GREEN}{s}{C.RESET}"
    if etype.startswith("sudo-cmd"): return f"{C.CYAN}{s}{C.RESET}"
    if etype.startswith("sudo-open"): return f"{C.YELLOW}{s}{C.RESET}"
    if etype.startswith("pkexec"): return f"{C.MAGENTA}{s}{C.RESET}"
    return s

def color_is_enabled(no_color_flag: bool) -> bool:
    return sys.stdout.isatty() and not no_color_flag and os.environ.get("TERM") not in (None, "dumb")

# ---- Regex ----
RE_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\+\-]\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>\S+):\s+(?P<msg>.*)$")
RE_SYSLOG_TS = re.compile(r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>\S+):\s+(?P<msg>.*)$")

RE_SUDO_OPEN = re.compile(r"pam_unix\(sudo:session\): session opened for user (?P<as>\w+).* by (?P<by>\w+)\(uid=\d+\)")
RE_SUDO_CLOSE = re.compile(r"pam_unix\(sudo:session\): session closed for user (?P<as>\w+)")
RE_SUDO_CMD = re.compile(r"^(?P<user>\w+)\s*:\s*TTY=.*;\s*PWD=.*;\s*USER=(?P<as>\w+)\s*;\s*COMMAND=(?P<cmd>.*)$")

RE_SSH_ACCEPT = re.compile(r"Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+) from (?P<ip>\S+).*")
RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+).*")
RE_SSH_DISC = re.compile(r"Disconnected from (?:(?:invalid user )?(?P<user>\S+) )?(?P<ip>\S+).*")

RE_SU = re.compile(r"pam_unix\(su:session\): session opened for user (?P<as>\w+) by (?P<by>\w+)\(uid=\d+\)")
RE_PKEXEC = re.compile(r"pkexec\[(?P<pid>\d+)\]: (?P<user>\w+)\s*:\s*executing\s*command\s*\[(?P<cmd>.+)\]")

def normalize_event(ts: str, host: str, etype: str, actor: str, detail: str) -> Event:
    return {"time": ts, "host": host or "-", "type": etype, "actor": actor, "detail": detail}

# ---- Parsers ----
def parse_journal_lines(lines: Iterable[str]):
    for line in lines:
        m = RE_ISO_TS.match(line.rstrip("\n"))
        if not m: continue
        ts, host, prog, msg = m.group("ts", "host", "prog", "msg")

        if prog.startswith("sudo["):
            if (cm := RE_SUDO_CMD.search(msg)):
                yield normalize_event(ts, host, "sudo-cmd", cm["user"], f"as {cm['as']} → {cm['cmd']}")
                continue
            if (om := RE_SUDO_OPEN.search(msg)):
                yield normalize_event(ts, host, "sudo-open", om["by"], f"as {om['as']}")
                continue
            if (cl := RE_SUDO_CLOSE.search(msg)):
                yield normalize_event(ts, host, "sudo-close", "sudo", f"closed for {cl['as']}")
                continue

        elif prog.startswith("sshd["):
            if (am := RE_SSH_ACCEPT.search(msg)):
                yield normalize_event(ts, host, "ssh-accepted", am["user"], f"from {am['ip']}")
                continue
            if (fm := RE_SSH_FAIL.search(msg)):
                yield normalize_event(ts, host, "ssh-failed", fm["user"], f"from {fm['ip']}")
                continue
            if (dm := RE_SSH_DISC.search(msg)):
                user = dm["user"] or "?"
                yield normalize_event(ts, host, "ssh-disconnect", user, f"from {dm['ip']}")
                continue

        elif prog.startswith("su["):
            if (sm := RE_SU.search(msg)):
                yield normalize_event(ts, host, "su-open", sm["by"], f"as {sm['as']}")
                continue

        elif prog.startswith("pkexec[") or prog.startswith("polkitd["):
            if (pm := RE_PKEXEC.search(msg)):
                yield normalize_event(ts, host, "pkexec", pm["user"], pm["cmd"])
                continue

def parse_syslog_lines(lines: Iterable[str], year: Optional[int] = None):
    if year is None:
        year = dt.datetime.now().year
    for line in lines:
        m = RE_SYSLOG_TS.match(line.rstrip("\n"))
        if not m: continue
        mon, day, time_s, host, prog, msg = m.group("mon", "day", "time", "host", "prog", "msg")
        month_num = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"].index(mon) + 1
        dt_local = dt.datetime.strptime(f"{year}-{month_num:02d}-{int(day):02d} {time_s}", "%Y-%m-%d %H:%M:%S").astimezone()
        ts = dt_local.isoformat(timespec="seconds")
        faux = f"{ts} {host} {prog}: {msg}"
        yield from parse_journal_lines([faux])

# ---- Collection ----
def have_auth_file() -> Optional[str]:
    for p in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(p): return p
    return None

def run_journalctl(grep: Optional[str], since: Optional[str], until: Optional[str]) -> List[str]:
    cmd = ["journalctl", "-o", "short-iso"]
    if since: cmd += ["--since", since]
    if until: cmd += ["--until", until]
    if grep:  cmd += ["-g", grep]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out.splitlines()
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output); return []
    except FileNotFoundError:
        return []

def collect_events(source: str, since: Optional[str], until: Optional[str]) -> List[Event]:
    events: List[Event] = []
    if source in ("auto","journal"):
        for pat in [r"sudo\[", r"sshd\[", r"su\[", r"pkexec\[|polkitd\["]:
            lines = run_journalctl(pat, since, until)
            events.extend(parse_journal_lines(lines))
        if source == "journal" or (source == "auto" and events):
            return list(events)
    if source in ("auto","authlog"):
        if (path := have_auth_file()):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    events.extend(parse_syslog_lines(f))
            except Exception:
                pass
    return list(events)

# ---- Filters/Renderers ----
def passes_filters(ev: Event, args) -> bool:
    if getattr(args, "user", None) and args.user != ev.get("actor"): return False
    if getattr(args, "host", None) and args.host != ev.get("host"): return False
    only = getattr(args, "only", None)
    if only and not any(ev.get("type","").startswith(kind) for kind in only): return False
    return True

def render_table(rows: List[Event], color: bool) -> None:
    if not rows:
        print("No matching events."); return
    cols = ["time","host","type","actor","detail"]
    widths = {c: max(len(c), *(len(r.get(c,"")) for r in rows)) for c in cols}
    def H(s): return f"{C.BOLD}{s}{C.RESET}" if color else s
    print("  ".join(H(c.upper().ljust(widths[c])) for c in cols))
    print("  ".join("-"*widths[c] for c in cols))
    for r in rows:
        t = colorize(r["type"], r["type"].ljust(widths["type"]), color)
        print(
            f"{r['time'].ljust(widths['time'])}  "
            f"{r['host'].ljust(widths['host'])}  "
            f"{t}  "
            f"{r['actor'].ljust(widths['actor'])}  "
            f"{r['detail']}"
        )

def write_csv(rows: List[Event], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["time","host","type","actor","detail"])
        w.writeheader(); w.writerows(rows)

def iso_now_tz() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")

def finalize_output(args, events: List[Event]) -> None:
    # Map friendly kinds for --only
    kind_prefix = {"sudo":("sudo-",), "ssh":("ssh-",), "su":("su-",), "pkexec":("pkexec",)}
    if args.only: args.only = tuple(k for sel in args.only for k in kind_prefix[sel])

    # filter/sort/limit
    rows = [e for e in events if passes_filters(e, args)]
    rows.sort(key=lambda e: e["time"])
    if args.limit and args.limit > 0:
        rows = rows[:args.limit]

    print(f"\n🧾 Found {len(rows)} relevant events:\n")

    if args.format == "table":
        render_table(rows, color_is_enabled(args.no_color))
    elif args.format == "json":
        print(json.dumps(rows, indent=2))
    elif args.format == "csv":
        out = args.output or f"catlog-events-{iso_now_tz().replace(':','').replace('-','')}.csv"
        write_csv(rows, out)
        print(f"CSV written to {out}")
