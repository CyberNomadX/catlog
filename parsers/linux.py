import os
import re
import subprocess
from datetime import datetime

def analyze_linux_logs():
    log_paths = [
        "/var/log/auth.log",     # Debian/Ubuntu
        "/var/log/secure"         # RHEL/CentOS
    ]

    log_file = None
    for path in log_paths:
        if os.path.exists(path):
            log_file = path
            break

    if log_file:
        print(f"📄 Scanning log file: {log_file}")
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    else:
        print("⚙️  No auth log found, trying journalctl (systemd)")
        try:
            journal_output = subprocess.check_output(
                ["journalctl", "--no-pager", "--output=short-iso"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            lines = journal_output.splitlines()
        except Exception as e:
            print(f"❌ Failed to read from journalctl: {e}")
            return

    events = []
    for line in lines:
        if any(keyword in line for keyword in ["Failed password", "Accepted password", "sudo"]):
            events.append(line.strip())

    print(f"\n🧾 Found {len(events)} relevant events:\n")
    for line in events[-20:]:  # Show last 20 events
        print(pretty_print_event(line))

def pretty_print_event(log_line):
    timestamp_match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", log_line)
    timestamp = timestamp_match.group(0) if timestamp_match else ""

    if "Failed password" in log_line:
        user_ip = re.search(r"Failed password.*?for (invalid user )?(\w+) from ([\d.:]+)", log_line)
        if user_ip:
            username = user_ip.group(2)
            ip = user_ip.group(3)
            return f"❌ Failed SSH login for '{username}' from {ip} at {timestamp}"
        return f"❌ Failed login at {timestamp}: {log_line}"

    elif "Accepted password" in log_line:
        user_ip = re.search(r"Accepted password.*?for (\w+) from ([\d.:]+)", log_line)
        if user_ip:
            username = user_ip.group(1)
            ip = user_ip.group(2)
            return f"✅ Successful SSH login for '{username}' from {ip} at {timestamp}"
        return f"✅ Successful login at {timestamp}: {log_line}"

    elif "sudo" in log_line:
        return f"🔐 Sudo usage at {timestamp}: {log_line}"

    else:
        return f"ℹ️ Event: {log_line}"

if __name__ == "__main__":
    analyze_linux_logs()
