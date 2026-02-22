import re
import subprocess
from pathlib import Path
from datetime import datetime


def _run(cmd):
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return ""


def get_auth_events():
    """
    Authentication events — logins, sudo usage, SSH attempts.
    Uses journalctl since Kali doesn't always have /var/log/auth.log.
    Falls back to auth.log if it exists.
    """
    results = {}

    # Try journalctl first (modern systemd systems)
    journal_auth = _run(
        "journalctl _COMM=sudo _COMM=sshd _COMM=login "
        "--since '24 hours ago' --no-pager -n 100 2>/dev/null"
    )

    if journal_auth:
        lines = journal_auth.splitlines()
        results["source"]        = "journald"
        results["all_events"]    = lines

        # Sudo usage — who ran what as root
        results["sudo_usage"]    = [
            l for l in lines if "sudo" in l.lower() and "command" in l.lower()
        ]

        # Failed authentication attempts
        results["auth_failures"] = [
            l for l in lines
            if any(kw in l.lower() for kw in [
                "failed", "failure", "invalid user",
                "authentication failure", "wrong password"
            ])
        ]

        # Successful logins
        results["successful_logins"] = [
            l for l in lines
            if any(kw in l.lower() for kw in [
                "accepted password", "accepted publickey",
                "session opened", "new session"
            ])
        ]

    # Also try flat file as fallback
    elif Path("/var/log/auth.log").exists():
        lines = []
        try:
            with open("/var/log/auth.log", errors="replace") as f:
                lines = f.readlines()[-100:]
            lines = [l.rstrip() for l in lines]
        except PermissionError:
            lines = ["[Permission denied — run as root]"]

        results["source"]        = "auth.log"
        results["all_events"]    = lines
        results["sudo_usage"]    = [l for l in lines if "sudo" in l.lower()]
        results["auth_failures"] = [
            l for l in lines
            if any(kw in l.lower() for kw in ["failed", "failure", "invalid"])
        ]
        results["successful_logins"] = [
            l for l in lines if "accepted" in l.lower() or "session opened" in l.lower()
        ]
    else:
        results["source"] = "none found"
        results["note"]   = "No auth log source available"

    return results


def get_brute_force_candidates(auth_events):
    """
    Count failed login attempts per IP address.
    Possible brute force attack.
    """
    ip_counts = {}
    failures  = auth_events.get("auth_failures", [])

    for line in failures:
        # Extract any IP addresses from the log line
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        for ip in ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Only return IPs with 3+ failures
    candidates = [
        {"ip": ip, "failure_count": count}
        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])
        if count >= 3
    ]
    return candidates


def get_system_errors():
    """
    High priority system errors from the last 24 hours.
    Crashes, kernel panics, service failures.
    """
    errors = _run(
        "journalctl -p err..emerg --since '24 hours ago' "
        "--no-pager -n 50 2>/dev/null"
    )
    return errors.splitlines() if errors else []


def get_service_failures():
    """
    Services that crashed or failed recently.
    Attackers sometimes crash services to cover tracks or cause disruption.
    """
    failures = _run(
        "journalctl --no-pager -n 50 2>/dev/null | "
        "grep -i 'failed\\|crash\\|killed\\|core dump\\|segfault'"
    )
    return failures.splitlines() if failures else []


def get_log_inventory():
    """
    List all log files with sizes and modification times.
    Unusually large or recently modified logs can indicate tampering.
    Also - if a log file was DELETED or is empty, that's suspicious.
    """
    inventory = []
    log_dir   = Path("/var/log")
    try:
        for f in sorted(log_dir.iterdir()):
            if f.is_file():
                stat = f.stat()
                inventory.append({
                    "file":      str(f),
                    "size_kb":   round(stat.st_size / 1024, 1),
                    "modified":  datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
    except Exception:
        pass
    return inventory


def get_dpkg_changes():
    """
    Recently installed or removed packages.
    Attackers sometimes install tools (ncat, socat) or remove security software.
    """
    output = _run(
        "grep 'install\\|remove\\|upgrade' /var/log/dpkg.log 2>/dev/null | tail -20"
    )
    return output.splitlines() if output else []


def collect_logs():
    print("  -> Authentication events...")
    data = {}
    auth = get_auth_events()
    data["auth_events"] = auth

    print("  -> Brute force detection...")
    data["brute_force_candidates"] = get_brute_force_candidates(auth)

    print("  -> System errors...")
    data["system_errors"] = get_system_errors()

    print("  -> Service failures...")
    data["service_failures"] = get_service_failures()

    print("  -> Package changes...")
    data["recent_package_changes"] = get_dpkg_changes()

    print("  -> Log file inventory...")
    data["log_inventory"] = get_log_inventory()

    return data

