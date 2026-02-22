import os
import subprocess
from pathlib import Path


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


def get_current_users():
    """Who is logged in at the time."""
    users = []
    who_output = _run("who")
    for line in who_output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            users.append({
                "user":       parts[0],
                "terminal":   parts[1],
                "login_time": " ".join(parts[2:4]),
                "host":       parts[4] if len(parts) > 4 else "local",
            })
    return users


def get_login_history():
    """Full login history from wtmp."""
    history = []
    last_output = _run("last -n 30 --time-format iso 2>/dev/null || last -n 30")
    for line in last_output.splitlines():
        # Skip the summary line at the bottom
        if line.startswith("wtmp") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            history.append({
                "user":     parts[0],
                "terminal": parts[1],
                "host":     parts[2],
                "datetime": " ".join(parts[3:6]) if len(parts) > 5 else "",
                "duration": parts[-1] if parts[-1].startswith("(") else "",
            })
    return history


def get_failed_logins():
    """Failed login attempts from btmp via lastb."""
    failed = []
    lastb_output = _run("lastb -n 20 2>/dev/null")
    for line in lastb_output.splitlines():
        if line.startswith("btmp") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            failed.append({
                "user":     parts[0],
                "terminal": parts[1],
                "host":     parts[2] if len(parts) > 2 else "",
                "datetime": " ".join(parts[3:6]) if len(parts) > 5 else "",
            })
    return failed

def get_local_users():
    """Read all real user accounts."""
    users = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    uid = int(parts[2])
                    # UID 0 = root, UID >= 1000 = real human users
                    # Everything in between is system/service accounts
                    if uid == 0 or uid >= 1000:
                        users.append({
                            "username": parts[0],
                            "uid":      parts[2],
                            "gid":      parts[3],
                            "home":     parts[5],
                            "shell":    parts[6],
                        })
    except Exception as e:
        return [{"error": str(e)}]
    return users


def get_shell_history():
    """Collect command history for each user, checks all shell types."""
    history = {}

    # Build list of home directories to check
    home_dirs = [Path("/root")]
    home_base  = Path("/home")
    if home_base.exists():
        home_dirs += [d for d in home_base.iterdir() if d.is_dir()]

    # All known shell history files
    history_files = [
        ".bash_history",
        ".zsh_history",
        ".fish_history",
        ".sh_history",
    ]

    suspicious_keywords = [
        "wget", "curl", "nc ", "ncat", "nmap", "chmod +x",
        "base64", "/tmp/", "python -c", "perl -e", "bash -i",
        "rm -rf", "sudo su", "passwd", "adduser", "useradd"
    ]

    for home in home_dirs:
        username = "root" if str(home) == "/root" else home.name
        for hist_file in history_files:
            full_path = home / hist_file
            try:
                if full_path.exists():
                    with open(full_path, errors="replace") as f:
                        lines = [l.strip() for l in f if l.strip()]

                    history[username] = {
                        "history_file":   str(full_path),
                        "total_commands": len(lines),
                        "last_20":        lines[-20:],
                        "suspicious":     [
                            l for l in lines
                            if any(kw in l.lower() for kw in suspicious_keywords)
                        ]
                    }
                    break   # found a history file for this user, stop checking
            except PermissionError:
                history[username] = {"error": "Permission denied"}
            except Exception as e:
                history[username] = {"error": str(e)}

    return history

def get_cron_jobs():
    """Collect cron jobs for all users - common attacker persistence location."""
    crons = {}

    # System wide crontab
    system_crontab = _run("cat /etc/crontab 2>/dev/null")
    if system_crontab:
        crons["system_crontab"] = system_crontab.splitlines()

    # Per user crontabs
    home_dirs = [Path("/root")]
    home_base  = Path("/home")
    if home_base.exists():
        home_dirs += [d for d in home_base.iterdir() if d.is_dir()]

    user_crons = {}
    for home in home_dirs:
        username = "root" if str(home) == "/root" else home.name
        output = _run(f"crontab -l -u {username} 2>/dev/null")
        if output and "no crontab" not in output.lower():
            user_crons[username] = output.splitlines()
    if user_crons:
        crons["user_crontabs"] = user_crons

    return crons


def get_ssh_keys():
    """Check authorized_keys for each user — for backdoors."""
    results = {}

    home_dirs = [Path("/root")]
    home_base  = Path("/home")
    if home_base.exists():
        home_dirs += [d for d in home_base.iterdir() if d.is_dir()]

    for home in home_dirs:
        username   = "root" if str(home) == "/root" else home.name
        keys_file  = home / ".ssh" / "authorized_keys"
        try:
            if keys_file.exists():
                with open(keys_file, errors="replace") as f:
                    keys = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                results[username] = {
                    "count": len(keys),
                    # Only show first 80 chars of each key — they're very long
                    "keys":  [k[:80] + "..." if len(k) > 80 else k for k in keys]
                }
        except PermissionError:
            results[username] = {"error": "Permission denied"}

    return results

def collect_user_activity():
    print("  -> Currently logged in users...")
    data = {}
    data["currently_logged_in"] = get_current_users()

    print("  -> Login history...")
    data["login_history"] = get_login_history()

    print("  -> Failed logins...")
    data["failed_logins"] = get_failed_logins()

    print("  -> Local user accounts...")
    data["local_users"] = get_local_users()

    print("  -> Shell history...")
    data["shell_history"] = get_shell_history()

    print("  -> Cron jobs...")
    data["cron_jobs"] = get_cron_jobs()

    print("  -> SSH authorized keys...")
    data["ssh_keys"] = get_ssh_keys()

    return data

