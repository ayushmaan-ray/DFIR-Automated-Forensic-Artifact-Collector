import os
import subprocess
from pathlib import Path


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


SUSPICIOUS_KEYWORDS = [
    "nc ", "ncat", "netcat", "nmap", "meterpreter",
    "reverse", "shell", "backdoor", "payload",
    "cobalt", "sliver", "beacon", "mimikatz",
    "/tmp/", "/dev/shm/", "base64 -d",
    "python -c", "perl -e", "bash -i",
    "socat", "xmrig", "minerd",
]


def get_all_processes():
    processes = []
    output = _run("ps aux --no-headers")
    for line in output.splitlines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append({
                "user":    parts[0],
                "pid":     parts[1],
                "cpu":     parts[2],
                "mem":     parts[3],
                "tty":     parts[6],
                "stat":    parts[7],
                "started": parts[8],
                "command": parts[10],
            })
    return processes


def get_suspicious_processes(all_processes):
    suspicious = []
    for proc in all_processes:
        cmd_lower = proc["command"].lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in cmd_lower:
                proc["reason"] = f"Keyword match: '{kw}'"
                suspicious.append(proc)
                break
    return suspicious


def get_deleted_exe_processes():
    """
    Processes whose executable was deleted from disk but still running.
    Classic malware technique — run, then delete themself so can't find.    Linux keeps running it from memory anyway.
    """
    deleted = []
    try:
        for pid_dir in Path("/proc").iterdir():
            if pid_dir.name.isdigit():
                exe_link = pid_dir / "exe"
                try:
                    target = os.readlink(exe_link)
                    if "(deleted)" in target:
                        cmdline = (pid_dir / "cmdline").read_bytes()
                        cmdline = cmdline.replace(b'\x00', b' ').decode(errors="replace")
                        deleted.append({
                            "pid":     pid_dir.name,
                            "exe":     target,
                            "cmdline": cmdline.strip(),
                        })
                except (PermissionError, FileNotFoundError, OSError):
                    pass
    except Exception as e:
        return [{"error": str(e)}]
    return deleted


def collect_processes():
    print("  -> All running processes...")
    all_procs = get_all_processes()

    print("  -> Scanning for suspicious processes...")
    suspicious = get_suspicious_processes(all_procs)

    print("  -> Checking for deleted executable processes...")
    deleted = get_deleted_exe_processes()

    print("  -> Running services...")
    services_output = _run("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null")
    services = []
    for line in services_output.splitlines():
        parts = line.split(None, 4)
        if parts:
            services.append({
                "service":     parts[0],
                "active":      parts[2] if len(parts) > 2 else "",
                "description": parts[4] if len(parts) > 4 else "",
            })

    return {
        "total_count":              len(all_procs),
        "all_processes":            all_procs,
        "suspicious_processes":     suspicious,
        "deleted_exe_processes":    deleted,
        "running_services":         services,
    }

