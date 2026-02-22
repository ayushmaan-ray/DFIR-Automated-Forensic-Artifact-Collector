import subprocess
from pathlib import Path
from datetime import datetime


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


def get_suid_binaries():
    """
    SUID binaries — run as file owner (often root) regardless of who executes them.
    Attackers abuse these for privilege escalation.
    Check results against GTFOBins.
    """
    binaries = []
    output   = _run("find / -perm -4000 -type f -not -path '/proc/*' 2>/dev/null")
    for line in output.splitlines():
        binaries.append(line.strip())
    return binaries


def get_world_writable_dirs():
    """
    Directories anyone can write to.
    Attackers use these to drop files without needing special permissions.
    /tmp and /var/tmp are expected — anything else is suspicious.
    """
    dirs   = []
    output = _run(
        "find / -maxdepth 5 -type d -perm -0002 "
        "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null"
    )
    for line in output.splitlines():
        dirs.append(line.strip())
    return dirs


def get_recently_modified_files():
    """
    Files modified in the last 24 hours.
    In an incident this helps build a timeline of what changed and when.
    """
    files  = []
    output = _run(
        "find / -maxdepth 6 -type f "
        "-not -path '/proc/*' -not -path '/sys/*' "
        "-not -path '/dev/*'  -not -path '/run/*' "
        "-newer /proc/1/exe "           # newer than PID 1 = modified since boot
        "2>/dev/null | head -50"
    )
    for line in output.splitlines():
        files.append(line.strip())
    return files


def get_hidden_files():
    """
    Hidden files (starting with .) in locations malware commonly uses.
    Legitimate hidden files exist everywhere — flag unusual locations.
    """
    results     = {}
    search_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home"]

    for d in search_dirs:
        p = Path(d)
        if p.exists():
            output = _run(f"find {d} -maxdepth 3 -name '.*' -type f 2>/dev/null")
            if output:
                results[d] = output.splitlines()
    return results


def get_executables_in_tmp():
    """
    Executable files sitting in /tmp or /dev/shm.
    Legitimate software never installs itself here.
    This is almost always malware.
    """
    output = _run("find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null")
    return output.splitlines() if output else []


def get_critical_file_timestamps():
    """
    Modification timestamps on files attackers commonly tamper with.
    Unexpected recent modifications = red flag.
    """
    results   = {}
    critical  = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/hosts",
        "/etc/ssh/sshd_config",
    ]
    for f in critical:
        output = _run(f"stat -c '%n | Modified: %y | Size: %s bytes' {f} 2>/dev/null")
        if output:
            results[f] = output
    return results


def get_usb_history():
    """
    USB devices that have been plugged in.
    Data exfiltration via USB is a classic insider threat method.
    """
    usb = []
    dmesg_output = _run(
        "dmesg 2>/dev/null | grep -i usb | "
        "grep -i 'storage\\|attached\\|new.*device' | tail -20"
    )
    if dmesg_output:
        usb.extend(dmesg_output.splitlines())
    return usb


def collect_filesystem_info():
    print("  -> SUID binaries...")
    data = {}
    data["suid_binaries"] = get_suid_binaries()

    print("  -> World writable directories...")
    data["world_writable_dirs"] = get_world_writable_dirs()

    print("  -> Recently modified files...")
    data["recently_modified_files"] = get_recently_modified_files()

    print("  -> Hidden files in sensitive locations...")
    data["hidden_files"] = get_hidden_files()

    print("  -> Executables in /tmp...")
    data["executables_in_tmp"] = get_executables_in_tmp()

    print("  -> Critical file timestamps...")
    data["critical_file_timestamps"] = get_critical_file_timestamps()

    print("  -> USB history...")
    data["usb_history"] = get_usb_history()

    return data
