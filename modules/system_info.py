import os
import platform
import subprocess
from datetime import datetime, timedelta


def _run(cmd):
    """Helper - runs a shell command and returns the output as a string."""
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "N/A"


def get_basic_info():
    uname = platform.uname()
    return {
        "hostname":     uname.node,
        "os":           uname.system,
        "kernel":       uname.release,
        "architecture": uname.machine,
        "os_version":   platform.version(),
    }


def get_uptime():
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
        uptime_str  = str(timedelta(seconds=int(uptime_seconds)))
        boot_time   = datetime.fromtimestamp(
            datetime.now().timestamp() - uptime_seconds
        ).isoformat()
        return {
            "uptime":    uptime_str,
            "boot_time": boot_time,
        }
    except Exception as e:
        return {"error": str(e)}


def get_cpu_info():
    return {
        "cpu_model": _run("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip(),
        "cpu_cores": _run("nproc"),
    }


def get_memory_info():
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                meminfo[parts[0].rstrip(":")] = int(parts[1])
        return {
            "total_mb":     meminfo["MemTotal"]     // 1024,
            "available_mb": meminfo["MemAvailable"] // 1024,
            "used_mb":      (meminfo["MemTotal"] - meminfo["MemAvailable"]) // 1024,
        }
    except Exception as e:
        return {"error": str(e)}


def get_disk_info():
    disks = []
    output = _run("df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs")
    lines  = output.splitlines()
    for line in lines[1:]:        # skip header row
        parts = line.split()
        if len(parts) >= 6:
            disks.append({
                "device":      parts[0],
                "size":        parts[1],
                "used":        parts[2],
                "available":   parts[3],
                "use_percent": parts[4],
                "mount":       parts[5],
            })
    return disks


def collect_system_info():
    print("  -> Basic info...")
    data = get_basic_info()

    print("  -> Uptime and boot time...")
    data.update(get_uptime())

    print("  -> CPU...")
    data.update(get_cpu_info())

    print("  -> Memory...")
    data["memory"] = get_memory_info()

    print("  -> Disk usage...")
    data["disks"] = get_disk_info()

    print("  -> Timezone...")
    data["timezone"] = _run("timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null")

    print("  -> Installed packages...")
    data["installed_packages"] = _run("dpkg -l 2>/dev/null | grep -c '^ii' || rpm -qa 2>/dev/null | wc -l")

    print("  -> Kernel modules...")
    data["loaded_kernel_modules"] = _run("lsmod | wc -l")

    print("  -> Environment variables...")
    data["environment_variables"] = {
        "SHELL": os.environ.get("SHELL", "N/A"),
        "HOME":  os.environ.get("HOME",  "N/A"),
        "PATH":  os.environ.get("PATH",  "N/A"),
        "LANG":  os.environ.get("LANG",  "N/A"),
        "USER":  os.environ.get("USER",  "N/A"),
    }

    data["collected_at"] = datetime.now().isoformat()
    return data
