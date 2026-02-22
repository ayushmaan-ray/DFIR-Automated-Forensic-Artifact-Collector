#!/usr/bin/env python3
"""
DFIR Automated Forensic Artifact Collector
Usage: sudo python3 collector.py
       sudo python3 collector.py --output /cases/case-001
       sudo python3 collector.py --modules system,users,processes
"""

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

from modules.system_info import collect_system_info
from modules.users       import collect_user_activity
from modules.processes   import collect_processes
from modules.network     import collect_network_info
from modules.filesystem  import collect_filesystem_info
from modules.logs        import collect_logs


# --- Terminal colors ---
class C:
    HEADER  = '\033[95m'
    BLUE    = '\033[94m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    END     = '\033[0m'


MODULE_MAP = {
    "system":    ("System Information",    collect_system_info),
    "users":     ("User Activity",         collect_user_activity),
    "processes": ("Running Processes",     collect_processes),
    "network":   ("Network Information",   collect_network_info),
    "files":     ("File System Artifacts", collect_filesystem_info),
    "logs":      ("System Logs",           collect_logs),
}


def banner():
    print(f"""{C.BLUE}{C.BOLD}
╔══════════════════════════════════════════════════╗
║     DFIR Automated Forensic Artifact Collector   ║
║              [ Linux Edition v1.0 ]              ║
╚══════════════════════════════════════════════════╝
{C.END}""")


def write_text_report(report, path):
    """Human readable version of the report."""
    sep  = "=" * 60
    sep2 = "-" * 60
    with open(path, "w") as f:
        f.write(f"{sep}\n")
        f.write("  DFIR FORENSIC ARTIFACT REPORT\n")
        f.write(f"{sep}\n\n")

        meta = report["metadata"]
        f.write(f"  Host      : {meta['hostname']}\n")
        f.write(f"  Collected : {meta['collected_at']}\n")
        f.write(f"  Duration  : {meta['duration_seconds']}s\n")
        f.write(f"  Modules   : {', '.join(meta['modules_run'])}\n")
        f.write(f"  Root      : {'Yes' if meta['root'] else 'No (some data may be missing)'}\n\n")

        for mod_key, mod_data in report["artifacts"].items():
            display = MODULE_MAP.get(mod_key, (mod_key,))[0]
            f.write(f"\n{sep2}\n")
            f.write(f"  [{mod_key.upper()}] {display}\n")
            f.write(f"{sep2}\n\n")
            f.write(format_data(mod_data, indent=1))
            f.write("\n")

        f.write(f"\n{sep}\n  END OF REPORT\n{sep}\n")


def format_data(data, indent=0):
    """Recursively turn dict/list into readable text."""
    lines = []
    pad   = "  " * indent

    if isinstance(data, dict):
        if "error" in data and len(data) == 1:
            return f"{pad}ERROR: {data['error']}\n"
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}:")
                lines.append(format_data(v, indent + 1))
            else:
                lines.append(f"{pad}{k:<30}: {v}")
    elif isinstance(data, list):
        if not data:
            lines.append(f"{pad}(none)")
        for item in data:
            if isinstance(item, dict):
                lines.append(format_data(item, indent))
                lines.append(f"{pad}{'·' * 40}")
            else:
                lines.append(f"{pad}- {item}")
    else:
        lines.append(f"{pad}{data}")

    return "\n".join(lines) + "\n"


def run(selected_modules, output_dir):
    banner()

    is_root = os.geteuid() == 0
    if not is_root:
        print(f"{C.YELLOW}[!] Not running as root — some artifacts may be incomplete.{C.END}")
        print(f"{C.YELLOW}    Re-run with: sudo python3 collector.py{C.END}\n")
    else:
        print(f"{C.GREEN}[✔] Running as root — full access.{C.END}\n")

    # --- Setup output directory ---
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname  = os.uname().nodename
    out_dir   = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"forensic_report_{hostname}_{timestamp}"

    # --- Build report skeleton ---
    report = {
        "metadata": {
            "tool":           "DFIR Artifact Collector v1.0",
            "collected_at":   datetime.now().isoformat(),
            "hostname":       hostname,
            "modules_run":    selected_modules,
            "root":           is_root,
            "duration_seconds": 0,
        },
        "artifacts": {}
    }

    start = time.time()

    # --- Run each module ---
    for mod_key in selected_modules:
        if mod_key not in MODULE_MAP:
            print(f"{C.YELLOW}[!] Unknown module '{mod_key}' — skipping.{C.END}")
            continue

        display, func = MODULE_MAP[mod_key]
        print(f"{C.BLUE}{C.BOLD}[+] {display}{C.END}")

        try:
            report["artifacts"][mod_key] = func()
            print(f"{C.GREEN}    ✔ Done{C.END}\n")
        except Exception as e:
            print(f"{C.RED}    ✘ Failed: {e}{C.END}\n")
            report["artifacts"][mod_key] = {"error": str(e)}

    report["metadata"]["duration_seconds"] = round(time.time() - start, 2)

    # --- Save JSON report ---
    json_path = out_dir / f"{base_name}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=4, default=str)
    print(f"{C.GREEN}[✔] JSON report : {json_path}{C.END}")

    # --- Save text report ---
    txt_path = out_dir / f"{base_name}.txt"
    write_text_report(report, txt_path)
    print(f"{C.GREEN}[✔] Text report : {txt_path}{C.END}")

    print(f"\n{C.BOLD}Collection complete in {report['metadata']['duration_seconds']}s{C.END}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="DFIR Artifact Collector")
    parser.add_argument(
        "--output", default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--modules", default="all",
        help="Modules to run: all OR comma-separated list\n"
             "Options: system, users, processes, network, files, logs"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    selected = list(MODULE_MAP.keys()) if args.modules == "all" else [
        m.strip() for m in args.modules.split(",")
    ]
    run(selected, args.output)

