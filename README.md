# DFIR Automated Forensic Artifact Collector
> **Author:** Ayushman Ray

A command-line forensic investigation tool that automatically collects and analyzes system artifacts from a Linux host for incident response and investigation.


---

## Features

| Module       | What It Collects                                                                 |
|--------------|---------------------------------------------------------------------------------|
| `system`     | OS version, CPU, RAM, disk, uptime, boot time, timezone                        |
| `users`      | Logged-in users, login history, failed logins, bash history, cron jobs, SSH keys |
| `processes`  | All running processes, suspicious processes, deleted-exe detections, services   |
| `network`    | Interfaces, active connections, listening ports, ARP cache, DNS, firewall rules |
| `files`      | Recently modified files, SUID binaries, hidden files, executables in /tmp, USB history |
| `logs`       | Auth events via journald, brute-force detection, system errors, service failures            |

**Output:** A structured `forensic_report_<hostname>_<timestamp>.json` and human-readable `.txt` report.

---

## Requirements

- Python 3.6+
- Linux (tested on Kali Linux, Ubuntu)
- Recommended: run as `root` for full artifact access

No external Python libraries required — uses only the standard library.

---

## Installation

```bash
git clone <your-repo-url>
cd dfir-artifact-collector
chmod +x collector.py
```

---

## Usage

### Collect everything (recommended)
```bash
sudo python3 collector.py
```

### Specify output directory
```bash
sudo python3 collector.py --output /home/kali/cases/case-001
```

### Run specific modules only
```bash
sudo python3 collector.py --modules system,users,processes
sudo python3 collector.py --modules network,logs
```

### Available modules
```
system    - System information
users     - User activity and history
processes - Running processes
network   - Network connections and config
files     - File system artifacts
logs      - System log analysis
```

---

## Output Example

```
reports/
├── forensic_report_<hostname>_<timestamp>.json  ← Full structured data
└── forensic_report_<hostname>_<timestamp>.txt     ← Human-readable report
```

**JSON report structure:**
```json
{
  "metadata": {
    "tool": "DFIR Artifact Collector v1.0",
    "collected_at": "2025-02-22T14:30:22",
    "hostname": "kali",
    "modules_run": ["system", "users", "processes", "network", "files", "logs"]
  },
  "artifacts": {
    "system": { ... },
    "users": { ... },
    "processes": { ... },
    "network": { ... },
    "files": { ... },
    "logs": { ... }
  }
}
```

---

## Project Structure

```
dfir-artifact-collector/
├── collector.py           ← Main entry point
├── modules/
│   ├── __init__.py
│   ├── system_info.py     ← OS, hardware, environment
│   ├── users.py           ← User activity, history, crons
│   ├── processes.py       ← Process analysis
│   ├── network.py         ← Network forensics
│   ├── filesystem.py      ← File system artifacts
│   └── logs.py            ← Log analysis + brute-force detection
└── README.md
```

---

## Resume Description

**Automated Forensic Artifact Collector | Python, Linux, DFIR**
- Developed a modular forensic investigation tool to automatically collect and analyze system artifacts including login history, running processes, network connections, file system anomalies, and system logs
- Implemented suspicious activity detection: brute-force login identification, SUID binary enumeration, malware-associated process flagging, and deleted-executable detection
- Generated structured forensic reports in JSON and human-readable TXT format for incident investigation and timeline reconstruction
- Designed with modular architecture allowing targeted collection by artifact category

---

## Ethical Use

This tool is designed for **authorized forensic investigations and educational purposes only**.  
Always obtain proper authorization before running forensic tools on any system.

---

## Future Enhancements (Ideas)

- [ ] Memory artifact collection (using `/proc/<pid>/maps`)
- [ ] Browser history collection (Chrome, Firefox)
- [ ] Hash verification of critical system binaries
- [ ] Timeline generation (all events sorted by timestamp)
- [ ] HTML report with charts and highlights
- [ ] Integration with VirusTotal API for hash lookup
