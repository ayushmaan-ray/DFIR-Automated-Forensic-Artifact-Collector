import subprocess
from pathlib import Path


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


# Ports commonly used by malware and C2 frameworks
SUSPICIOUS_PORTS = {
    "4444", "4445", "1234", "31337",
    "6666", "6667", "6668", "6669",
    "8888", "9999", "1337", "12345",
    "54321", "65535"
}


def get_interfaces():
    interfaces = []
    output = _run("ip -o addr show 2>/dev/null")
    seen   = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            iface = parts[1]
            if iface not in seen:
                seen.add(iface)
                interfaces.append({
                    "interface": iface,
                    "address":   parts[3],
                    "state":     "UP" if "UP" in line else "DOWN",
                })
    return interfaces


def get_connections():
    """
    All active network connections.
    Also flags any connection to a known suspicious port.
    """
    connections = []
    suspicious  = []

    output = _run("ss -tunap 2>/dev/null")
    for line in output.splitlines()[1:]:      # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        conn = {
            "proto":   parts[0],
            "state":   parts[1],
            "local":   parts[4],
            "remote":  parts[5] if len(parts) > 5 else "",
            "process": parts[-1] if len(parts) > 6 else "",
        }
        connections.append(conn)

        # Check if remote port is suspicious
        remote = conn["remote"]
        if remote and remote not in ("*:*", "0.0.0.0:*"):
            port = remote.split(":")[-1]
            if port in SUSPICIOUS_PORTS:
                conn["suspicious_reason"] = f"Known malware port: {port}"
                suspicious.append(conn)

    return connections, suspicious


def get_listening_ports():
    ports   = []
    output  = _run("ss -tlnup 2>/dev/null")
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            ports.append({
                "proto":   parts[0],
                "address": parts[4],
                "process": parts[-1] if len(parts) > 5 else "",
            })
    return ports


def get_arp_cache():
    """
    ARP cache — shows other machines this host has recently talked to.
    In forensics this reveals what else is on the network.
    """
    arp     = []
    output  = _run("ip neigh show 2>/dev/null")
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            arp.append({
                "ip":    parts[0],
                "iface": parts[2],
                "mac":   parts[4] if len(parts) > 4 else "",
                "state": parts[-1],
            })
    return arp


def get_dns_config():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except Exception:
        pass
    return servers


def get_hosts_file():
    """
    Check for hosts file poisoning.
    Attackers modify this to redirect legitimate domains to malicious IPs.
    """
    entries = []
    try:
        with open("/etc/hosts") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
    except Exception:
        pass
    return entries


def collect_network_info():
    print("  -> Network interfaces...")
    data = {}
    data["interfaces"] = get_interfaces()

    print("  -> Active connections...")
    connections, suspicious = get_connections()
    data["active_connections"]    = connections
    data["suspicious_connections"] = suspicious

    print("  -> Listening ports...")
    data["listening_ports"] = get_listening_ports()

    print("  -> ARP cache...")
    data["arp_cache"] = get_arp_cache()

    print("  -> DNS configuration...")
    data["dns_servers"] = get_dns_config()

    print("  -> Hosts file...")
    data["hosts_file"] = get_hosts_file()

    return data

