"""
modules/network/interfaces.py
Network interface discovery and selection (Blueprint extension — "cyber machine").

Lists the local machine's network interfaces (en0, eth0, lo0, ...) with
IP/MAC/status. Does NOT require root. Reads system commands (ifconfig / ip),
falling back to the Python stdlib. Shows ONLY your own machine's interfaces.
"""
from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess

log = logging.getLogger("cerberus.iface")


def _run(cmd: list[str], timeout: int = 5) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:  # noqa: BLE001
        return ""


def list_interfaces() -> list[dict]:
    """{name, ipv4, mac, status, is_loopback} for each interface."""
    out = _run(["ifconfig"]) if shutil.which("ifconfig") else _run(["ip", "addr"])
    ifaces: list[dict] = []
    current: dict | None = None

    for line in out.splitlines():
        # ifconfig (macOS/BSD): "en0: flags=..."  |  ip: "2: eth0: <...>"
        m = re.match(r"^(?:\d+:\s*)?([A-Za-z0-9@._-]+):?\s", line)
        if m and not line.startswith((" ", "\t")):
            if current:
                ifaces.append(current)
            name = m.group(1).split("@")[0]
            current = {"name": name, "ipv4": "", "mac": "", "status": "unknown",
                       "is_loopback": name.startswith("lo")}
            if "RUNNING" in line or "UP" in line or "state UP" in line:
                current["status"] = "up"
        if current is None:
            continue
        ip = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if ip:
            current["ipv4"] = ip.group(1)
        mac = re.search(r"(?:ether|link/ether)\s+([0-9a-fA-F:]{17})", line)
        if mac:
            current["mac"] = mac.group(1)
        if "status: active" in line or "state UP" in line:
            current["status"] = "up"
        elif "status: inactive" in line:
            current["status"] = "down"
    if current:
        ifaces.append(current)

    if not ifaces:  # last resort: at least hostname/IP via the stdlib
        try:
            ip = socket.gethostbyname(socket.gethostname())
            ifaces.append({"name": "default", "ipv4": ip, "mac": "",
                           "status": "up", "is_loopback": False})
        except Exception:  # noqa: BLE001
            pass
    log.info("Network interfaces: %d found.", len(ifaces))
    return ifaces


def default_gateway() -> dict:
    """Default gateway and egress interface."""
    info = {"gateway": "", "interface": ""}
    out = _run(["netstat", "-rn"])
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] in ("default", "0.0.0.0"):
            if len(parts) >= 2:
                info["gateway"] = parts[1]
            info["interface"] = parts[-1]
            break
    return info


def local_subnet_hosts(limit: int = 0) -> dict:
    """
    Reads KNOWN neighbour devices on the local network from the ARP table (passive).
    Does NOT actively scan or ARP-poison; only shows neighbours the OS already knows.
    """
    out = _run(["arp", "-a"])
    hosts = []
    for line in out.splitlines():
        m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-fA-F:]+)", line)
        if m:
            hosts.append({"ip": m.group(1), "mac": m.group(2)})
    if limit:
        hosts = hosts[:limit]
    return {"neighbors": hosts, "count": len(hosts),
            "note": "OS ARP table (passive) — no active scanning/ARP spoofing performed."}
