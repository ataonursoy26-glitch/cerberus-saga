"""
modules/network/connection_monitor.py
Live network connection monitor ("watch internet traffic" — passive, no root needed).

Shows the TCP/UDP connections the machine has open RIGHT NOW (local/remote
address, port, state) — not packet contents like Wireshark, but the operating
system's connection table. Fully passive; sends nothing to anyone.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess

log = logging.getLogger("cerberus.conn")

# Service labels for common ports (for readability).
PORT_LABELS = {
    "80": "HTTP", "443": "HTTPS", "22": "SSH", "53": "DNS", "25": "SMTP",
    "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
    "8080": "HTTP-alt", "3389": "RDP", "993": "IMAPS", "995": "POP3S",
}


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:  # noqa: BLE001
        return ""


def snapshot(established_only: bool = True, limit: int = 100) -> dict:
    """Snapshot of the current connections."""
    conns = _parse_lsof() if shutil.which("lsof") else _parse_netstat()
    if established_only:
        conns = [c for c in conns if c.get("state") in ("ESTABLISHED", "")]
    conns = conns[:limit]
    # Uzak port servis etiketi ekle
    for c in conns:
        rport = c.get("remote", "").rsplit(":", 1)[-1]
        c["service"] = PORT_LABELS.get(rport, "")
    return {"connections": conns, "count": len(conns)}


def _parse_lsof() -> list[dict]:
    out = _run(["lsof", "-i", "-n", "-P"])
    conns = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, proto, name = parts[0], parts[7], parts[8]
        state = ""
        m = re.search(r"\((\w+)\)$", line)
        if m:
            state = m.group(1)
        if "->" in name:
            local, remote = name.split("->", 1)
        else:
            local, remote = name, ""
        conns.append({"process": proc, "proto": proto, "local": local,
                      "remote": remote, "state": state})
    return conns


def _parse_netstat() -> list[dict]:
    out = _run(["netstat", "-an"])
    conns = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].lower().startswith(("tcp", "udp")):
            continue
        proto = parts[0]
        local, remote = parts[3], parts[4] if len(parts) > 4 else ""
        state = parts[5] if len(parts) > 5 else ""
        conns.append({"process": "", "proto": proto, "local": local,
                      "remote": remote, "state": state})
    return conns
