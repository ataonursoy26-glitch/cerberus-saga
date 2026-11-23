"""
modules/network/packet_capture.py
Passive packet capture (Wireshark/tcpdump style) — YOUR OWN machine's traffic.

Captures a SUMMARY (time, source→destination, protocol, length) of a limited
number of packets on the selected interface. Uses the tcpdump binary, which on
macOS/Linux usually needs 'sudo' for BPF access. Returns a clear message without it.

ETHICAL BOUNDARY: passive listening only (not promiscuous, default). It does
NOT capture OTHER people's traffic via ARP poisoning / MITM — this module
only summarizes traffic passing through your own interface. Packet contents
(payload) are not stored; only a header/summary line is kept.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess

log = logging.getLogger("cerberus.pcap")


def available() -> bool:
    return shutil.which("tcpdump") is not None


def capture(interface: str, count: int = 20, bpf_filter: str = "",
            timeout: int = 20) -> dict:
    """
    Captures summaries for up to <count> packets or <timeout> seconds.
    Returns: {"packets": [...], "engine": "tcpdump"|"unavailable", "note": ...}
    """
    if not available():
        return {"packets": [], "engine": "unavailable",
                "note": "tcpdump is not installed. Packet capture requires tcpdump."}

    count = max(1, min(count, 500))
    cmd = ["tcpdump", "-i", interface, "-n", "-l", "-q", "-c", str(count)]
    if bpf_filter:
        cmd += bpf_filter.split()
    log.info("Paket yakalama: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        return {"packets": _parse(out if isinstance(out, str) else out.decode("utf-8", "ignore")),
                "engine": "tcpdump", "note": f"{timeout}s timeout; captured packets returned."}
    except Exception as exc:  # noqa: BLE001
        return {"packets": [], "engine": "error", "note": str(exc)[:120]}

    if proc.returncode != 0 and not proc.stdout:
        err = (proc.stderr or "").strip()
        hint = ("Permission required. Run the admin panel with 'sudo': "
                "sudo python3 cerberus.py serve") if "permission" in err.lower() \
            or "operation not permitted" in err.lower() else err[:160]
        return {"packets": [], "engine": "denied", "note": hint}
    return {"packets": _parse(proc.stdout), "engine": "tcpdump",
            "note": f"Passive capture of up to {count} packets completed."}


_LINE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<proto>\w+)?\s*"
    r"(?P<src>[0-9a-fA-F:.]+)\s*>\s*(?P<dst>[0-9a-fA-F:.]+):"
)


def _parse(out: str) -> list[dict]:
    packets = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE.match(line)
        length = re.search(r"length (\d+)", line)
        if m:
            packets.append({
                "time": m.group("ts"),
                "proto": m.group("proto") or "IP",
                "src": m.group("src"),
                "dst": m.group("dst"),
                "length": length.group(1) if length else "",
            })
        else:
            # Still show the raw summary line (unparseable protocols)
            packets.append({"time": "", "proto": "", "src": "", "dst": "",
                            "length": "", "raw": line[:160]})
    return packets
