"""
modules/offensive/injection_tester.py
Injection tester — reflected XSS and error-based SQLi (authorized pentest).

NON-DESTRUCTIVE: never deletes/modifies data, no DoS. Only:
  * XSS: puts a unique marker into the parameter and checks whether it is
    reflected back UNENCODED in the response (if so, possible XSS).
  * SQLi: appends a single quote to the parameter and checks for a database ERROR
    signature (SQL syntax, mysql_fetch, ORA-, etc.) in the response (if so, possible SQLi).
Runs only on targets listed in scope.yaml.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.inject")

XSS_MARKER = "cerb9z1x<svg/onload=1>"
SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_", r"mysqli?_fetch", r"mysql_num_rows",
    r"ora-\d{5}", r"postgresql.*error", r"psql:.*error",
    r"sqlite_?error", r"unclosed quotation mark", r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server", r"odbc.*sql server",
]
_SQL_RE = re.compile("|".join(SQL_ERRORS), re.I)


@dataclass
class InjectionFinding:
    param: str
    kind: str          # REFLECTED_XSS / SQL_INJECTION
    severity: str
    evidence: str


@dataclass
class InjectionReport:
    target: str
    params_tested: list = field(default_factory=list)
    findings: list = field(default_factory=list)


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[param] = [value]
    newq = urlencode({k: v[0] for k, v in q.items()})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, newq, ""))


class InjectionTester:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "http://" + target

    def run(self) -> InjectionReport:
        rep = InjectionReport(target=self.target)
        parts = urlsplit(self.target)
        params = list(parse_qs(parts.query, keep_blank_values=True).keys())
        if not params:
            rep.findings.append(InjectionFinding("-", "INFO", "INFO",
                "URL has no parameters to test (e.g. add ?id=1)."))
            return rep

        for p in params:
            rep.params_tested.append(p)

            # --- Reflected XSS ---
            xurl = _set_param(self.target, p, XSS_MARKER)
            xr = request(xurl)
            if xr.body and XSS_MARKER in xr.body:
                rep.findings.append(InjectionFinding(p, "REFLECTED_XSS", "HIGH",
                    f"Parameter '{p}' reflected the marker back unencoded."))

            # --- Error-based SQLi ---
            baseline = request(_set_param(self.target, p, "1"))
            sqli = request(_set_param(self.target, p, "1'"))
            m = _SQL_RE.search(sqli.body or "")
            if m and not _SQL_RE.search(baseline.body or ""):
                rep.findings.append(InjectionFinding(p, "SQL_INJECTION", "CRITICAL",
                    f"Adding a single quote to '{p}' triggered a DB error: '{m.group(0)[:40]}'"))

        log.info("Injection test (%s): %d parameters, %d findings.",
                 self.target, len(rep.params_tested), len(rep.findings))
        return rep
