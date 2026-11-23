"""
utils/assessment_report.py
Unified security assessment report (all module outputs in one document).

Takes recon + fingerprint + TLS + email + storefront findings, sorts by
severity, and produces a colored HTML report (plus PDF if weasyprint exists).
It only formats the findings given to it; it makes no network requests.
"""
from __future__ import annotations

import html
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cerberus.assess")

SEVC = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825",
        "LOW": "#2e7d32", "INFO": "#607d8b"}
_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def collect(target: str) -> tuple[dict, list[dict]]:
    """Runs all modules on an authorized target and returns (stack, sections).
 So the CLI and web dashboard share the same logic."""
    from modules.offensive.tech_fingerprint import TechFingerprint
    from modules.offensive.web_recon import WebRecon
    from modules.web.tls_analyzer import TLSAnalyzer
    from modules.web.email_security import EmailSecurityAuditor
    from modules.web.storefront_audit import StorefrontAuditor

    sections: list[dict] = []
    fp = TechFingerprint(target).run()
    stack = dict(fp.get("stack", {}))
    sections.append({"title": "Vulnerability / CVE Hints (version-based)",
                     "findings": [{"severity": c["severity"], "area": c["template"],
                                   "detail": f"{c['name']} — {c['detail']}"} for c in fp.get("cve_hints", [])]})
    tls = TLSAnalyzer(target).analyze()
    stack.update({f"TLS {k}": v for k, v in tls.info.items()})
    sections.append({"title": "TLS / Sertifika",
                     "findings": [{"severity": f.severity, "area": f.check, "detail": f.detail} for f in tls.findings]})
    em = EmailSecurityAuditor().audit(target)
    sections.append({"title": "Email Security (anti-phishing)",
                     "findings": [{"severity": f.severity, "area": f.check, "detail": f.detail} for f in em.findings]})
    sf = StorefrontAuditor(target).audit()
    sf_f = [{"severity": f.severity, "area": f.area, "detail": f.detail} for f in sf.findings]
    for label, ok in sf.trust_pages.items():
        if not ok:
            sf_f.append({"severity": "MEDIUM", "area": "Trust Page", "detail": f"{label} not found."})
    sections.append({"title": "Store Security & Trust", "findings": sf_f})
    rc = WebRecon(target).run()
    sections.append({"title": "Active Web Recon (exposure)",
                     "findings": [{"severity": f.severity, "area": f.path, "detail": f"{f.status} — {f.detail}"} for f in rc.findings]})

    # --- Extended offensive audits (each one is error-guarded) ---
    def _safe(title, fn):
        try:
            sections.append({"title": title, "findings": fn()})
        except Exception as exc:  # noqa: BLE001
            sections.append({"title": title, "findings": [{"severity": "INFO", "area": "hata", "detail": str(exc)[:80]}]})

    def _csp():
        from modules.offensive.csp_analyzer import CSPAnalyzer
        r = CSPAnalyzer(target).run()
        return [{"severity": f.severity, "area": f.directive, "detail": f.detail} for f in r.findings]

    def _cors():
        from modules.offensive.cors_test import CORSTester
        r = CORSTester(target).run()
        return [{"severity": f.severity, "area": "CORS", "detail": f.detail} for f in r.findings]

    def _host():
        from modules.offensive.host_header import HostHeaderTester
        r = HostHeaderTester(target).run()
        return [{"severity": f.severity, "area": f.vector, "detail": f.detail} for f in r.findings]

    def _methods():
        from modules.offensive.http_methods import HTTPMethodTester
        r = HTTPMethodTester(target).run()
        return [{"severity": f.severity, "area": "HTTP metot", "detail": f.detail} for f in r.findings]

    def _jsleak():
        from modules.offensive.js_secret_scan import JSSecretScanner
        r = JSSecretScanner(target).run()
        if r.inconclusive:
            return [{"severity": "INFO", "area": "access", "detail": "Rate-limited — deferred."}]
        return [{"severity": f.severity, "area": f.category, "detail": f"{f.masked} <- {f.source}"} for f in r.findings]

    def _headers():
        from modules.offensive.security_headers import SecurityHeaderAuditor
        r = SecurityHeaderAuditor(target).run()
        if r.inconclusive:
            return [{"severity": "INFO", "area": "access", "detail": "Rate-limited — deferred."}]
        return [{"severity": f.severity, "area": f.header, "detail": f.detail} for f in r.findings]

    def _dns():
        from modules.offensive.dns_audit import DNSAuditor
        r = DNSAuditor(target).run()
        return [{"severity": f.severity, "area": f.check, "detail": f.detail} for f in r.findings]

    def _tls():
        from modules.offensive.tls_scan import TLSScanner
        r = TLSScanner(target).run()
        return [{"severity": f.severity, "area": "TLS version", "detail": f.detail} for f in r.findings]

    _safe("Security Headers", _headers)
    _safe("TLS Protocol Versions", _tls)
    _safe("DNS Security (AXFR/CAA/DNSSEC)", _dns)
    _safe("CSP + Clickjacking", _csp)
    _safe("CORS Configuration", _cors)
    _safe("Host Header Injection", _host)
    _safe("HTTP Method Abuse", _methods)
    _safe("Client-Side Secret Leak (JS)", _jsleak)
    return stack, sections


def build(target: str, sections: list[dict], stack: dict, out_dir: str = "reports") -> Path:
    """
    sections: [{"title": str, "findings": [{"severity","area"/"check","detail"}]}]
    stack: technology fingerprint dictionary
    """
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    counts = {k: 0 for k in SEVC}
    for sec in sections:
        for f in sec["findings"]:
            s = str(f.get("severity", "INFO")).upper()
            counts[s] = counts.get(s, 0) + 1
    chips = "".join(
        f'<span class="chip" style="background:{SEVC[s]}">{s}: {counts[s]}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    stack_rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in stack.items()) or "<tr><td colspan=2>—</td></tr>"

    # Priority actions (executive summary)
    try:
        from modules.remediation import recommend
        actions = recommend(sections)
    except Exception:  # noqa: BLE001
        actions = []
    act_html = ""
    if actions:
        rows = "".join(
            f'<tr><td><span class="chip" style="background:{SEVC.get(a["severity"],"#607d8b")}">{a["severity"]}</span></td>'
            f'<td>{html.escape(a["action"])}</td></tr>' for a in actions)
        act_html = f'<h2>🛠️ Priority Actions ({len(actions)})</h2><table><tr><th>Priority</th><th>Action</th></tr>{rows}</table>'

    sec_html = act_html
    for sec in sections:
        fs = sorted(sec["findings"], key=lambda x: _ORDER.get(str(x.get("severity", "INFO")).upper(), 9))
        rows = ""
        for f in fs:
            sev = str(f.get("severity", "INFO")).upper()
            label = f.get("area") or f.get("check") or ""
            rows += (f'<tr><td><span class="chip" style="background:{SEVC.get(sev,"#607d8b")}">{sev}</span></td>'
                     f'<td>{html.escape(str(label))}</td><td>{html.escape(str(f.get("detail","")))}</td></tr>')
        if not rows:
            rows = '<tr><td colspan=3 class="muted">No findings.</td></tr>'
        sec_html += f'<h2>{html.escape(sec["title"])}</h2><table><tr><th>Severity</th><th>Area</th><th>Description</th></tr>{rows}</table>'

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    path = out / f"assessment_{safe}_{stamp}.html"
    doc = f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>Cerberus Assessment — {html.escape(target)}</title><style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}}
 header{{background:#111b24;padding:26px 34px;border-bottom:3px solid #b00020}}
 h1{{margin:0;font-size:22px}} h2{{color:#7fd1ff;border-bottom:1px solid #223;padding-bottom:6px;margin-top:30px}}
 .wrap{{padding:22px 34px;max-width:1050px}} .chip{{color:#fff;padding:5px 12px;border-radius:14px;font-size:13px;margin:3px 5px 3px 0;display:inline-block}}
 table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #223;vertical-align:top}}
 th{{color:#9bb;text-transform:uppercase;font-size:11px}} .muted{{color:#667}}
 footer{{padding:18px 34px;color:#667;border-top:1px solid #223;font-size:12px}}
</style></head><body>
<header><h1>🛡️ Cerberus — Unified Security Assessment</h1>
<div style="color:#9bb;font-size:13px;margin-top:6px">Hedef: <code>{html.escape(target)}</code> · {datetime.now():%Y-%m-%d %H:%M}</div>
<div style="margin-top:12px">{chips}</div></header>
<div class="wrap">
<h2>Technology Fingerprint</h2><table><tr><th>Component</th><th>Value</th></tr>{stack_rows}</table>
{sec_html}
<p class="muted" style="margin-top:24px">All tests were run on an in-scope target using non-destructive techniques. Sensitive data is masked.</p>
</div>
<footer>Cerberus Saga · Authorized Defensive Mode · auto-generated</footer>
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=doc).write_pdf(str(path.with_suffix(".pdf")))
    except Exception:  # noqa: BLE001
        pass
    log.info("Assessment report: %s", path)
    return path
