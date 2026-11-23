"""
utils/report_engine.py
Automated technical reporting engine (Blueprint Volume 1, utils).

Always renders the scan result as an HTML report. If weasyprint
is installed it also produces a PDF. Because findings arrive already masked, the report
contains no raw sensitive data (Blueprint Volume 7/8).
"""
from __future__ import annotations

import html
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cerberus.report")

SEVERITY_COLOR = {
    "CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825",
    "LOW": "#2e7d32", "INFO": "#607d8b",
}


def _severity(item) -> str:
    if isinstance(item, dict):
        return str(item.get("severity", "INFO")).upper()
    return str(getattr(item, "severity", "INFO")).upper()


class ReportGenerator:
    def __init__(self, target: str, results: dict, out_dir: str = "reports") -> None:
        self.target = target
        self.results = results
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(exist_ok=True)

    def generate(self) -> Path:
        html_str = self._render_html()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        html_path = self.out_dir / f"cerberus_{safe}_{stamp}.html"
        html_path.write_text(html_str, encoding="utf-8")
        log.info("HTML rapor: %s", html_path)
        self._try_pdf(html_str, html_path.with_suffix(".pdf"))
        return html_path

    def _try_pdf(self, html_str: str, pdf_path: Path) -> None:
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html_str).write_pdf(str(pdf_path))
            log.info("PDF rapor: %s", pdf_path)
        except Exception as exc:  # noqa: BLE001
            log.info("PDF not produced (weasyprint missing or error: %s). HTML is sufficient.", str(exc)[:60])

    # --- HTML generation -----------------------------------------------------
    def _counts(self) -> dict:
        counts = {k: 0 for k in SEVERITY_COLOR}
        buckets = (
            self.results.get("dlp_findings", [])
            + self.results.get("vulnerabilities", [])
            + self.results.get("ai_injection", [])
            + self.results.get("sbom", [])
            + self.results.get("cti", [])
        )
        for item in buckets:
            counts[_severity(item)] = counts.get(_severity(item), 0) + 1
        return counts

    def _render_html(self) -> str:
        meta = self.results.get("meta", {})
        counts = self._counts()
        chips = "".join(
            f'<span class="chip" style="background:{SEVERITY_COLOR[s]}">{s}: {counts[s]}</span>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        audit_ok = meta.get("audit_chain_valid", True)
        audit_badge = ("✅ Immutable audit chain VERIFIED"
                       if audit_ok else "❌ Audit chain is broken!")

        sections = [
            self._kv_section("Network / Port Findings", self.results.get("network", {}).get("ports", [])),
            self._dict_list("Vulnerability Findings (Nuclei + Embedded)", self.results.get("vulnerabilities", [])),
            self._dict_list("DLP: Hassas Veri Maruziyeti (maskeli)", self.results.get("dlp_findings", [])),
            self._dict_list("Tedarik Zinciri (SBOM)", self.results.get("sbom", [])),
            self._dict_list("CTI: Ransomware Korelasyonu", self.results.get("cti", [])),
            self._dict_list("Safe PoC Verification", self.results.get("verified_exploits", [])),
            self._iam_section(self.results.get("iam", {})),
        ]
        body = "\n".join(s for s in sections if s)

        return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>Cerberus Raporu - {html.escape(self.target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}}
 header{{background:#111b24;padding:28px 36px;border-bottom:3px solid #b00020}}
 h1{{margin:0;font-size:24px}} h2{{color:#7fd1ff;border-bottom:1px solid #223;padding-bottom:6px;margin-top:34px}}
 .wrap{{padding:24px 36px;max-width:1100px}}
 .chip{{display:inline-block;color:#fff;padding:5px 12px;border-radius:14px;font-size:13px;margin:4px 6px 4px 0}}
 .meta{{color:#9bb;font-size:13px;margin-top:8px}}
 .audit{{margin-top:12px;font-weight:600;color:{'#2e7d32' if audit_ok else '#b00020'}}}
 table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #223;vertical-align:top}}
 th{{color:#9bb;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
 code{{color:#ffd479}}
 footer{{padding:20px 36px;color:#667;border-top:1px solid #223;font-size:12px}}
</style></head><body>
<header>
 <h1>🛡️ CERBERUS SAGA — Security Audit Report</h1>
 <div class="meta">Hedef: <code>{html.escape(self.target)}</code> ·
   Started: {html.escape(str(meta.get('started_at','-')))} ·
   Elapsed: {meta.get('elapsed_seconds','-')} s</div>
 <div style="margin-top:14px">{chips}</div>
 <div class="audit">{audit_badge}</div>
</header>
<div class="wrap">
 <p>This report is the result of an audit run only on an <b>in-scope</b>
 target. All sensitive findings are <b>masked</b>; it contains no raw data (GDPR-compliant).</p>
 {body}
</div>
<footer>Cerberus Saga · Authorized Defensive Mode · Report auto-generated.</footer>
</body></html>"""

    def _dict_list(self, title: str, items: list) -> str:
        if not items:
            return f"<h2>{html.escape(title)}</h2><p class='meta'>No findings.</p>"
        keys: list[str] = []
        norm = []
        for it in items:
            d = it if isinstance(it, dict) else getattr(it, "__dict__", {"value": str(it)})
            norm.append(d)
            for k in d:
                if k not in keys:
                    keys.append(k)
        head = "".join(f"<th>{html.escape(k)}</th>" for k in keys)
        rows = ""
        for d in norm:
            sev = _severity(d)
            color = SEVERITY_COLOR.get(sev, "#607d8b")
            cells = ""
            for k in keys:
                v = html.escape(str(d.get(k, "")))
                if k == "severity":
                    v = f'<span class="chip" style="background:{color}">{v}</span>'
                cells += f"<td>{v}</td>"
            rows += f"<tr>{cells}</tr>"
        return f"<h2>{html.escape(title)}</h2><table><tr>{head}</tr>{rows}</table>"

    def _kv_section(self, title: str, ports: list) -> str:
        if not ports:
            return f"<h2>{html.escape(title)}</h2><p class='meta'>No open ports found.</p>"
        rows = "".join(
            f"<tr><td><code>{html.escape(str(p.get('port')))}</code></td>"
            f"<td>{html.escape(str(p.get('service','')))}</td>"
            f"<td>{html.escape(str(p.get('product','')))} {html.escape(str(p.get('version','')))}</td></tr>"
            for p in ports)
        return (f"<h2>{html.escape(title)}</h2><table>"
                f"<tr><th>Port</th><th>Service</th><th>Product/Version</th></tr>{rows}</table>")

    def _iam_section(self, iam: dict) -> str:
        if not iam:
            return ""
        out = ["<h2>IAM Denetimi (Identification / Authentication / Authorization)</h2>"]
        for key, label in [("identity", "Identification"), ("authentication", "Authentication"),
                           ("authorization", "Authorization")]:
            rep = iam.get(key)
            if rep is None:
                continue
            items = getattr(rep, "findings", None) or getattr(rep, "surfaces", []) or []
            out.append(self._dict_list(label, list(items)))
        return "\n".join(out)
