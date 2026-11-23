"""
core/orchestrator.py
CERBERUS SAGA - MAIN ORCHESTRATION ENGINE (Blueprint Volume 3, Module 1).

Architecture: micro-service, asynchronous (asyncio), thread-safe.
Mode: AUTHORIZED DEFENSIVE MODE - findings are masked, kept locally,
     every scan is written to a signed audit log (Blueprint Volume 7/8 compliant).

Pipeline stages:
  Stage 0 : Authorization gate + stealth/rate-limit route
  Stage 1 : Passive recon (OSINT / Shodan / DNS)
  Stage 2 : Active network and service analysis (Nmap / Masscan)
  Stage 3 : Vulnerability scanning (Nuclei + OWASP + AI/supply-chain audits)
  Stage 3.5: PII/SPII + financial DLP scanning
  Stage 3.6: IAM audit (Identification / Authentication / Authorization)
  Stage 3.7: Controlled (safe) PoC verification
  Stage 4 : Reporting + session memory cleanup
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from core.event_bus import bus
from core.scope_guard import assert_in_scope

# --- Modules (graceful import: a missing one must not crash the pipeline) ----
from modules.osint.shodan_intel import ShodanScanner
from modules.osint.dns_recon import DNSRecon
from modules.network.port_scanner import NetworkScanner
from modules.network.content_fetch import ContentFetcher
from modules.vulnerability.nuclei_runner import NucleiScanner
from modules.vulnerability.cve_matcher import CVEMatcher
from modules.vulnerability.owasp_top10 import OWASPScanner
from modules.vulnerability.ai_injection_check import AIInjectionScanner
from modules.vulnerability.excessive_agency import AgencyAuditor
from modules.supply_chain.sbom_analyzer import SBOMAnalyzer
from modules.dlp.pii_spii_scanner import PIISPIIScanner
from modules.dlp.financial_scanner import FinancialDataScanner
from modules.iam.identity_enum import IdentityEnumerator
from modules.iam.auth_tester import AuthenticationTester
from modules.iam.authz_tester import AuthorizationTester
from modules.exploit.exploit_verifier import ExploitVerifier
from modules.evasion.waf_evasion import TrafficShaper
from modules.intelligence.ransomware_tracker import RansomwareTracker
from modules.forensics.integrity_log import AuditLog
from modules.forensics.anti_forensics import SessionCleaner
from utils.report_engine import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [CERBERUS-CORE] - %(levelname)s - %(message)s",
)
log = logging.getLogger("cerberus.core")


class CerberusOrchestrator:
    def __init__(self, target: str, demo_blob: str | None = None) -> None:
        self.target = target.strip()
        self.demo_blob = demo_blob
        self.scan_results: Dict[str, Any] = {}
        self.shaper = TrafficShaper()
        self.audit = AuditLog(engagement="DEMO-2026-SCHOOL-PROJECT")
        self.dlp = PIISPIIScanner()
        self.financial = FinancialDataScanner()

    async def run_pipeline(self) -> Dict[str, Any]:
        start = datetime.now(timezone.utc)
        log.info("GHOST-CERBERUS starting | Target -> %s", self.target)

        # --- Stage 0: AUTHORIZATION GATE (most critical check) --------------
        assert_in_scope(self.target)
        self.audit.record("scope_check", {"target": self.target, "result": "AUTHORIZED"})
        await self.shaper.initialize_route()
        await bus.publish("scan", {"stage": "0", "msg": "Authorization gate passed, route ready"})

        try:
            # --- Stage 1: Passive recon ------------------------------------
            log.info("Stage 1: Passive OSINT / DNS recon...")
            self.scan_results["osint"] = await ShodanScanner().fetch(self.target)
            self.scan_results["dns"] = await DNSRecon().enumerate(self.target)
            self.audit.record("osint", {"target": self.target})

            # --- Stage 2: Active network analysis --------------------------
            log.info("Stage 2: Active network / port / service analysis...")
            net = await NetworkScanner(self.target).scan_ports()
            self.scan_results["network"] = net
            self.audit.record("network_scan", {"open_ports": len(net.get("ports", []))})

            # --- Stage 2.5: Real HTTP content fetch ------------------------
            log.info("Stage 2.5: Fetching live HTTP content (real response body)...")
            content = await ContentFetcher(self.target).fetch()
            self.scan_results["content"] = {
                "pages": [{"path": p["path"], "status": p["status"],
                           "bytes": len(p["body"])} for p in content["pages"]],
            }
            self.audit.record("content_fetch", {"pages": len(content["pages"])})

            # --- Stage 3: Vulnerability scanning ---------------------------
            log.info("Stage 3: Vulnerability scans (Nuclei + OWASP + AI + SBOM)...")
            vulns = await NucleiScanner(self.target).run_templates()
            cve_banners = net.get("banners", []) + content.get("bodies", [])
            if self.demo_blob:
                cve_banners = cve_banners + [self.demo_blob]
            vulns += await CVEMatcher().match(cve_banners)
            self.scan_results["vulnerabilities"] = vulns
            self.scan_results["owasp"] = await OWASPScanner(self.target).scan()
            self.scan_results["ai_injection"] = await AIInjectionScanner().audit(
                {"banners": net.get("banners", []) + content.get("bodies", [])})
            self.scan_results["excessive_agency"] = await AgencyAuditor().audit()
            self.scan_results["sbom"] = await SBOMAnalyzer().analyze()
            self.audit.record("vuln_scan", {"engine": "nuclei+owasp"})

            # --- Stage 3.5: DLP (PII/SPII + financial) ---------------------
            log.info("Stage 3.5: Sensitive data (PII/SPII + financial) exposure scan...")
            dlp_findings = []
            sources = net.get("banners", []) + content.get("bodies", [])
            if self.demo_blob:
                sources = sources + [self.demo_blob]
            for blob in sources:
                if not blob:
                    continue
                dlp_findings += (await self.dlp.scan_async(blob, self.target)).findings
                dlp_findings += (await self.financial.scan_async(blob, self.target)).findings
            self.scan_results["dlp_findings"] = dlp_findings
            self.audit.record("dlp_scan", {"findings": len(dlp_findings)})

            # --- Stage 3.6: IAM audit --------------------------------------
            log.info("Stage 3.6: IAM (Identification / Authentication / Authorization)...")
            self.scan_results["iam"] = await self._run_iam()

            # --- Stage 3.7: Controlled PoC verification --------------------
            log.info("Stage 3.7: SAFE PoC verification for discovered findings...")
            verifier = ExploitVerifier(self.scan_results["vulnerabilities"])
            self.scan_results["verified_exploits"] = await verifier.verify()

            # --- CTI korelasyonu --------------------------------------------
            self.scan_results["cti"] = await RansomwareTracker().correlate(
                self.scan_results["vulnerabilities"]
            )

        finally:
            # --- Stage 4: Session memory cleanup (RAM only; never deletes logs)-
            await SessionCleaner().purge_process_memory()

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        self.scan_results["meta"] = {
            "target": self.target,
            "started_at": start.isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "audit_chain_valid": self.audit.verify_chain(),
        }

        # --- Stage 4: Report ------------------------------------------------
        log.info("Stage 4: Generating report...")
        report_path = ReportGenerator(self.target, self.scan_results).generate()
        self.scan_results["report_path"] = str(report_path)
        self.audit.record("report_generated", {"path": str(report_path)})
        log.info("Completed (%.2fs). Report: %s", elapsed, report_path)
        return self.scan_results

    async def _run_iam(self) -> dict:
        """Runs the IAM triad with safe/passive techniques."""
        base = f"http://{self.target}" if "://" not in self.target else self.target
        identity = await IdentityEnumerator(authorized_scope=[self.target]).probe(base + "/login")
        auth = await AuthenticationTester().run_all(
            session_cookie="demo_session_token_abc123xyz789",
            protected_endpoint=base + "/dashboard",
            reset_response_text="If the account exists, an email was sent.",
        )
        authz = await AuthorizationTester().run_all(
            resource_url_template=base + "/api/user/{id}",
            own_id="1001", other_id="1002",
            admin_endpoint=base + "/admin",
        )
        return {"identity": identity, "authentication": auth, "authorization": authz}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m core.orchestrator <target>")
        sys.exit(1)
    asyncio.run(CerberusOrchestrator(sys.argv[1]).run_pipeline())
