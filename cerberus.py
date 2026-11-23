#!/usr/bin/env python3
"""
cerberus.py -- Command-line entry point (Blueprint Volume 1, CLI Entrypoint).

Komutlar:
  python cerberus.py demo               # end-to-end demo on a local/isolated target (no network needed)
  python cerberus.py scan <hedef>       # scan a target listed in scope.yaml
  python cerberus.py verify-audit       # verify the immutable audit chain
  python cerberus.py scope              # list the authorization scope
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from config.settings import get_authorized_scope           # noqa: E402
from core.orchestrator import CerberusOrchestrator          # noqa: E402
from modules.forensics.integrity_log import AuditLog        # noqa: E402
from utils.ai_brain import AIBrain                           # noqa: E402

BANNER = r"""
   ____          _
  / ___|___ _ __| |__   ___ _ __ _   _ ___
 | |   / _ \ '__| '_ \ / _ \ '__| | | / __|
 | |__|  __/ |  | |_) |  __/ |  | |_| \__ \
  \____\___|_|  |_.__/ \___|_|   \__,_|___/  SAGA
  Authorized Defensive Security Platform
"""


def _severity_of(x) -> str:
    return (x.get("severity") if isinstance(x, dict) else getattr(x, "severity", "INFO")) or "INFO"


def _print_summary(results: dict) -> None:
    print("\n" + "=" * 62)
    print("  SCAN SUMMARY")
    print("=" * 62)
    meta = results.get("meta", {})
    print(f"  Target          : {meta.get('target')}")
    print(f"  Elapsed         : {meta.get('elapsed_seconds')} s")
    print(f"  Audit chain     : {'VERIFIED ✅' if meta.get('audit_chain_valid') else 'BROKEN ❌'}")
    print(f"  Open ports      : {len(results.get('network', {}).get('ports', []))}")
    print(f"  Vulnerabilities : {len(results.get('vulnerabilities', []))}")
    print(f"  DLP findings    : {len(results.get('dlp_findings', []))}")
    print(f"  CTI alerts      : {len(results.get('cti', []))}")

    dlp = results.get("dlp_findings", [])
    if dlp:
        print("\n  --- DLP (masked) first 12 findings ---")
        for f in dlp[:12]:
            cat = getattr(f, "category", "?")
            sev = _severity_of(f)
            masked = getattr(f, "match_masked", "")
            print(f"   [{sev:<8}] {cat:<24} {masked}")

    cti = results.get("cti", [])
    if cti:
        print("\n  --- CTI: Ransomware correlation ---")
        for a in cti:
            print(f"   [{a['priority']}] {a['cve']} -> {', '.join(a['linked_ransomware_groups'])}")

    print("\n  " + AIBrain().summarize(results))
    print(f"\n  📄 Report: {results.get('report_path')}")
    print("=" * 62 + "\n")


async def _run(target: str, demo_blob: str | None) -> dict:
    results = await CerberusOrchestrator(target, demo_blob=demo_blob).run_pipeline()
    return results


def cmd_demo(_args) -> None:
    print(BANNER)
    print(">> DEMO MODE: local/isolated target (localhost); a leaky sample response is injected.\n")
    blob = (BASE / "tests/fixtures/leaky_response.txt").read_text(encoding="utf-8")
    results = asyncio.run(_run("localhost", demo_blob=blob))
    _print_summary(results)


def cmd_scan(args) -> None:
    print(BANNER)
    results = asyncio.run(_run(args.target, demo_blob=None))
    _print_summary(results)
    if args.json:
        print(json.dumps({k: str(v) for k, v in results.get("meta", {}).items()}, indent=2))


def cmd_verify_audit(_args) -> None:
    log = AuditLog(engagement="DEMO-2026-SCHOOL-PROJECT")
    ok = log.verify_chain()
    print(f"Audit chain ({log.path}): {'VERIFIED ✅' if ok else 'BROKEN ❌'}")
    sys.exit(0 if ok else 1)


def cmd_scope(_args) -> None:
    print("Authorization scope (scope.yaml):")
    for s in get_authorized_scope():
        print(f"  - {s}")


def cmd_secret_scan(args) -> None:
    from modules.dlp.secret_audit import SecretAuditor
    print(BANNER)
    print(f">> SECRET LEAK AUDIT: {args.path}\n")
    report = SecretAuditor().scan_dir(args.path)
    print("=" * 62)
    print(f"  Files scanned : {report.files_scanned}")
    print(f"  Secret findings: {len(report.findings)}")
    print("=" * 62)
    if report.findings:
        print("  ⚠️  Possible hardcoded secrets (masked):\n")
        for f in report.findings[:50]:
            print(f"   [{f.severity:<8}] {f.category:<24} {f.match_masked}")
            print(f"       {f.file}:{f.line}")
    else:
        print("  ✅ No hardcoded secrets found. Clean.")
    print()


def cmd_crypto_scan(args) -> None:
    import os
    from pathlib import Path
    from modules.crypto.exchange_guard import ExchangeGuard
    from modules.dlp.secret_audit import SKIP_DIRS, SKIP_EXT, MAX_FILE_BYTES
    print(BANNER)
    print(f">> CRYPTO LEAK AUDIT: {args.path}\n")
    guard = ExchangeGuard()
    root = Path(args.path).expanduser().resolve()
    findings, scanned = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            fp = Path(dirpath) / name
            if fp.suffix.lower() in SKIP_EXT:
                continue
            try:
                if fp.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            scanned += 1
            for f in guard.scan_text(text).findings:
                findings.append((fp, f))
    print("=" * 62)
    print(f"  Files scanned : {scanned}")
    print(f"  Crypto findings: {len(findings)}")
    print("=" * 62)
    for fp, f in findings[:50]:
        try:
            rel = fp.relative_to(root)
        except ValueError:
            rel = fp
        print(f"   [{f.severity:<8}] {f.kind:<20} {f.masked}")
        print(f"       {rel} — {f.detail}")
    if not findings:
        print("  ✅ No hardcoded crypto secret found.")
    print()


def cmd_crypto_phish(args) -> None:
    from modules.crypto.exchange_guard import ExchangeGuard
    g = ExchangeGuard()
    for d in args.domains:
        res = g.check_phishing_domain(d)
        if res:
            print(f"  [{res.severity:<5}] {d:<28} {res.detail}")
        else:
            print(f"  [OK   ] {d:<28} does not resemble known exchanges.")


def cmd_assess(args) -> None:
    from modules.offensive.tech_fingerprint import TechFingerprint  # triggers the authorization gate
    from core.scope_guard import assert_in_scope
    from utils.assessment_report import collect, build
    assert_in_scope(args.target)
    print(BANNER)
    print(f">> UNIFIED SECURITY ASSESSMENT: {args.target}\n")
    from modules.posture import score_findings, save_snapshot, diff_last
    from modules.offensive._requester import request
    pre = request(args.target, timeout=8)
    if pre.status in (429, 403, 503) or pre.status == 0:
        print(f"  ⏸️  ASSESSMENT DEFERRED -- target returned HTTP {pre.status} "
              "(likely Cloudflare rate-limit). Stopped to avoid emitting a fake grade.")
        print("  Wait a few minutes and retry. (The tool backs off to avoid stressing the target.)\n")
        return
    stack, sections = collect(args.target)
    path = build(args.target, sections, stack)
    score, grade, counts = score_findings(sections)
    save_snapshot(args.target, sections, stack)
    total = sum(len(s["findings"]) for s in sections)
    print(f"  🏅 SECURITY GRADE: {grade}  ({score}/100)")
    print(f"  Findings: " + " ".join(f"{k}:{v}" for k, v in counts.items() if v))
    print(f"  Total findings: {total}")
    d = diff_last(args.target)
    if d.get("enough"):
        print(f"  Vs previous assessment: grade {d['prev_grade']}→{d['cur_grade']}, "
              f"{len(d['new'])} new / {len(d['resolved'])} resolved findings")
    print(f"  📄 Unified report: {path}\n")


def cmd_history(args) -> None:
    from modules.posture import list_snapshots, diff_last
    print(BANNER)
    snaps = list_snapshots(args.target)
    print(f">> MONITORING HISTORY: {args.target}  ({len(snaps)} assessments)\n")
    for s in snaps[-10:]:
        c = s["counts"]
        print(f"   {s['ts']}  not {s['grade']:<2} ({s['score']}/100)  "
              f"C:{c.get('CRITICAL',0)} H:{c.get('HIGH',0)} M:{c.get('MEDIUM',0)} L:{c.get('LOW',0)}")
    d = diff_last(args.target)
    if d.get("enough"):
        print(f"\n  Diff of last two assessments (grade {d['prev_grade']}→{d['cur_grade']}):")
        for k in d["new"]:
            print(f"   + NEW: {k}")
        for k in d["resolved"]:
            print(f"   - RESOLVED: {k}")
    elif snaps:
        print("\n  (At least 2 assessments are required to compare.)")
    print()


def cmd_verify_ownership(args) -> None:
    from modules.offensive.ownership import check, add_to_scope
    print(BANNER)
    domain = args.domain
    res = check(domain)
    if res["verified"]:
        add_to_scope(res["domain"])
        print(f"  ✅ OWNERSHIP VERIFIED ({res['method'].upper()}): {res['domain']}")
        print(f"  '{res['domain']}' is now in scope -- active scan commands unlocked.\n")
    else:
        print(f"  ⏳ '{res['domain']}' is not verified yet.\n")
        print("  To prove ownership, do ONE OF THE FOLLOWING, then run the command again:\n")
        print(f"  1) HTTP: place a file at this URL with this content")
        print(f"       URL : https://{res['domain']}/.well-known/cerberus-verify.txt")
        print(f"       Content: {res['token']}\n")
        print(f"  2) DNS : add this TXT record")
        print(f"       {res['domain']}  TXT  \"{res['token']}\"\n")
        print(f"  To re-verify: python3 cerberus.py verify-ownership {res['domain']}\n")


def cmd_headers(args) -> None:
    from modules.offensive.security_headers import SecurityHeaderAuditor
    print(BANNER)
    print(f">> SECURITY HEADER AUDIT: {args.target}\n")
    rep = SecurityHeaderAuditor(args.target).run()
    if rep.inconclusive:
        print("  ⏸️  Rate-limited/unreachable -- deferred.\n"); return
    for f in rep.findings:
        print(f"   [{f.severity:<7}] {f.header:<30} {f.detail}")
    print()


def cmd_csp(args) -> None:
    from modules.offensive.csp_analyzer import CSPAnalyzer
    print(BANNER)
    print(f">> CSP + CLICKJACKING ANALYSIS: {args.target}\n")
    rep = CSPAnalyzer(args.target).run()
    if rep.inconclusive:
        print("  ⏸️  Target rate-limited/unreachable -- deferred.\n"); return
    print(f"  CSP: {(rep.csp[:90]+'…') if len(rep.csp)>90 else (rep.csp or 'YOK')}\n")
    for f in rep.findings:
        print(f"   [{f.severity:<7}] {f.directive:<22} {f.detail}")
    print()


def cmd_jsleak(args) -> None:
    from modules.offensive.js_secret_scan import JSSecretScanner
    print(BANNER)
    print(f">> CLIENT-SIDE (JS) SECRET LEAK: {args.target}\n")
    rep = JSSecretScanner(args.target).run()
    if rep.inconclusive:
        print("  ⏸️  Target returned rate-limit/unreachable -- deferred.\n")
        return
    print(f"  Scripts scanned: {rep.scripts_scanned}  |  Findings: {len(rep.findings)}\n")
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.category:<20} {f.masked}  <- {f.source}")
    if not rep.findings:
        print("  ✅ No hardcoded secret found in the frontend.")
    print()


def cmd_hosthdr(args) -> None:
    from modules.offensive.host_header import HostHeaderTester
    print(BANNER)
    print(f">> HOST HEADER INJECTION TEST: {args.target}\n")
    for f in HostHeaderTester(args.target).run().findings:
        print(f"   [{f.severity:<7}] {f.vector:<18} {f.detail}")
    print()


def cmd_methods(args) -> None:
    from modules.offensive.http_methods import HTTPMethodTester
    print(BANNER)
    print(f">> HTTP METHOD ABUSE TEST: {args.target}\n")
    rep = HTTPMethodTester(args.target).run()
    print(f"  Allow: {rep.allow or '-'}\n")
    for f in rep.findings:
        print(f"   [{f.severity:<7}] {f.detail}")
    print()


def cmd_jwt(args) -> None:
    from modules.offensive.jwt_analyzer import JWTAnalyzer
    print(BANNER)
    print(">> JWT WEAKNESS ANALYSIS\n")
    rep = JWTAnalyzer().analyze(args.token)
    print(f"  Header : {rep.header}")
    print(f"  Payload: {rep.payload}")
    if rep.cracked_secret:
        print(f"  🔓 CRACKED SECRET: '{rep.cracked_secret}'")
    print()
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.check:<16} {f.detail}")
    print()


def cmd_jslib(args) -> None:
    from modules.offensive.js_lib_cve import JSLibCVE
    print(BANNER)
    print(f">> JS LIBRARY CVE TEST: {args.target}\n")
    rep = JSLibCVE(args.target).run()
    if rep.inconclusive:
        print("  ⏸️  Rate-limited/unreachable -- deferred.\n"); return
    if rep.libraries:
        print("  Detected: " + ", ".join(f"{l['lib']} {l['version']}" for l in rep.libraries) + "\n")
    for f in rep.findings:
        print(f"   [{f['severity']:<7}] {f['lib']:<12} {f['detail']}")
    print()


def cmd_graphql(args) -> None:
    from modules.offensive.graphql_introspect import GraphQLIntrospect
    print(BANNER)
    print(f">> GRAPHQL INTROSPECTION TEST: {args.target}\n")
    for f in GraphQLIntrospect(args.target).run().findings:
        print(f"   [{f['severity']:<7}] {f['path']:<22} {f['detail']}")
    print()


def cmd_trackers(args) -> None:
    from modules.offensive.tracker_audit import TrackerAuditor
    print(BANNER)
    print(f">> TRACKER / PRIVACY AUDIT: {args.target}\n")
    rep = TrackerAuditor(args.target).run()
    if rep.inconclusive:
        print("  ⏸️  Rate-limited/unreachable -- deferred.\n"); return
    for f in rep.findings:
        print(f"   [{f['severity']:<7}] {f['detail']}")
    print()


def cmd_tls_scan(args) -> None:
    from modules.offensive.tls_scan import TLSScanner
    print(BANNER)
    print(f">> TLS PROTOCOL SCAN: {args.target}\n")
    rep = TLSScanner(args.target).run()
    print("  Supported versions: " +
          ", ".join(f"{k}{'✓' if v else '✗'}" for k, v in rep.supported.items()) + "\n")
    for f in rep.findings:
        print(f"   [{f.severity:<7}] {f.detail}")
    print()


def cmd_dns_audit(args) -> None:
    from modules.offensive.dns_audit import DNSAuditor
    print(BANNER)
    print(f">> DNS SECURITY AUDIT: {args.domain}\n")
    rep = DNSAuditor(args.domain).run()
    print(f"  Nameservers: {', '.join(rep.nameservers) or '-'}\n")
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.check:<8} {f.detail}")
    print()


def cmd_subdomains(args) -> None:
    from modules.offensive.subdomain_enum import SubdomainEnum
    print(BANNER)
    print(f">> SUBDOMAIN DISCOVERY: {args.domain}\n")
    rep = SubdomainEnum(args.domain).run()
    print(f"  {len(rep.found)}/{rep.tested} resolved:\n")
    for s in rep.found:
        print(f"   {s['subdomain']:<36} {s['ip']}")
    print()


def cmd_fuzz(args) -> None:
    from modules.offensive.param_fuzzer import ParamFuzzer
    print(BANNER)
    print(f">> PARAMETER FUZZ (LFI/SSTI/CMDi -- non-destructive): {args.target}\n")
    rep = ParamFuzzer(args.target).run()
    print(f"  Parameters tested: {', '.join(rep.params_tested) or '-'}\n")
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.kind:<16} param='{f.param}'  {f.evidence}")
    print()


def cmd_cors(args) -> None:
    from modules.offensive.cors_test import CORSTester
    print(BANNER)
    print(f">> CORS MISCONFIGURATION TEST: {args.target}\n")
    rep = CORSTester(args.target).run()
    print(f"  ACAO: {rep.acao or '-'} | ACAC: {rep.acac or '-'}\n")
    for f in rep.findings:
        print(f"   [{f.severity}] {f.detail}")
    print()


def cmd_redirect(args) -> None:
    from modules.offensive.open_redirect import OpenRedirectTester
    print(BANNER)
    print(f">> OPEN REDIRECT TEST: {args.target}\n")
    rep = OpenRedirectTester(args.target).run()
    for f in rep.findings:
        print(f"   [{f.severity}] param='{f.param}' {f.detail}")
    print()


def cmd_harvest(args) -> None:
    from modules.offensive.harvester import RawHarvester
    print(BANNER)
    print(f">> RAW DATA HARVEST (read-only, data pull): {args.target}\n")
    rep = RawHarvester(args.target).harvest()
    print("=" * 62)
    print(f"  Hedef       : {rep.target}")
    print(f"  Output dir  : {rep.out_dir}")
    print(f"  Items pulled: {rep.products_count}")
    print("=" * 62)
    for it in rep.items:
        flag = "✓" if it.status == 200 else ("·" if it.status else "✗")
        print(f"   {flag} {it.path:<28} {it.status}  {it.bytes:>8} bytes  {it.note}")
    if rep.rate_limited:
        print("\n  ⚠️  Target enforced rate-limit (429) -- the tool backed off respectfully.")
    print(f"\n  📁 Raw files: {rep.out_dir}\n")


def cmd_fingerprint(args) -> None:
    from modules.offensive.tech_fingerprint import TechFingerprint
    print(BANNER)
    print(f">> TECHNOLOGY FINGERPRINT: {args.target}\n")
    rep = TechFingerprint(args.target).run()
    print("=" * 62)
    for k, v in rep.get("stack", {}).items():
        print(f"   {k:<16}: {v}")
    print("=" * 62)
    if rep.get("cve_hints"):
        print("  Version-based CVE hints:")
        for c in rep["cve_hints"]:
            print(f"   [{c['severity']}] {c['template']} {c['name']} — {c['detail']}")
    print()


def cmd_recon(args) -> None:
    from modules.offensive.web_recon import WebRecon
    print(BANNER)
    print(f">> ACTIVE WEB RECON (authorized): {args.target}\n")
    rep = WebRecon(args.target).run()
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rep.findings.sort(key=lambda f: order.get(f.severity, 9))
    print("=" * 62)
    print(f"  Paths tested    : {rep.tested}")
    print(f"  Findings        : {len(rep.findings)}")
    print(f"  Allowed methods : {rep.methods_allowed or '-'}")
    print("=" * 62)
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.status}  {f.path}")
        print(f"       {f.detail}")
    if not rep.findings:
        print("  ✅ No exposed sensitive path found.")
    print()


def cmd_inject(args) -> None:
    from modules.offensive.injection_tester import InjectionTester
    print(BANNER)
    print(f">> INJECTION TEST (authorized, non-destructive): {args.target}\n")
    rep = InjectionTester(args.target).run()
    print("=" * 62)
    print(f"  Parameters tested     : {', '.join(rep.params_tested) or '-'}")
    print(f"  Findings              : {len([f for f in rep.findings if f.kind!='INFO'])}")
    print("=" * 62)
    for f in rep.findings:
        print(f"   [{f.severity:<8}] {f.kind:<16} param='{f.param}'")
        print(f"       {f.evidence}")
    print()


def cmd_domain_audit(args) -> None:
    from modules.web.email_security import EmailSecurityAuditor
    from modules.web.tls_analyzer import TLSAnalyzer
    print(BANNER)
    print(f">> DOMAIN SECURITY AUDIT: {args.target}\n")
    tls = TLSAnalyzer(args.target).analyze()
    print("  [TLS]")
    for k, v in tls.info.items():
        print(f"    {k}: {v}")
    for f in tls.findings:
        print(f"    [{f.severity}] {f.detail}")
    email = EmailSecurityAuditor().audit(args.target)
    print("\n  [EMAIL SECURITY]")
    print(f"    SPF   : {email.records.get('spf') or 'YOK'}")
    print(f"    DMARC : {email.records.get('dmarc') or 'YOK'}")
    print(f"    DKIM  : {email.records.get('dkim_selectors') or 'not found'}")
    print(f"    MX    : {', '.join(email.records.get('mx', [])) or '-'}")
    print()
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    allf = sorted(email.findings, key=lambda f: order.get(f.severity, 9))
    for f in allf:
        print(f"    [{f.severity:<7}] {f.check:<7} {f.detail}")
    print()


def cmd_storefront(args) -> None:
    from modules.web.storefront_audit import StorefrontAuditor
    print(BANNER)
    print(f">> STOREFRONT SECURITY & TRUST AUDIT: {args.target}\n")
    rep = StorefrontAuditor(args.target).audit()
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    rep.findings.sort(key=lambda f: order.get(f.severity, 9))
    print("=" * 62)
    print(f"  Hedef        : {rep.target}")
    print(f"  Findings     : {len(rep.findings)}")
    print("=" * 62)
    for f in rep.findings:
        print(f"   [{f.severity:<7}] {f.area:<18} {f.detail}")
    print("\n  Trust pages:")
    for label, ok in rep.trust_pages.items():
        print(f"   {'✅' if ok else '❌'} {label}")
    print()


def cmd_serve(args) -> None:
    from web_api.server import serve
    print(BANNER)
    serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cerberus Saga -- authorized defensive security platform")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="End-to-end demo on a local target").set_defaults(func=cmd_demo)
    sp = sub.add_parser("scan", help="Scan a target from scope.yaml")
    sp.add_argument("target")
    sp.add_argument("--json", action="store_true", help="also print meta output as JSON")
    sp.set_defaults(func=cmd_scan)
    sub.add_parser("verify-audit", help="Verify the audit chain").set_defaults(func=cmd_verify_audit)
    sub.add_parser("scope", help="List the authorization scope").set_defaults(func=cmd_scope)
    ss = sub.add_parser("secret-scan", help="Search a folder for hardcoded secrets/keys")
    ss.add_argument("path", help="Folder to scan (e.g. ~/my-projects)")
    ss.set_defaults(func=cmd_secret_scan)
    sf = sub.add_parser("storefront", help="E-commerce storefront security & trust audit")
    sf.add_argument("target", help="Storefront URL (must be in scope)")
    sf.set_defaults(func=cmd_storefront)
    cs = sub.add_parser("crypto-scan", help="Scan a folder for exchange API keys / seed phrases / wallet keys")
    cs.add_argument("path")
    cs.set_defaults(func=cmd_crypto_scan)
    cp = sub.add_parser("crypto-phish", help="Check domain(s) for fake-exchange (typosquat) lookalikes")
    cp.add_argument("domains", nargs="+")
    cp.set_defaults(func=cmd_crypto_phish)
    da = sub.add_parser("domain-audit", help="TLS certificate + email security (SPF/DMARC/DKIM)")
    da.add_argument("target")
    da.set_defaults(func=cmd_domain_audit)
    rc = sub.add_parser("recon", help="Active web recon (sensitive path/file exposure)")
    rc.add_argument("target")
    rc.set_defaults(func=cmd_recon)
    it = sub.add_parser("inject-test", help="Reflected XSS + error-based SQLi test (non-destructive)")
    it.add_argument("target", help="URL with a parameter, e.g. http://site/x.php?id=1")
    it.set_defaults(func=cmd_inject)
    hv = sub.add_parser("harvest", help="Pull raw data from an authorized target (saves to disk)")
    hv.add_argument("target")
    hv.set_defaults(func=cmd_harvest)
    fp = sub.add_parser("fingerprint", help="Technology/CMS fingerprint + CVE hints")
    fp.add_argument("target")
    fp.set_defaults(func=cmd_fingerprint)
    asmt = sub.add_parser("assess", help="Unified security assessment + grade + snapshot")
    asmt.add_argument("target")
    asmt.set_defaults(func=cmd_assess)
    hist = sub.add_parser("history", help="A target's assessment history + change diff")
    hist.add_argument("target")
    hist.set_defaults(func=cmd_history)
    vo = sub.add_parser("verify-ownership", help="Verify domain ownership (unlocks active scanning)")
    vo.add_argument("domain")
    vo.set_defaults(func=cmd_verify_ownership)
    hd = sub.add_parser("headers", help="Comprehensive security header + cookie audit")
    hd.add_argument("target")
    hd.set_defaults(func=cmd_headers)
    cs = sub.add_parser("csp", help="Deep CSP analysis + clickjacking detection")
    cs.add_argument("target")
    cs.set_defaults(func=cmd_csp)
    jl = sub.add_parser("js-leak", help="Scans for client-side (JS/HTML) secret leaks")
    jl.add_argument("target")
    jl.set_defaults(func=cmd_jsleak)
    hh = sub.add_parser("host-header", help="Host header injection (password-reset poisoning)")
    hh.add_argument("target")
    hh.set_defaults(func=cmd_hosthdr)
    mt = sub.add_parser("http-methods", help="HTTP method abuse (TRACE/PUT/DELETE/XST)")
    mt.add_argument("target")
    mt.set_defaults(func=cmd_methods)
    jw = sub.add_parser("jwt-analyze", help="JWT weakness analysis (alg=none, weak secret, claims)")
    jw.add_argument("token")
    jw.set_defaults(func=cmd_jwt)
    jc = sub.add_parser("js-libs", help="Client-side JS library version + CVE detection")
    jc.add_argument("target")
    jc.set_defaults(func=cmd_jslib)
    gq = sub.add_parser("graphql", help="GraphQL introspection exposure detection")
    gq.add_argument("target")
    gq.set_defaults(func=cmd_graphql)
    tk = sub.add_parser("trackers", help="Third-party tracker / GDPR privacy audit")
    tk.add_argument("target")
    tk.set_defaults(func=cmd_trackers)
    ts = sub.add_parser("tls-scan", help="TLS protocol version scan (legacy/weak version detection)")
    ts.add_argument("target")
    ts.set_defaults(func=cmd_tls_scan)
    dn = sub.add_parser("dns-audit", help="DNS security audit (AXFR/CAA/DNSSEC)")
    dn.add_argument("domain")
    dn.set_defaults(func=cmd_dns_audit)
    sd = sub.add_parser("subdomains", help="Subdomain discovery (DNS recon)")
    sd.add_argument("domain")
    sd.set_defaults(func=cmd_subdomains)
    fz = sub.add_parser("fuzz", help="Parameter fuzz: LFI/SSTI/command-injection (non-destructive)")
    fz.add_argument("target", help="URL with a parameter, e.g. http://site/x.php?page=1")
    fz.set_defaults(func=cmd_fuzz)
    co = sub.add_parser("cors-test", help="CORS misconfiguration test")
    co.add_argument("target")
    co.set_defaults(func=cmd_cors)
    rd = sub.add_parser("redirect-test", help="Open redirect test")
    rd.add_argument("target")
    rd.set_defaults(func=cmd_redirect)
    sv = sub.add_parser("serve", help="Start the web dashboard (opens in browser)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser")
    sv.set_defaults(func=cmd_serve)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
