"""
Cerberus core tests. No network or external binaries required.
Run: pytest -q
"""
import asyncio
from pathlib import Path

import pytest

from core.scope_guard import is_in_scope, assert_in_scope
from core.exceptions import OutOfScopeError
from modules.dlp.pii_spii_scanner import PIISPIIScanner, _luhn_valid, _tc_kimlik_valid
from modules.dlp.financial_scanner import FinancialDataScanner, _iban_mod97_valid
from modules.forensics.integrity_log import AuditLog


# --- Authorization gate -----------------------------------------------------
def test_scope_allows_localhost():
    assert is_in_scope("localhost")
    assert is_in_scope("http://127.0.0.1/login")


def test_scope_blocks_unauthorized():
    assert not is_in_scope("evil-random-target.example")
    with pytest.raises(OutOfScopeError):
        assert_in_scope("https://unauthorized.example/x")


# --- DLP: checksum validators ----------------------------------------------
def test_luhn():
    assert _luhn_valid("4242424242424242")      # valid test card
    assert not _luhn_valid("1234567812345678")


def test_tc_kimlik():
    assert _tc_kimlik_valid("10000000146")       # algorithmically valid
    assert not _tc_kimlik_valid("12345678901")


def test_iban_mod97():
    assert _iban_mod97_valid("TR330006100519786457841326")
    assert not _iban_mod97_valid("TR000000000000000000000000")


# --- DLP: scanning + masking + suppression----------------------------------
def test_dlp_detects_and_masks():
    blob = Path("tests/fixtures/leaky_response.txt").read_text(encoding="utf-8")
    report = PIISPIIScanner().scan_text(blob, "test")
    cats = report.summary()
    assert "TC_KIMLIK_NO" in cats
    assert "AWS_ACCESS_KEY" in cats
    # No finding may contain the raw (unmasked) full value
    for f in report.findings:
        assert "*" in f.match_masked or len(f.match_masked) <= 4


def test_dlp_suppresses_example_context():
    report = PIISPIIScanner().scan_text("example dummy AKIAZZZZZZZZZZZZZZZZ key", "t")
    aws = [f for f in report.findings if f.category == "AWS_ACCESS_KEY"]
    assert aws and aws[0].severity == "INFO"   # 'example/dummy' -> downgraded to INFO


def test_financial_scanner():
    rep = FinancialDataScanner().scan_text("IBAN: TR330006100519786457841326", "t")
    assert any(f.category == "IBAN_INTL" for f in rep.findings)


# --- Audit zinciri -----------------------------------------------------------
def test_audit_chain(tmp_path, monkeypatch):
    import modules.forensics.integrity_log as il
    monkeypatch.setattr(il, "AUDIT_DIR", str(tmp_path))
    log = il.AuditLog("UNITTEST")
    log.record("a", {"x": 1})
    log.record("b", {"y": 2})
    assert log.verify_chain() is True
    # Break the chain -> verification must fail
    p = Path(log.path)
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"x": 1', '"x": 999')
    p.write_text("\n".join(lines) + "\n")
    assert il.AuditLog("UNITTEST").verify_chain() is False


# --- CVE matching (real version logic) ------------------------------------
def test_cve_matcher_fires_only_on_vulnerable_version():
    from modules.vulnerability.cve_matcher import CVEMatcher
    # Vulnerable version -> must produce a finding
    hits = asyncio.run(CVEMatcher().match(["Server: Apache/2.4.49 (Unix)"]))
    assert any(h["template"] == "CVE-2021-41773" for h in hits)
    # Patched/safe version -> must NOT produce a finding (no false positive)
    safe = asyncio.run(CVEMatcher().match(["Server: Apache/2.4.58 (Unix)"]))
    assert not any(h["template"] == "CVE-2021-41773" for h in safe)


def test_cve_matcher_expanded_db():
    from modules.vulnerability.cve_matcher import CVEMatcher
    hits = asyncio.run(CVEMatcher().match(["SSH-2.0-OpenSSH_9.2p1"]))
    assert any(h["template"] == "CVE-2024-6387" for h in hits)  # regreSSHion
    safe = asyncio.run(CVEMatcher().match(["SSH-2.0-OpenSSH_9.8p1"]))
    assert not any(h["template"] == "CVE-2024-6387" for h in safe)


def test_nuclei_absent_does_not_fabricate(monkeypatch):
    import modules.vulnerability.nuclei_runner as nr
    monkeypatch.setattr(nr.shutil, "which", lambda _: None)
    res = asyncio.run(nr.NucleiScanner("localhost").run_templates())
    # Must return a single INFO "engine missing" record, not a fake CVE list
    assert len(res) == 1 and res[0]["severity"] == "INFO"


# --- Crypto exchange/wallet security detection---------------------------------
def test_exchange_guard_detects_fake_secrets():
    from modules.crypto.exchange_guard import ExchangeGuard
    blob = Path("tests/fixtures/crypto_leak.txt").read_text(encoding="utf-8")
    rep = ExchangeGuard().scan_text(blob)
    kinds = {f.kind for f in rep.findings}
    assert "EXCHANGE_API_KEY" in kinds   # binance_api_key context
    assert "SEED_PHRASE" in kinds        # recovery phrase 12 kelime
    assert "WALLET_PRIVATE_KEY" in kinds # 0x + private key context
    # A context-free asset_hash must NOT be flagged as a secret (false-positive test)
    for f in rep.findings:
        assert "8cd477" not in f.masked


def test_exchange_guard_masks_secrets():
    from modules.crypto.exchange_guard import ExchangeGuard
    rep = ExchangeGuard().scan_text("binance api_key = " + "A" * 64)
    assert rep.findings and "*" in rep.findings[0].masked


def test_phishing_domain_typosquat():
    from modules.crypto.exchange_guard import ExchangeGuard
    g = ExchangeGuard()
    assert g.check_phishing_domain("binance.com").severity == "INFO"   # legitimate
    assert g.check_phishing_domain("binnance.com").severity == "HIGH"  # typosquat
    assert g.check_phishing_domain("github.com") is None               # unrelated


# --- Offensive: injection detection (proven with synthetic responses)--------------
def test_injection_detects_sqli_and_xss(monkeypatch):
    import modules.offensive.injection_tester as it
    from modules.offensive._requester import Resp

    def fake_request(url, method="GET", timeout=8, read_bytes=120000):
        # return a DB error for single-quote requests; reflect the XSS marker verbatim
        if "%27" in url or url.endswith("'") or "1'" in url:
            return Resp(200, {}, "You have an error in your SQL syntax; check near ''")
        if it.XSS_MARKER in url or "svg" in url.lower():
            return Resp(200, {}, "result: " + it.XSS_MARKER + " found")
        return Resp(200, {}, "normal page, no error")

    monkeypatch.setattr(it, "request", fake_request)
    rep = it.InjectionTester("http://127.0.0.1/x.php?id=1").run()
    kinds = {f.kind for f in rep.findings}
    assert "SQL_INJECTION" in kinds
    assert "REFLECTED_XSS" in kinds


def test_injection_no_param_is_informational(monkeypatch):
    import modules.offensive.injection_tester as it
    rep = it.InjectionTester("http://127.0.0.1/").run()
    assert rep.findings and rep.findings[0].kind == "INFO"


# --- Offensive: CORS + open redirect (synthetic responses) -------------------
def test_cors_detects_reflected_origin(monkeypatch):
    import modules.offensive.cors_test as ct
    from modules.offensive._requester import Resp
    monkeypatch.setattr(ct, "request", lambda *a, **k: Resp(
        200, {"access-control-allow-origin": ct.EVIL_ORIGIN,
              "access-control-allow-credentials": "true"}, ""))
    rep = ct.CORSTester("http://127.0.0.1/").run()
    assert rep.findings[0].severity == "CRITICAL"


def test_cors_safe(monkeypatch):
    import modules.offensive.cors_test as ct
    from modules.offensive._requester import Resp
    monkeypatch.setattr(ct, "request", lambda *a, **k: Resp(200, {}, ""))
    rep = ct.CORSTester("http://127.0.0.1/").run()
    assert rep.findings[0].severity == "INFO"


def test_open_redirect_detects(monkeypatch):
    import modules.offensive.open_redirect as orr
    from modules.offensive._requester import Resp
    monkeypatch.setattr(orr, "request", lambda *a, **k: Resp(
        302, {"location": "https://cerberus-evil.example/pwn"}, ""))
    rep = orr.OpenRedirectTester("http://127.0.0.1/login").run()
    assert any(f.severity == "MEDIUM" for f in rep.findings)


# --- Offensive: parameter fuzzer (LFI/SSTI/CMDi synthetic proof)-------------
def test_fuzzer_detects_lfi_ssti_cmdi(monkeypatch):
    import modules.offensive.param_fuzzer as pf
    from modules.offensive._requester import Resp

    def fake(url, method="GET", timeout=8, read_bytes=120000, extra_headers=None):
        if "passwd" in url:
            return Resp(200, {}, "root:x:0:0:root:/root:/bin/bash")
        if "7*7" in url or "%7B%7B7*7" in url or "7%2A7" in url:
            return Resp(200, {}, "sonuc cerb49xy tamam")
        if "id" in url and (";" in url or "|" in url or "`" in url or "%3B" in url or "%7C" in url):
            return Resp(200, {}, "uid=33(www-data) gid=33")
        return Resp(200, {}, "normal")

    monkeypatch.setattr(pf, "request", fake)
    rep = pf.ParamFuzzer("http://127.0.0.1/x.php?page=1").run()
    kinds = {f.kind for f in rep.findings}
    assert "LFI" in kinds and "SSTI" in kinds and "CMD_INJECTION" in kinds


def test_fuzzer_no_false_positive_on_clean(monkeypatch):
    import modules.offensive.param_fuzzer as pf
    from modules.offensive._requester import Resp
    monkeypatch.setattr(pf, "request", lambda *a, **k: Resp(200, {}, "temiz sayfa"))
    rep = pf.ParamFuzzer("http://127.0.0.1/x.php?page=1").run()
    assert not [f for f in rep.findings if f.kind != "INFO"]


def test_subdomain_enum_localhost():
    from modules.offensive.subdomain_enum import SubdomainEnum
    rep = SubdomainEnum("localhost").run()
    assert rep.tested > 0  # resolution ran (result may be 0; what matters is that it ran)


# --- Ofansif: JWT analizi ----------------------------------------------------
def _mk_jwt(header: dict, payload: dict, secret: str | None = None):
    import base64, hmac, hashlib, json
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    si = f"{b(header)}.{b(payload)}"
    if secret is None:
        return si + "."
    sig = hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest()
    return si + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def test_jwt_alg_none():
    from modules.offensive.jwt_analyzer import JWTAnalyzer
    tok = _mk_jwt({"alg": "none", "typ": "JWT"}, {"user": "admin"})
    rep = JWTAnalyzer().analyze(tok)
    assert any(f.check == "alg_none" and f.severity == "CRITICAL" for f in rep.findings)


def test_jwt_weak_secret_cracked():
    from modules.offensive.jwt_analyzer import JWTAnalyzer
    tok = _mk_jwt({"alg": "HS256", "typ": "JWT"}, {"user": "x"}, secret="secret")
    rep = JWTAnalyzer().analyze(tok)
    assert rep.cracked_secret == "secret"
    assert any(f.check == "weak_secret" for f in rep.findings)


# --- Offensive: Host header + HTTP methods (synthetic) ------------------------
def test_host_header_reflected(monkeypatch):
    import modules.offensive.host_header as hh
    from modules.offensive._requester import Resp
    monkeypatch.setattr(hh, "request", lambda *a, **k: Resp(
        302, {"location": "https://cerberus-evil.example/reset"}, ""))
    rep = hh.HostHeaderTester("https://127.0.0.1/").run()
    assert any(f.severity == "HIGH" for f in rep.findings)


def test_http_methods_flags_trace(monkeypatch):
    import modules.offensive.http_methods as hm
    from modules.offensive._requester import Resp
    def fake(url, method="GET", **k):
        if method == "OPTIONS":
            return Resp(200, {"allow": "GET, POST, TRACE, PUT"}, "")
        return Resp(200, {}, "")
    monkeypatch.setattr(hm, "request", fake)
    rep = hm.HTTPMethodTester("https://127.0.0.1/").run()
    sevs = {f.severity for f in rep.findings}
    assert "HIGH" in sevs  # TRACE
    assert any("PUT" in f.detail for f in rep.findings)


# --- Offensive: client-side (JS) secret leakage ----------------------------
def test_js_secret_scan_finds_embedded_key(monkeypatch):
    import modules.offensive.js_secret_scan as js
    from modules.offensive._requester import Resp

    def fake(url, method="GET", timeout=8, read_bytes=120000, extra_headers=None):
        if url.endswith("/app.js"):
            return Resp(200, {}, "const k='AKIAIOSFODNN7EXAMPLE';")
        return Resp(200, {}, "<html><script src='/app.js'></script>"
                             "sk_live_51H8xXxXxXxXxXxXxXxXxXxXx</html>")

    monkeypatch.setattr(js, "request", fake)
    rep = js.JSSecretScanner("https://127.0.0.1/").run()
    cats = {f.category for f in rep.findings}
    assert "STRIPE_SECRET_KEY" in cats   # from the home page
    assert "AWS_ACCESS_KEY" in cats       # from app.js
    assert rep.scripts_scanned == 1


# --- Ofansif: CSP analizi ----------------------------------------------------
def test_csp_flags_unsafe_inline_and_clickjacking(monkeypatch):
    import modules.offensive.csp_analyzer as cp
    from modules.offensive._requester import Resp
    monkeypatch.setattr(cp, "request", lambda *a, **k: Resp(
        200, {"content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}, "<html></html>"))
    rep = cp.CSPAnalyzer("https://127.0.0.1/").run()
    details = " ".join(f.detail for f in rep.findings)
    assert "unsafe-inline" in details
    assert any("clickjacking" in f.detail for f in rep.findings)  # no XFO + no frame-ancestors


def test_csp_missing_is_high(monkeypatch):
    import modules.offensive.csp_analyzer as cp
    from modules.offensive._requester import Resp
    monkeypatch.setattr(cp, "request", lambda *a, **k: Resp(200, {}, "<html></html>"))
    rep = cp.CSPAnalyzer("https://127.0.0.1/").run()
    assert any(f.severity == "HIGH" for f in rep.findings)


# --- Offensive: security headers --------------------------------------------
def test_security_headers_flags_missing_hsts(monkeypatch):
    import modules.offensive.security_headers as sh
    from modules.offensive._requester import Resp
    monkeypatch.setattr(sh, "request", lambda *a, **k: Resp(200, {"server": "nginx/1.18.0"}, ""))
    rep = sh.SecurityHeaderAuditor("https://127.0.0.1/").run()
    assert any(f.header == "HSTS" and f.severity == "HIGH" for f in rep.findings)
    assert any("Version disclosure" in f.detail for f in rep.findings)


def test_security_headers_strong(monkeypatch):
    import modules.offensive.security_headers as sh
    from modules.offensive._requester import Resp
    strong = {"strict-transport-security": "max-age=63072000; includeSubDomains; preload",
              "x-content-type-options": "nosniff", "referrer-policy": "strict-origin",
              "permissions-policy": "geolocation=()", "cross-origin-opener-policy": "same-origin",
              "cross-origin-resource-policy": "same-origin"}
    monkeypatch.setattr(sh, "request", lambda *a, **k: Resp(200, strong, ""))
    rep = sh.SecurityHeaderAuditor("https://127.0.0.1/").run()
    assert all(f.severity in ("INFO",) for f in rep.findings)


# --- Offensive: DNS audit (AXFR detection, dig monkeypatch) -----------------
def test_dns_audit_detects_open_axfr(monkeypatch):
    import modules.offensive.dns_audit as da

    def fake_dig(args, timeout=10):
        if "NS" in args:
            return "ns1.example.com.\nns2.example.com.\n"
        if "AXFR" in args:
            return ("example.com.\t3600\tIN\tSOA\tns1 root 1 1 1 1 1\n"
                    "www.example.com.\t3600\tIN\tA\t1.2.3.4\n"
                    "mail.example.com.\t3600\tIN\tA\t1.2.3.5\n"
                    "dev.example.com.\t3600\tIN\tA\t1.2.3.6\n"
                    "vpn.example.com.\t3600\tIN\tA\t1.2.3.7\n")
        return ""

    monkeypatch.setattr(da, "_dig", fake_dig)
    rep = da.DNSAuditor("example.com").run()
    assert any(f.check == "AXFR" and f.severity == "CRITICAL" for f in rep.findings)


# --- Offensive: TLS version evaluation (pure function) ----------------------
def test_tls_scan_flags_old_protocols():
    from modules.offensive.tls_scan import assess_protocols
    weak = assess_protocols({"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True})
    assert any(f.severity == "HIGH" for f in weak)
    good = assess_protocols({"TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True})
    assert all(f.severity == "INFO" for f in good)


# --- Offensive: tracker audit -----------------------------------------------
def test_tracker_audit_detects(monkeypatch):
    import modules.offensive.tracker_audit as ta
    from modules.offensive._requester import Resp
    monkeypatch.setattr(ta, "request", lambda *a, **k: Resp(
        200, {}, "<script src='https://www.googletagmanager.com/gtag/js'></script> fbq('init')"))
    rep = ta.TrackerAuditor("https://127.0.0.1/").run()
    assert "Google Analytics" in rep.trackers and "Meta/Facebook Pixel" in rep.trackers


# --- Ofansif: GraphQL introspection ------------------------------------------
def test_graphql_introspection_open(monkeypatch):
    import modules.offensive.graphql_introspect as gq
    from modules.offensive._requester import Resp
    def fake(url, method="GET", **k):
        if url.endswith("/graphql"):
            return Resp(200, {}, '{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}')
        return Resp(404, {}, "")
    monkeypatch.setattr(gq, "request", fake)
    rep = gq.GraphQLIntrospect("https://127.0.0.1/").run()
    assert "/graphql" in rep.endpoints
    assert any(f["severity"] == "MEDIUM" for f in rep.findings)


# --- Offensive: JS library CVE (pure classify) ------------------------------
def test_js_lib_cve_old_jquery():
    from modules.offensive.js_lib_cve import classify
    libs, finds = classify("<script src='/assets/jquery-3.4.1.min.js'></script>")
    assert any(l["lib"] == "jQuery" for l in libs)
    assert any(f["lib"] == "jQuery" for f in finds)  # <3.5.0 is vulnerable
    _, safe = classify("jquery-3.7.1.min.js")
    assert not any(f["lib"] == "jQuery" for f in safe)  # up to date -> no finding


# --- IAM (offline behaviour) --------------------------------------------------
def test_auth_token_entropy():
    from modules.iam.auth_tester import AuthenticationTester
    weak = asyncio.run(AuthenticationTester().check_session_token_entropy("aaaa1111"))
    assert weak.severity == "HIGH"


def test_cve_matcher_nginx2root_branch_aware():
    """nginx2root (CVE-2026-123007) must flag vulnerable builds but stay quiet
    on the branch-patched 1.30.7 (stable) and 1.31.9 (mainline) releases --
    the branch-aware patch logic, verified end to end."""
    from modules.vulnerability.cve_matcher import CVEMatcher
    m = CVEMatcher()

    def flags(banner):
        hits = asyncio.run(m.match([banner]))
        return any(h["template"] == "CVE-2026-123007" for h in hits)

    # Vulnerable: old mainline, in-range, and pre-patch stable branch
    assert flags("nginx/1.18.0")
    assert flags("nginx/1.25.3")
    assert flags("nginx/1.30.6")     # stable branch, before 1.30.7
    assert flags("nginx/1.31.8")     # mainline, before 1.31.9

    # Patched / out of range -> NO false positive
    assert not flags("nginx/1.30.7")  # stable branch, patched
    assert not flags("nginx/1.31.9")  # mainline, patched
    assert not flags("nginx/1.32.0")  # newer branch
    assert not flags("nginx/1.9.4")   # below the 1.9.5 floor
