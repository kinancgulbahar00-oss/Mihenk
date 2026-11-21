"""Guvenlik zafiyet raporu (4) — D-01..D-06 icin regresyon testleri. Ag erisimi gerektirmez.

Her bulgu icin raporun "Yeniden test" olcutu, laboratuvar yerine sahte ag katmaniyla sinanir.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import inspect
import logging
import os
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core import netguard, page_probe
from backend.core.analyzer_interface import analyze_url_pipeline, check_list_match, parse_url_components
from backend.core.brands import catalog, owner_brand
from backend.core.netguard import ProbeContext, TargetBusyError, current_probe_context, targets
from backend.core.scoring import collect_signals, score_signals

PASSWORD = os.environ["ADMIN_PASSWORD"]
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def client():
    from backend.main import app
    from backend.api import routes_auth, routes_analyze

    routes_auth._login_failures._events.clear()
    routes_auth._login_global._events.clear()
    routes_analyze._rate_limiter._events.clear()
    with TestClient(app) as c:
        yield c


def login(client, password=PASSWORD, **extra):
    return client.post("/admin/login", json={"password": password, **extra})


def analyze(raw, page=None, age=None, tls=None):
    parsed = parse_url_components(raw)
    url = f"{parsed['scheme'] or 'https'}://{parsed['authority']}{parsed['rest']}"
    if page is not None and "final_host" not in page:
        page = dict(page, final_host=parsed["domain"])
    signals, mitigations, context = collect_signals(
        {**parsed, "url": url}, {"resolved": True, "page": page or {}, "age_days": age, "tls": tls})
    score, level, reasons = score_signals(signals, mitigations)
    return score, level, reasons, context


def names(reasons):
    return [r["rule_name"] for r in reasons]


def _mock_network(monkeypatch, page=None, ip="93.184.216.34"):
    import backend.core.analyzer_interface as ai

    monkeypatch.setattr(ai, "resolve_ip", lambda d: ip)
    monkeypatch.setattr(ai, "lookup_domain_registration",
                        lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "none")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation",
                        lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    if page is not None:
        monkeypatch.setattr(ai, "probe_page", page if callable(page) else (lambda u: dict(page)))


def _fake_fetch(responses):
    calls = []

    def fetch(url, deadline, pinned=None):
        calls.append(url)
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item()
        status, headers, body = item
        return page_probe._Response(status, headers, body)

    fetch.calls = calls
    return fetch


# --- D-01: tarayicinin yok saydigi yonlendirme etiketi --------------------------

BANK_REFRESH = b"<meta http-equiv='refresh' content='0; url=https://www.garantibbva.com.tr/'>"
PHISH_PAGE = (b"<html><head><title>Garanti BBVA Internet Subesi</title>%s</head><body>"
              b"<h1>Garanti BBVA</h1><form action='/post'><input name=tckn placeholder='T.C. kimlik no'>"
              b"<input type=password name=sifre><input name=kartno></form></body></html>")
BANK_PAGE = (b"<html><head><title>Garanti BBVA | Bireysel</title></head><body><h1>Garanti BBVA</h1>"
             b"<p>Hos geldiniz</p></body></html>")

IGNORED_BY_BROWSERS = {
    "yorum": b"<!-- " + BANK_REFRESH + b" -->",
    "noscript": b"<noscript>" + BANK_REFRESH + b"</noscript>",
    "textarea": b"<textarea style='display:none'>" + BANK_REFRESH + b"</textarea>",
    "template": b"<template>" + BANK_REFRESH + b"</template>",
    "betik": b"<script>var s = \"" + BANK_REFRESH.replace(b"'", b"\\'") + b"\";</script>",
    "iframe": b"<iframe>" + BANK_REFRESH + b"</iframe>",
    # B-02 (a): <svg> icindeki <meta> tarayicida yabanci icerikten cikarilip ISLENIR; bu cesit artik
    # izlenir (test_security_v5.py). D-01 korumasi yine gecerlidir: ilk sayfanin bulgulari sonucta kalir.
    "textarea-kendinden-kapanan": b"<textarea/>" + BANK_REFRESH + b"</textarea>",
}


@pytest.mark.parametrize("variant", sorted(IGNORED_BY_BROWSERS))
def test_d01_refresh_tag_ignored_by_browsers_is_not_followed(monkeypatch, variant):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    fetch = _fake_fetch([(200, {"content-type": "text/html"}, PHISH_PAGE % IGNORED_BY_BROWSERS[variant]),
                         (200, {"content-type": "text/html"}, BANK_PAGE)])
    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    page = page_probe.probe_page(f"http://saldirgan-d01.com/{variant}")
    assert fetch.calls == [f"http://saldirgan-d01.com/{variant}"], fetch.calls
    assert page["final_host"] == "saldirgan-d01.com"
    assert "Şifre" in page["fields"] and "Kart bilgisi" in page["fields"]


@pytest.mark.parametrize("variant", ["yorum", "noscript", "textarea"])
def test_d01_retest_three_variants_score_above_75_with_identity_and_form(client, monkeypatch, variant):
    """Yeniden test: /yorum, /noscript, /textarea analiz edildiginde kurum kimligi ve form bulgu
    olarak raporlanmali ve skor 75'in uzerinde olmali."""
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    page_probe._cache.clear()
    _mock_network(monkeypatch, page=page_probe.probe_page)
    monkeypatch.setattr(page_probe, "_fetch_once", _fake_fetch([
        (200, {"content-type": "text/html"}, PHISH_PAGE % IGNORED_BY_BROWSERS[variant]),
        (200, {"content-type": "text/html"}, BANK_PAGE)]))
    r = client.post("/analyze/url", json={"url": f"http://saldirgan-d01.com/{variant}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["risk_score"] > 75, (body["risk_score"], names(body["reasons"]))
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(body["reasons"]))
    assert any("Hassas bilgi toplayan form" in n for n in names(body["reasons"]))
    assert body["ioc_details"]["final_url"] is None


def test_d01_real_refresh_keeps_findings_of_the_redirecting_page(monkeypatch):
    """Tarayicinin GERCEKTEN izledigi yonlendirme (ornegin </html> sonrasinda) izlenir; ancak ara
    sayfanin formu ve kurum kimligi sonucta kalir."""
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    html = PHISH_PAGE % b"" + b"</html>" + BANK_REFRESH
    fetch = _fake_fetch([(200, {"content-type": "text/html"}, html),
                         (200, {"content-type": "text/html"}, BANK_PAGE)])
    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    page = page_probe.probe_page("http://saldirgan-d01b.com/giris")
    assert fetch.calls == ["http://saldirgan-d01b.com/giris", "https://www.garantibbva.com.tr/"]
    assert page["final_host"] == "www.garantibbva.com.tr"
    assert page["steps"] and page["steps"][0]["final_host"] == "saldirgan-d01b.com"
    assert "Şifre" in page["steps"][0]["fields"]

    score, level, reasons, ctx = analyze("http://saldirgan-d01b.com/giris", page=page)
    assert score > 75 and level == "CRITICAL", (score, names(reasons))
    assert any(n.startswith("Yönlendirmeden önceki sayfa: Sayfa Garanti BBVA kimliği") for n in names(reasons))
    assert "Bilgi isteyen sayfa başka adrese yönlendiriyor" in names(reasons)
    assert ctx["target_brand"] == "Garanti BBVA"
    redirect = next(r for r in reasons if r["rule_name"] == "Başka alan adına yönlendirme")
    assert "ilk adresin içeriği ayrıca incelendi" in redirect["description"]


def test_d01_findings_of_redirecting_page_survive_a_failing_next_hop(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    html = PHISH_PAGE % b"<meta http-equiv=refresh content='1;url=https://hedef-yok-d01.com/'>"
    monkeypatch.setattr(page_probe, "_fetch_once", _fake_fetch([
        (200, {"content-type": "text/html"}, html), page_probe._FetchError("unresolved")]))
    page_probe._cache.clear()
    page = page_probe.probe_page("http://saldirgan-d01c.com/")
    assert page["status"] == "error" and page["steps"]
    score, _, reasons, _ = analyze("http://saldirgan-d01c.com/", page=page)
    assert score > 75, names(reasons)


def test_d01_plain_interstitial_still_followed():
    html = "<html><head><meta http-equiv=Refresh content=\"0;URL='https://hedef.com/x'\"></head></html>"
    assert page_probe._meta_refresh_target(html) == "https://hedef.com/x"
    assert page_probe._meta_refresh_target("<!-- <meta http-equiv=refresh content='0;url=/a'> -->") is None
    # A-01: gecikmeli yonlendirme de izlenir (60 saniyeye kadar); daha uzunu izlenmez ama kapsami dusurur
    assert page_probe._meta_refresh_target("<meta http-equiv=refresh content='30;url=/a'>") == "/a"
    assert page_probe._meta_refresh_target("<meta http-equiv=refresh content='300;url=/a'>") is None


def test_d01_same_signal_from_two_documents_is_not_double_counted(monkeypatch):
    page = {"status": "ok", "final_host": "saldirgan-d01d.com", "title": "Garanti BBVA",
            "identity": ["Garanti BBVA"], "logos": [], "text": "", "password_input": True,
            "fields": ["Şifre"], "steps": [{"final_host": "saldirgan-d01d.com", "identity": ["Garanti BBVA"],
                                            "logos": [], "text": "", "password_input": True, "fields": ["Şifre"]}]}
    _, _, reasons, _ = analyze("http://saldirgan-d01d.com/", page=page)
    assert sum(1 for n in names(reasons) if "kimliği taşıyor" in n) == 1


# --- D-02: yavas yonlendirme zinciriyle baska bir alan adini karantinaya aldirma ---

def test_d02_slow_first_hop_does_not_quarantine_redirect_target(monkeypatch):
    """Saldirganin sunucusu butcenin cogunu harcayip sites.google.com'a yonlendirir: google.com
    karantinaya ALINMAMALI; yavasligin kaynagi (saldirganin alan adi) suclanmali."""
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    monkeypatch.setattr(page_probe, "MIN_HOP_SECONDS", 0.2)

    def slow_redirect():
        time.sleep(0.5)
        return 302, {"location": "https://sites.google.com/view/kurban"}, b""

    fetch = _fake_fetch([slow_redirect, (200, {"content-type": "text/html"}, BANK_PAGE)])
    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    token = netguard.set_probe_context(ProbeContext("198.51.100.20", page_budget=0.6))
    try:
        result = page_probe.probe_page("http://yavas-d02.com/r")
    finally:
        netguard.reset_probe_context(token)
    assert result["status"] == "error"
    assert fetch.calls == ["http://yavas-d02.com/r"], "kalan sure esigin altindayken adim baslatilmamali"
    assert not targets.is_slow("google.com", scope="sites.google.com/view")
    # B-04: karantina sureyi tuketen ADRESE yazilir
    assert targets.is_slow("yavas-d02.com", scope="yavas-d02.com/r")


def test_d02_short_hop_timeout_does_not_quarantine(monkeypatch):
    """Kendisine MIN_HOP_SECONDS verilmemis bir adimin zaman asimi hedefi suclamaz."""
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "142.250.1.1")

    def exhausted(parts, host, ip, port, deadline):
        raise page_probe._FetchError("budget exhausted")

    monkeypatch.setattr(page_probe, "_fetch_pinned", exhausted)
    with pytest.raises(page_probe._FetchError):
        page_probe._fetch_once("https://sites.google.com/view/x", time.monotonic() + 0.3)
    assert not targets.is_slow("google.com")


def test_d02_catalog_target_needs_two_independent_timeouts_and_short_quarantine():
    assert not targets.record_timeout("google.com", client="198.51.100.1", protected=True)
    assert not targets.record_timeout("google.com", client="198.51.100.1", protected=True)
    assert not targets.is_slow("google.com")
    assert targets.record_timeout("google.com", client="198.51.100.2", protected=True)
    assert targets.is_slow("google.com")
    assert targets._slow["google.com"] - time.monotonic() <= netguard.PROTECTED_SLOW_TARGET_SECONDS


def test_d02_catalog_domains_are_protected():
    for host in ("sites.google.com", "docs.google.com", "www.garantibbva.com.tr", "google.com"):
        assert page_probe.is_protected_target(host), host
    for host in ("x.duckdns.org", "saldirgan.com", "93.184.216.34"):
        assert not page_probe.is_protected_target(host), host


def test_d02_retest_uninspected_user_content_page_is_not_low_risk():
    _, level, reasons, _ = analyze("https://sites.google.com/view/kurban-d02",
                                   page={"status": "slow_target"})
    assert "Sayfa içeriği incelenemedi (kullanıcı içeriği)" in names(reasons)
    assert level != "LOW"


def test_d02_tls_short_budget_does_not_quarantine(monkeypatch):
    from backend.core import domain_intel

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def slow_connect(ip, port, timeout):
        time.sleep(0.3)
        raise OSError("timeout")

    monkeypatch.setattr(domain_intel, "connect_pinned", slow_connect)
    token = netguard.set_probe_context(ProbeContext("198.51.100.30", tls_budget=0.1))
    try:
        assert domain_intel.probe_tls("www.google.com", "142.250.1.1") == "unreachable"
    finally:
        netguard.reset_probe_context(token)
    assert not targets.is_slow("google.com")


# --- D-03: sinirsiz ucretsiz alt alan adi ----------------------------------------

def test_d03_concurrent_probes_per_ip_are_capped():
    ip = "45.155.99.10"
    held = [targets.acquire(f"a{i}.duckdns.org", ip=ip, wait=0.05) for i in range(netguard.IP_MAX_CONCURRENT)]
    try:
        with pytest.raises(TargetBusyError):
            targets.acquire("baska.duckdns.org", ip=ip, wait=0.05)
        with targets.acquire("hizli-site.com", ip="93.184.216.34", wait=0.05):
            pass
    finally:
        for h in held:
            h.__exit__(None, None, None)
    with targets.acquire("baska.duckdns.org", ip=ip, wait=0.05):
        pass


def test_d03_timeouts_of_distinct_names_quarantine_the_address():
    """B-05 ile degisti: IP karantinaya alinmaz, kisitlanir. Kisitli IP'deki adlar beklemeden ve kisa
    butceyle yoklanir; IP sinirinin doldugu anda yeni ad beklemeden vazgecer (D-03 korumasi)."""
    ip = "45.155.99.11"
    for i in range(netguard.IP_SLOW_DISTINCT_NAMES):
        targets.record_timeout(f"rnd{i}.duckdns.org", ip=ip, client=f"198.51.100.{i}")
    assert targets.ip_degraded(ip)
    assert not targets.is_slow("yeni-ad.duckdns.org", ip)
    held = [targets.acquire(f"x{i}.duckdns.org", ip=ip, wait=0.0) for i in range(netguard.IP_MAX_CONCURRENT)]
    try:
        started = time.monotonic()
        with pytest.raises(TargetBusyError):
            targets.acquire("yeni-ad.duckdns.org", ip=ip, wait=0.0)
        assert time.monotonic() - started < 0.1
    finally:
        for h in held:
            h.__exit__(None, None, None)


def test_d03_client_that_causes_timeouts_gets_short_budget(monkeypatch):
    from backend.api import routes_analyze

    def pipeline(raw_url, db=None):
        ctx = current_probe_context()
        assert ctx is not None and ctx.client == "198.51.100.40"
        ctx.record_timeout(raw_url)
        return {}

    monkeypatch.setattr(routes_analyze, "analyze_url_pipeline", pipeline)
    assert targets.budget_for("198.51.100.40").page_budget == netguard.PAGE_BUDGET_SECONDS
    routes_analyze._pipeline_job("a1.duckdns.org", "198.51.100.40")
    routes_analyze._pipeline_job("a2.duckdns.org", "198.51.100.40")
    budget = targets.budget_for("198.51.100.40")
    assert budget.page_budget == netguard.PENALTY_BUDGET_SECONDS and budget.reason == "client_penalty"
    # Diger istemciler etkilenmez
    assert targets.budget_for("198.51.100.41").page_budget == netguard.PAGE_BUDGET_SECONDS


def test_d03_load_shortens_budget():
    assert targets.budget_for("198.51.100.50", load=0.9).page_budget == netguard.LOADED_PAGE_BUDGET_SECONDS
    assert targets.budget_for("198.51.100.50", load=0.1).page_budget == netguard.PAGE_BUDGET_SECONDS


def test_d03_probe_context_reaches_pipeline_threads(monkeypatch):
    seen = {}

    def page(url):
        seen["page"] = current_probe_context()
        return {"status": "error"}

    def tls(domain, ip):
        seen["tls"] = current_probe_context()
        return "none"

    _mock_network(monkeypatch, page=page)
    import backend.core.analyzer_interface as ai

    monkeypatch.setattr(ai, "probe_tls", tls)
    ctx = ProbeContext("198.51.100.60", page_budget=3.0)
    token = netguard.set_probe_context(ctx)
    try:
        analyze_url_pipeline("http://baglam-d03.com/")
    finally:
        netguard.reset_probe_context(token)
    assert seen["page"] is ctx and seen["tls"] is ctx


def test_d03_page_probe_uses_context_budget(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    deadlines = []

    def fetch(url, deadline, pinned=None):
        deadlines.append(deadline - time.monotonic())
        return page_probe._Response(200, {"content-type": "text/html"}, BANK_PAGE)

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    token = netguard.set_probe_context(ProbeContext("198.51.100.61", page_budget=3.0))
    try:
        page_probe.probe_page("http://butce-d03.com/")
    finally:
        netguard.reset_probe_context(token)
    assert deadlines and deadlines[0] <= 3.0


def test_d06_analyze_endpoint_does_not_hold_worker_threads():
    """Yuva beklemesi ve analiz suresi boyunca ortak is parcacigi havuzundan is parcacigi tutulmaz."""
    from backend.api.routes_analyze import analyze_url_endpoint

    assert inspect.iscoroutinefunction(analyze_url_endpoint)


def test_d03_endpoint_returns_503_when_slots_stay_full(client, monkeypatch):
    from backend.api import routes_analyze

    monkeypatch.setattr(routes_analyze, "SLOT_WAIT_SECONDS", 0.3)
    monkeypatch.setattr(routes_analyze, "_try_acquire_slot", lambda: False)
    r = client.post("/analyze/url", json={"url": "http://dolu-d03.com/"})
    assert r.status_code == 503
    # Istemci yuvasi birakilmis olmali: bir sonraki istek 429 "onceki analiz" almaz
    monkeypatch.setattr(routes_analyze, "_try_acquire_slot", lambda: False)
    assert client.post("/analyze/url", json={"url": "http://dolu-d03.com/"}).status_code == 503


# --- D-04: .env ayarlari Compose kurulumunda arka uca ulasmali --------------------

def _compose_backend():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]["backend"]


def _env_example_keys():
    keys = []
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.append(line.split("=", 1)[0].strip())
    return keys


def test_d04_every_env_example_key_reaches_the_backend():
    backend = _compose_backend()
    env_files = backend.get("env_file")
    env_files = [env_files] if isinstance(env_files, (str, dict)) else (env_files or [])
    paths = [e["path"] if isinstance(e, dict) else e for e in env_files]
    explicit = set((backend.get("environment") or {}).keys())
    delivered_by_env_file = ".env" in [p[2:] if p.startswith("./") else p for p in paths]
    missing = [k for k in _env_example_keys() if not delivered_by_env_file and k not in explicit]
    assert not missing, f"Compose bu ayarlari arka uca ulastirmiyor: {missing}"
    for key in ("ADMIN_TOTP_SECRET", "ADMIN_TRUSTED_NETWORKS", "ADMIN_RESTRICT_TO_TRUSTED", "LOGIN_MAX_FAILURES"):
        assert key in _env_example_keys()


def test_d04_compose_environment_only_holds_generated_or_pinned_values():
    explicit = set((_compose_backend().get("environment") or {}).keys())
    assert explicit <= {"DATABASE_URL", "COOKIE_SECURE", "FORWARDED_ALLOW_IPS"}, explicit


def test_d04_every_settings_field_is_documented_in_env_example():
    from backend.config import Settings

    internal = {"PROJECT_NAME", "VERSION", "API_V1_STR", "IOC_MAX_ROWS"}
    undocumented = set(Settings.model_fields) - set(_env_example_keys()) - internal
    assert not undocumented, undocumented


def test_d04_security_state_is_logged_at_startup(monkeypatch, caplog):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "ADMIN_TOTP_SECRET", "")
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)
    with caplog.at_level(logging.INFO, logger="mihenk.auth"):
        routes_auth.configure_security()
    text = caplog.text
    assert "security state second_factor=off" in text
    assert "SECURITY WARNING second factor is OFF" in text


def test_d04_admin_panel_shows_actual_security_state(client, monkeypatch):
    assert login(client).status_code == 200
    stats = client.get("/admin/stats").json()
    assert stats["second_factor_enabled"] is False
    assert stats["login_max_failures"] == settings.LOGIN_MAX_FAILURES
    assert "restrict_to_trusted" in stats and "trusted_networks" in stats


def test_d04_retest_settings_from_env_are_enforced(client, monkeypatch):
    """Ayar arka uca ulastiginda (env_file) uygulanir: kod olmadan giris 401, aralik disindan 403."""
    from backend.api import routes_auth
    from backend.core import security

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    monkeypatch.setattr(settings, "ADMIN_TOTP_SECRET", secret)
    monkeypatch.setattr(security, "totp", security.TotpVerifier())
    monkeypatch.setattr(routes_auth, "totp", security.totp)
    assert login(client).status_code == 401
    monkeypatch.setattr(settings, "ADMIN_TRUSTED_NETWORKS", "10.20.0.0/16")
    monkeypatch.setattr(settings, "ADMIN_RESTRICT_TO_TRUSTED", True)
    monkeypatch.setattr(routes_auth, "client_ip", lambda request: "198.51.100.7")
    assert login(client, otp=security.totp_code(secret, int(time.time() // 30))).status_code == 403


# --- D-05: adres kurallarinda iki kalan durum ------------------------------------

@pytest.fixture()
def blacklist_rule():
    from backend.models.database import SessionLocal
    from backend.models.list_model import ListModel

    db = SessionLocal()
    rule = ListModel(list_type="blacklist", entry_type="url", pattern="kotu-site-v06.com/giris")
    db.add(rule)
    db.commit()
    yield db
    db.delete(rule)
    db.commit()
    db.close()


@pytest.mark.parametrize("raw", [
    "http://a:b@kotu-site-v06.com/giris",
    "http://x@kotu-site-v06.com/giris",
    "https://kullanici:parola@KOTU-SITE-V06.com//giris?x=1",
])
def test_d05_retest_userinfo_does_not_bypass_url_blacklist(blacklist_rule, raw):
    result = analyze_url_pipeline(raw, db=blacklist_rule)
    assert result["risk_score"] == 100 and result["risk_level"] == "CRITICAL", raw
    parsed = parse_url_components(raw)
    assert check_list_match(blacklist_rule, parsed["domain"], parsed["authority"] + parsed["rest"],
                            "blacklist") is not None


@pytest.mark.parametrize("pattern", ["sites.google.com", "sites.google.com/", "https://docs.google.com/?x=1",
                                     "t.co", "www.sites.google.com", "blogspot.com"])
def test_d05_retest_pathless_url_rule_on_user_content_host_rejected(client, pattern):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "whitelist", "entry_type": "url", "pattern": pattern})
    assert r.status_code == 422, (pattern, r.text)


@pytest.mark.parametrize("pattern", ["sites.google.com/view/sirket-d05", "sirket-d05.blogspot.com"])
def test_d05_specific_user_content_url_rules_still_allowed(client, pattern):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "whitelist", "entry_type": "url", "pattern": pattern})
    assert r.status_code == 201, r.text
    client.delete(f"/lists/{r.json()['id']}")


# --- D-06: ek gozlemler ----------------------------------------------------------

def test_d06_registration_lookup_cached_by_registered_domain(monkeypatch):
    from backend.core import domain_intel

    calls = []
    monkeypatch.setattr(domain_intel, "_rdap_lookup",
                        lambda d: calls.append(d) or {"registration_date": "2001-01-01", "age_days": 9000,
                                                      "registrar": "x", "source": "rdap"})
    monkeypatch.setattr(domain_intel, "_whois_lookup", lambda d: pytest.fail("WHOIS'e gerek yok"))
    domain_intel._cache.clear()
    for i in range(5):
        domain_intel.lookup_domain_registration(f"rnd{i}-d06.duckdns.org")
    domain_intel.lookup_domain_registration("sube.garanti-d06.com.tr")
    domain_intel.lookup_domain_registration("www.garanti-d06.com.tr")
    assert calls == ["duckdns.org", "garanti-d06.com.tr"]


def test_d06_registration_lookup_sends_at_most_two_queries_per_new_name(monkeypatch):
    from backend.core import domain_intel

    rdap, whois = [], []
    monkeypatch.setattr(domain_intel, "_rdap_lookup", lambda d: rdap.append(d))
    monkeypatch.setattr(domain_intel, "_whois_lookup", lambda d: whois.append(d))
    domain_intel._cache.clear()
    domain_intel.lookup_domain_registration("a.b.c.yeni-d06.com")
    assert len(rdap) <= 1 and len(whois) <= 1


def test_d06_catalog_ownership_google_subdomains():
    for host in ("sites.google.com", "docs.google.com", "google.com", "drive.google.com"):
        assert owner_brand(host)["id"] == "google", host
    assert owner_brand("youtube.com")["id"] == "youtube"


# Kardes markalar (alt marka, ana kurulusun adresini ikincil adres olarak listeler). Bir adres
# birden fazla kurumda gecebilir, ancak sahibi TEKTIR: adresi birincil (ilk) olarak listeleyen kurum.
_SISTER_BRAND_DOMAINS = {
    "enpara.com", "saglik.gov.tr", "izmir.bel.tr", "trendyol.com", "dolap.com", "amazon.com.tr",
    "youtube.com", "facebook.com",
}


def test_d06_one_domain_one_owner():
    claims = {}
    for brand in catalog()["brands"]:
        for rank, d in enumerate(brand["domains"] + brand["user_content_domains"]):
            claims.setdefault(d, []).append((rank, brand["id"]))
    shared = {d for d, c in claims.items() if len({b for _, b in c}) > 1}
    assert shared <= _SISTER_BRAND_DOMAINS, sorted(shared - _SISTER_BRAND_DOMAINS)
    assert "google.com" not in shared
    for d in shared:
        primary = [b for rank, b in claims[d] if rank == 0]
        if primary:
            assert len(primary) == 1, (d, primary)
            assert owner_brand(d)["id"] == primary[0], d


def test_d06_tests_and_dev_requirements_not_in_image():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "backend/tests" in ignored
    assert "backend/requirements-dev.txt" in ignored


def test_d06_compose_uses_public_resolver_by_default():
    dns = _compose_backend().get("dns")
    assert dns and all("1.1.1.1" in d or "9.9.9.9" in d for d in dns)


def test_d06_totp_clock_skew_does_not_lock_out_next_login():
    from backend.core.security import TotpVerifier, totp_code

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    v = TotpVerifier()
    now = 1_800_000_000.0
    step = int(now // 30)
    # Saati ileride olan dogrulayici: bir sonraki adimin kodu kabul edilir
    assert v.verify(secret, totp_code(secret, step + 1), now=now)
    # Ayni kod tekrar kullanilamaz
    assert not v.verify(secret, totp_code(secret, step + 1), now=now)
    # Saati dogru olan dogrulayicinin kodu, ayni dakika icinde reddedilmez
    assert v.verify(secret, totp_code(secret, step), now=now + 5)
    assert not v.verify(secret, totp_code(secret, step), now=now + 6)
