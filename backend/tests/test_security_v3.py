"""Guvenlik zafiyet raporu (3) — Z-01..Z-09 icin regresyon testleri. Ag erisimi gerektirmez.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import os
import re
import threading
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core import page_probe
from backend.core.analyzer_interface import (
    InvalidTargetError, analyze_url_pipeline, check_list_match, parse_url_components,
)
from backend.core.brands import catalog, homograph_of, official_brand, owner_brand
from backend.core.netguard import BlockedAddressError, SlowTargetError, TargetBusyError, targets
from backend.core.scoring import collect_signals, score_signals
from backend.core.suffixes import SHORTENERS, is_public_suffix, shared_suffix

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


GARANTI_PAGE = {
    "status": "ok", "title": "Garanti BBVA İnternet Şubesi",
    "identity": ["Garanti BBVA İnternet Şubesi"], "logos": [], "text": "Müşteri girişi",
    "password_input": True, "card_input": True, "tckn_input": True,
    "fields": ["Şifre", "Kart bilgisi", "T.C. kimlik no"],
}


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


# --- Z-01: paylasimli alanlar resmi adres sayilmamali ---------------------------

@pytest.mark.parametrize("raw", [
    "http://garantibbva-giris.blogspot.com/giris",
    "http://isbank-sube.s3.amazonaws.com/giris",
    "http://sube-giris.blob.core.windows.net/giris",
])
def test_z01_retest_shared_hosting_is_not_official_and_scores_critical(raw):
    parsed = parse_url_components(raw)
    score, level, reasons, _ = analyze(raw, page=dict(GARANTI_PAGE, final_host=parsed["domain"]), tls="http_link")
    assert not any("resmi alan adı" in n for n in names(reasons)), names(reasons)
    assert any("kimliği taşıyor" in n for n in names(reasons))
    assert "Hassas bilgi toplayan form" in names(reasons)
    assert score > 75 and level == "CRITICAL"


@pytest.mark.parametrize("host", [
    "garantibbva-giris.blogspot.com", "isbank-sube.s3.amazonaws.com", "kova.s3.eu-west-1.amazonaws.com",
    "sube-giris.blob.core.windows.net", "lh3.googleusercontent.com", "tenant.sharepoint.com",
    "sites.google.com", "docs.google.com", "forms.gle", "t.co", "lnkd.in", "youtu.be", "t.me",
    "cdn.discordapp.com", "steamcommunity.com", "proje.web.app", "x.appspot.com",
])
def test_z01_user_content_hosts_never_official(host):
    assert official_brand(host) is None


@pytest.mark.parametrize("host,brand", [
    ("www.google.com", "google"), ("accounts.google.com", "google"), ("login.windows.net", "microsoft"),
    ("login.microsoftonline.com", "microsoft"), ("www.garanti.com.tr", "garanti"), ("www.amazon.com.tr", "amazon"),
])
def test_z01_real_official_domains_stay_official(host, brand):
    own = official_brand(host)
    assert own and own["id"] == brand


def test_z01_catalog_domains_are_not_shared_suffixes():
    shared = set()
    for brand in catalog()["brands"]:
        for domain in brand["domains"]:
            assert not is_public_suffix(domain), (brand["id"], domain)
            assert not shared_suffix(domain), (brand["id"], domain)
            assert domain not in SHORTENERS, (brand["id"], domain)
            assert domain not in brand["user_content_domains"], (brand["id"], domain)
            shared.add(domain)
    for brand in catalog()["brands"]:
        for domain in brand["user_content_domains"]:
            assert domain not in shared or official_brand(domain) is None, (brand["id"], domain)


@pytest.mark.parametrize("raw", ["https://steamcommunity.com/id/oyuncu", "https://discord.gg/davet",
                                 "https://cdn.discordapp.com/attachments/1/2/a.png", "https://t.me/kanal"])
def test_z01_owner_name_in_own_user_content_domain_is_not_impersonation(raw):
    score, level, reasons, _ = analyze(raw)
    assert not any(n.startswith("Marka taklidi") for n in names(reasons)), names(reasons)
    assert not any("resmi alan adı" in n for n in names(reasons))
    assert score < 25


def test_z01_brand_in_shared_subdomain_label_is_impersonation():
    _, _, reasons, ctx = analyze("https://garantibbva-giris.blogspot.com/")
    assert "Marka taklidi: Garanti BBVA" in names(reasons)
    assert ctx["target_brand"] == "Garanti BBVA"


def test_z01_official_site_hosting_other_brand_form_is_flagged():
    score, level, reasons, _ = analyze("https://www.google.com/", page=dict(GARANTI_PAGE, final_host="www.google.com"))
    assert "Google resmi alan adı" not in names(reasons)
    assert "Sayfa Garanti BBVA kimliği taşıyor" in names(reasons)
    assert score > 75


def test_z01_official_site_with_own_identity_stays_low():
    score, level, reasons, _ = analyze("https://www.garanti.com.tr/giris",
                                       page=dict(GARANTI_PAGE, final_host="www.garanti.com.tr"))
    assert "Garanti BBVA resmi alan adı" in names(reasons)
    assert score < 25


def test_z01_official_site_partner_mention_without_form_stays_low():
    page = dict(GARANTI_PAGE, title="Miles&Smiles ile mil kazanın", identity=["Türk Hava Yolları kampanyası"],
                password_input=False, card_input=False, tckn_input=False, fields=[], final_host="www.garanti.com.tr")
    score, _, reasons, _ = analyze("https://www.garanti.com.tr/kampanya", page=page)
    assert score < 25, names(reasons)


def test_z01_open_redirect_on_official_site_drops_trust():
    page = dict(GARANTI_PAGE, final_host="giris-garanti.xyz")
    score, _, reasons, _ = analyze("https://www.google.com/url?q=https://giris-garanti.xyz", page=page)
    assert "Google resmi alan adı" not in names(reasons)
    assert score > 75


# --- Z-09 (Z-01 ile ayni kural): kisitli uzanti ve kisa baglanti ---------------

def test_z09_compromised_restricted_site_with_other_brand_is_flagged():
    page = dict(GARANTI_PAGE, final_host="okul.k12.tr")
    score, _, reasons, _ = analyze("https://okul.k12.tr/wp-content/giris", page=page)
    assert "Kısıtlı resmi uzantı" not in names(reasons)
    assert score > 75


def test_z09_legit_restricted_site_asking_tckn_keeps_discount():
    page = {"status": "ok", "title": "Belediye e-Hizmet", "identity": ["Belediye e-Hizmet"], "logos": [],
            "text": "", "password_input": True, "card_input": False, "tckn_input": True,
            "fields": ["Şifre", "T.C. kimlik no"], "final_host": "ebelediye.ornek.bel.tr"}
    score, _, reasons, ctx = analyze("https://ebelediye.ornek.bel.tr/giris", page=page)
    # G-07: kisitli uzanti indirimi hassas bilgi isteyen sayfada verilmez; kimligi belirlenemeyen form bulgu
    # degil "Karar verilemedi"dir (dusuk agirlikli not). Sayfa yine "toplayan form" sayilmaz ve skor dusuktur.
    assert "Kısıtlı resmi uzantı" not in names(reasons)
    assert "Kimliği doğrulanamayan giriş formu" in names(reasons) and ctx["unverified_form"]
    assert "Hassas bilgi toplayan form" not in names(reasons)
    assert score < 35


def test_z09_shortener_is_judged_by_final_page():
    page = dict(GARANTI_PAGE, final_host="sube-giris.xyz")
    score, _, reasons, _ = analyze("https://t.co/abc123", page=page)
    assert "Hassas bilgi toplayan form" in names(reasons)
    assert not any("resmi alan adı" in n for n in names(reasons))
    assert score > 75


# --- Z-02: saldirgan verisi analizi sonlandiramaz -------------------------------

PHISH_HTML = (b"<html><head><title>Garanti BBVA Internet Subesi</title></head><body>"
              b"<form action='%s'><input type=password name=sifre><input name=kartno></form></body></html>")


def _fake_fetch(responses):
    calls = []

    def fetch(url, deadline, pinned=None):
        calls.append(url)
        item = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(item, Exception):
            raise item
        status, headers, body = item
        return page_probe._Response(status, headers, body)

    fetch.calls = calls
    return fetch


@pytest.mark.parametrize("ctype,action", [
    ("text/html; charset=undefined", b"/post"),
    ("text/html; charset=idna", b"/post"),
    ("text/html; charset=rot13", b"/post"),
    ("text/html; charset=utf-8", b"http://[x"),
    ("text/html", b"http://[::1"),
])
def test_z02_hostile_page_data_does_not_raise(monkeypatch, ctype, action):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    monkeypatch.setattr(page_probe, "_fetch_once", _fake_fetch([(200, {"content-type": ctype}, PHISH_HTML % action)]))
    page_probe._cache.clear()
    result = page_probe.probe_page("http://saldirgan-z02.com/giris")
    assert result["status"] == "ok"
    assert result["password_input"] and result["card_input"]
    assert "Garanti" in (result["title"] or "")


def test_z02_any_unexpected_probe_error_becomes_error_status(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    monkeypatch.setattr(page_probe, "_fetch_once", _fake_fetch([RuntimeError("beklenmeyen")]))
    page_probe._cache.clear()
    assert page_probe.probe_page("http://saldirgan-z02b.com/")["status"] == "error"


def test_z02_retest_hostile_pages_get_200_high_score_and_record(client, monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    page_probe._cache.clear()
    _mock_network(monkeypatch, page=page_probe.probe_page)
    for ctype, action in [("text/html; charset=undefined", b"/p"), ("text/html", b"http://[x")]:
        monkeypatch.setattr(page_probe, "_fetch_once",
                            _fake_fetch([(200, {"content-type": ctype}, PHISH_HTML % action)]))
        r = client.post("/analyze/url", json={"url": f"http://garanti-sube-{len(ctype)}.com/giris"})
        assert r.status_code == 200, r.text
        assert r.json()["risk_score"] > 75
        assert r.json()["id"] is not None


def test_z02_retest_long_unicode_path_is_recorded(client, monkeypatch):
    from backend.models.database import SessionLocal
    from backend.models.ioc_model import IOCModel, value_digest

    _mock_network(monkeypatch, page={"status": "error"})
    raw = "http://uzun-yol.com/" + "ş" * 2000
    r = client.post("/analyze/url", json={"url": raw})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] is not None
    assert body["url"].isascii() and "%C5%9F" in body["url"]
    db = SessionLocal()
    try:
        record = db.get(IOCModel, body["id"])
        assert record.value == body["url"] and record.value_hash == value_digest(body["url"])
    finally:
        db.close()


def test_z02_persist_failure_still_returns_result(client, monkeypatch):
    import backend.api.routes_analyze as ra

    _mock_network(monkeypatch, page={"status": "error"})
    monkeypatch.setattr(ra, "trim_history", lambda db, ioc_id: (_ for _ in ()).throw(RuntimeError("db")))
    r = client.post("/analyze/url", json={"url": "http://kayit-hatasi.com/"})
    assert r.status_code == 200
    assert r.json()["id"] is None and r.json()["risk_score"] >= 0


def test_z02_uninspected_page_is_a_visible_finding():
    _, _, reasons, _ = analyze("https://incelenemeyen.com/", page={"status": "error"})
    assert "Sayfa içeriği incelenemedi" in names(reasons)
    assert "Bilinen gösterge yok" not in names(reasons)


def test_z02_canonical_path_is_percent_encoded_and_detection_uses_decoded():
    parsed = parse_url_components("https://ornek.com/giriş?ad=şifre#bölüm")
    assert (parsed["rest"]).isascii()
    _, _, reasons, _ = analyze("https://ornek-site.com/%67arantibbva/giris")
    assert any("Garanti" in n for n in names(reasons))


# --- Z-03: genel giris esigi yoneticiyi kilitleyemez ---------------------------

def test_z03_retest_correct_password_after_distributed_failures(client, monkeypatch):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "LOGIN_GLOBAL_DELAY_SECONDS", 0.01)
    current = {"ip": ""}
    monkeypatch.setattr(routes_auth, "client_ip", lambda request: current["ip"])
    for n in range(10):
        current["ip"] = f"198.51.100.{n + 10}"
        for _ in range(5):
            assert login(client, "yanlis-parola-1234567").status_code == 401
    current["ip"] = "203.0.113.50"
    assert login(client).status_code == 200


def test_z03_per_ip_limit_still_applies(client):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert login(client, "yanlis-parola-1234567").status_code == 401
    assert login(client).status_code == 429


def test_z03_totp_second_factor(client, monkeypatch):
    from backend.core import security

    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    monkeypatch.setattr(settings, "ADMIN_TOTP_SECRET", secret)
    monkeypatch.setattr(security, "totp", security.TotpVerifier())
    from backend.api import routes_auth
    monkeypatch.setattr(routes_auth, "totp", security.totp)
    assert login(client).status_code == 401
    assert login(client, otp="000000").status_code == 401
    code = security.totp_code(secret, int(time.time() // 30))
    assert login(client, otp=code).status_code == 200
    assert login(client, otp=code).status_code == 401  # ayni kod ikinci kez kullanilamaz


def test_z03_restrict_admin_to_trusted_networks(client, monkeypatch):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "ADMIN_TRUSTED_NETWORKS", "10.20.0.0/16")
    monkeypatch.setattr(settings, "ADMIN_RESTRICT_TO_TRUSTED", True)
    monkeypatch.setattr(routes_auth, "client_ip", lambda request: "198.51.100.7")
    assert login(client).status_code == 403
    monkeypatch.setattr(routes_auth, "client_ip", lambda request: "10.20.3.4")
    assert login(client).status_code == 200


# --- Z-04: hedef basina sinir ve yavas hedef karantinasi ------------------------

def test_z04_slow_target_is_quarantined_for_any_path(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "93.184.216.34")

    # D-02: hedef ancak sureyi KENDISI tuketirse karantinaya alinir (adima verilen asgari sure kisaltildi)
    monkeypatch.setattr(page_probe, "MIN_HOP_SECONDS", 0.05)

    def slow(parts, host, ip, port, deadline):
        time.sleep(0.06)
        raise page_probe._FetchError("budget exhausted")

    monkeypatch.setattr(page_probe, "_fetch_pinned", slow)
    page_probe._cache.clear()
    # B-04: karantina adrese (ad + ilk yol parcasi) yazilir; ayni adresin her sorgu/alt yolu karantinadadir.
    # Alan adinin tamami ancak bagimsiz istemcilerin farkli adreslerdeki zaman asimlariyla karantinaya alinir.
    from backend.core.netguard import ProbeContext, reset_probe_context, set_probe_context

    for i, path in enumerate(("a1", "a2", "a3")):
        token = set_probe_context(ProbeContext(f"198.51.100.{60 + i}"))
        try:
            assert page_probe.probe_page(f"http://yavas-sunucu.com/{path}?r={i}")["status"] == "error"
        finally:
            reset_probe_context(token)
    monkeypatch.setattr(page_probe, "_fetch_pinned", lambda *a: pytest.fail("karantinadaki hedef yoklanmamali"))
    started = time.monotonic()
    assert page_probe.probe_page("http://yavas-sunucu.com/a1/baska?x=1")["status"] == "slow_target"
    assert page_probe.probe_page("http://yavas-sunucu.com/yeni")["status"] == "slow_target"
    assert page_probe.probe_page("http://alt.yavas-sunucu.com/a4")["status"] == "slow_target"
    assert time.monotonic() - started < 0.5


def test_z04_one_probe_per_target_at_a_time():
    """B-04: tek kilit yerine sinirli sayac; ayni alan adina en fazla TARGET_MAX_CONCURRENT yoklama."""
    from backend.core import netguard

    held = [targets.acquire("hedef.com") for _ in range(netguard.TARGET_MAX_CONCURRENT)]
    try:
        with pytest.raises(TargetBusyError):
            targets.acquire("hedef.com", wait=0.05)
        with targets.acquire("baska-hedef.com", wait=0.05):
            pass
    finally:
        for h in held:
            h.__exit__(None, None, None)
    with targets.acquire("hedef.com", wait=0.05):
        pass


def test_z04_tls_probe_skips_quarantined_target(monkeypatch):
    from backend.core import domain_intel

    targets.mark_slow("yavas-tls.com")
    monkeypatch.setattr(domain_intel, "connect_pinned", lambda *a, **k: pytest.fail("baglanilmamali"))
    assert domain_intel.probe_tls("www.yavas-tls.com", "93.184.216.34") == "unreachable"


def test_z04_shared_slots_increased():
    assert settings.ANALYZE_MAX_CONCURRENT >= 8


# --- Z-05: 'www.' onekiyle ust alan adi kurali ---------------------------------

@pytest.mark.parametrize("pattern", ["www.com.tr", "www.com", "www.github.io", "WWW.Com.Tr", "co.com", "uk.com",
                                     "www.blogspot.com", "sites.google.com", "t.co", "docs.google.com"])
def test_z05_retest_overbroad_patterns_rejected(client, pattern):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "whitelist", "entry_type": "domain", "pattern": pattern})
    assert r.status_code == 422, (pattern, r.text)


def test_z05_stored_pattern_is_the_matched_value(client):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "blacklist", "entry_type": "domain", "pattern": "www.ornek-z05.com.tr"})
    assert r.status_code == 201 and r.json()["pattern"] == "ornek-z05.com.tr"
    client.delete(f"/lists/{r.json()['id']}")


def test_z05_previously_stored_invalid_rules_are_not_applied(client):
    from backend.models.database import SessionLocal
    from backend.models.list_model import ListModel

    db = SessionLocal()
    rule = ListModel(list_type="whitelist", entry_type="domain", pattern="www.com.tr", description="eski kural")
    db.add(rule)
    db.commit()
    try:
        assert check_list_match(db, "garanti-giris.com.tr", "garanti-giris.com.tr/", "whitelist") is None
        assert login(client).status_code == 200
        listed = [i for i in client.get("/lists").json() if i["id"] == rule.id][0]
        assert listed["disabled_reason"]
    finally:
        db.delete(rule)
        db.commit()
        db.close()


def test_z05_parent_whitelist_does_not_cover_user_content():
    from backend.models.database import SessionLocal
    from backend.models.list_model import ListModel

    db = SessionLocal()
    rule = ListModel(list_type="whitelist", entry_type="domain", pattern="google.com")
    db.add(rule)
    db.commit()
    try:
        assert check_list_match(db, "www.google.com", "www.google.com/", "whitelist") is not None
        assert check_list_match(db, "sites.google.com", "sites.google.com/view/x", "whitelist") is None
    finally:
        db.delete(rule)
        db.commit()
        db.close()


# --- Z-06: adres kurallari bilesen bilesen ve sadelestirilerek -----------------

@pytest.fixture()
def url_rules():
    from backend.models.database import SessionLocal
    from backend.models.list_model import ListModel

    db = SessionLocal()
    rules = [ListModel(list_type="whitelist", entry_type="url", pattern="ornek-z06.com/kurumsal"),
             ListModel(list_type="blacklist", entry_type="url", pattern="ornek-z06.com/giris")]
    db.add_all(rules)
    db.commit()
    yield db
    for rule in rules:
        db.delete(rule)
    db.commit()
    db.close()


def _match(db, raw, list_type):
    parsed = parse_url_components(raw)
    return check_list_match(db, parsed["domain"], parsed["authority"] + parsed["rest"], list_type)


def test_z06_retest_dot_segments_do_not_widen_allow_rule(url_rules):
    assert _match(url_rules, "ornek-z06.com/kurumsal/hakkimizda", "whitelist") is not None
    assert _match(url_rules, "ornek-z06.com/kurumsal/../giris", "whitelist") is None
    assert _match(url_rules, "ornek-z06.com/kurumsal/%2e%2e/giris", "whitelist") is None
    assert _match(url_rules, "ornek-z06.com/kurumsal-sahte", "whitelist") is None
    assert _match(url_rules, "ornek-z06.com/Kurumsal", "whitelist") is None


@pytest.mark.parametrize("raw", ["ornek-z06.com/giris?a=1", "ornek-z06.com/%67iris", "ornek-z06.com//giris",
                                 "ornek-z06.com/GIRIS", "ornek-z06.com/x/../giris#y", "https://www.ornek-z06.com/giris/"])
def test_z06_retest_block_rule_cannot_be_evaded(url_rules, raw, monkeypatch):
    assert _match(url_rules, raw, "blacklist") is not None
    result = analyze_url_pipeline(raw, db=url_rules)
    assert result["risk_score"] == 100


def test_z06_canonical_url_resolves_dot_segments_like_browsers():
    assert parse_url_components("https://a.com/x/./y/../z")["rest"] == "/x/z"
    assert parse_url_components("https://a.com/x/..")["rest"] == "/"


# --- Z-07: ic ag adlarinin varligi yanittan anlasilmamali -----------------------

def test_z07_retest_single_label_names_same_response(client):
    responses = [client.post("/analyze/url", json={"url": u}) for u in
                 ("http://db/", "http://vault/", "http://yok-boyle-bir-ad/", "http://jenkins.sirket.local/",
                  "http://app.internal/")]
    assert {r.status_code for r in responses} == {400}
    assert len({r.json()["detail"] for r in responses}) == 1


def test_z07_name_resolving_internally_looks_unresolved(monkeypatch):
    import backend.core.analyzer_interface as ai

    _mock_network(monkeypatch, page=lambda u: pytest.fail("ic ada baglanilmamali"))

    def internal(d):
        raise BlockedAddressError(d)

    monkeypatch.setattr(ai, "resolve_ip", internal)
    hidden = analyze_url_pipeline("http://jenkins.sirket.com.tr/")
    monkeypatch.setattr(ai, "resolve_ip", lambda d: None)
    missing = analyze_url_pipeline("http://jenkins.sirket.com.tr/")
    assert names(hidden["reasons"]) == names(missing["reasons"])
    assert hidden["ioc_details"]["ip_address"] is None


def test_z07_ip_literals_still_rejected_explicitly():
    with pytest.raises(InvalidTargetError):
        analyze_url_pipeline("http://10.0.0.5/")


# --- Z-08: CI is akisi ve araclari sabitli --------------------------------------

def test_z08_workflow_tools_are_pinned():
    text = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    uses = [step["uses"] for job in workflow["jobs"].values() for step in job["steps"] if "uses" in step]
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses
    trivy = re.search(r"TRIVY_IMAGE:\s*(\S+)", text).group(1)
    assert "@sha256:" in trivy
    assert "docker.sock" not in text
    assert "requirements-dev.txt" in text and "pip install pytest" not in text


def test_z08_dev_lock_has_hashes():
    lock = (ROOT / "backend/requirements-dev.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==", lock, flags=re.M)
    assert {"pytest", "pip-audit", "httpx"} <= {p.lower() for p in pins}
    assert lock.count("--hash=sha256:") >= len(pins)


def test_z08_backend_image_drops_packaging_tools():
    dockerfile = (ROOT / "backend/Dockerfile").read_text(encoding="utf-8")
    assert "pip uninstall -y setuptools wheel" in dockerfile


def test_z08_risk_acceptances_expire():
    data = yaml.safe_load((ROOT / ".trivyignore.yaml").read_text(encoding="utf-8"))
    for entry in data["vulnerabilities"]:
        assert entry.get("expired_at") and entry.get("statement"), entry


# --- Z-09: ek gozlemler ---------------------------------------------------------

@pytest.mark.parametrize("raw,brand", [
    ("http://iոg.com.tr/giris", "ING Türkiye"),     # Ermeni 'ո'
    ("http://hsƅc.com/giris", "HSBC Türkiye"),      # Latin 'ƅ'
    ("http://ziraatbanꝁ.com.tr/", "Ziraat Bankası"),  # tabloda olmayan harf: genel denetim
])
def test_z09_homograph_beyond_table(raw, brand):
    score, level, reasons, ctx = analyze(raw)
    assert any(n.startswith("Benzer harfle resmi adres taklidi") for n in names(reasons)), names(reasons)
    assert ctx["target_brand"] == brand
    assert level == "CRITICAL"


def test_z09_punycode_prefix_is_not_counted_as_hyphens():
    _, _, reasons, _ = analyze("http://şeker.com/")
    assert "Çok sayıda tire" not in names(reasons)


def test_z09_meta_refresh_is_followed(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    fetch = _fake_fetch([
        (200, {"content-type": "text/html"},
         b"<html><head><meta http-equiv='refresh' content='0; url=https://hedef-z09.com/giris'></head></html>"),
        (200, {"content-type": "text/html"}, PHISH_HTML % b"/post"),
    ])
    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    result = page_probe.probe_page("http://ara-sayfa-z09.com/")
    assert result["status"] == "ok" and result["final_host"] == "hedef-z09.com"
    assert result["password_input"]
    assert fetch.calls == ["http://ara-sayfa-z09.com/", "https://hedef-z09.com/giris"]


def test_z09_script_redirect_interstitial_is_reported(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    html = b"<html><body><script>window.location.href='https://garanti-sube-giris.xyz/'</script></body></html>"
    monkeypatch.setattr(page_probe, "_fetch_once", _fake_fetch([(200, {"content-type": "text/html"}, html)]))
    page_probe._cache.clear()
    page = page_probe.probe_page("http://ara-js-z09.com/")
    assert page["script_redirect_host"] == "garanti-sube-giris.xyz"
    _, _, reasons, _ = analyze("http://ara-js-z09.com/", page=page)
    assert "İzlenemeyen yönlendirme" in names(reasons)
    assert any("Garanti" in n for n in names(reasons))


def test_z09_proxy_and_db_containers_hardened():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for name in ("proxy", "db"):
        service = compose["services"][name]
        assert service.get("read_only") is True, name
        assert service.get("cap_drop") == ["ALL"], name
    assert compose["services"]["proxy"]["cap_add"] == ["NET_BIND_SERVICE"]


def test_z09_total_ioc_rows_capped(monkeypatch):
    from backend.core import retention
    from backend.models.database import SessionLocal
    from backend.models.ioc_model import IOCModel

    db = SessionLocal()
    try:
        before = db.query(IOCModel).count()
        for i in range(5):
            db.add(IOCModel(type="url", value=f"https://satir-siniri-{i}.com", risk_score=0, risk_level="LOW"))
        db.commit()
        monkeypatch.setattr(settings, "IOC_MAX_ROWS", before + 2)
        retention.enforce_row_cap(db)
        assert db.query(IOCModel).count() == before + 2
    finally:
        db.query(IOCModel).filter(IOCModel.value.like("https://satir-siniri-%")).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_z09_unused_unguarded_dns_module_removed():
    assert not (ROOT / "backend/core/typosquat.py").exists()


def test_z01_platform_registration_age_is_not_inherited():
    score, _, reasons, _ = analyze("https://garantibbva-giris.blogspot.com/giris", age=9000)
    assert "Köklü alan adı" not in names(reasons)
    assert "Marka taklidi: Garanti BBVA" in names(reasons)
    assert score >= 75
