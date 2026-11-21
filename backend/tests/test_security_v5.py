"""Guvenlik zafiyet raporu (5) — B-01..B-11 icin regresyon testleri. Ag erisimi gerektirmez.

Her bulgu icin raporun "Yeniden test" olcutu, laboratuvar yerine sahte ag katmaniyla sinanir.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core import netguard, page_probe
from backend.core.analyzer_interface import analyze_url_pipeline, parse_url_components
from backend.core.brands import catalog, normalize_text, official_brand, owner_brand
from backend.core.netguard import ProbeContext, SlowTargetError, TargetBusyError, targets
from backend.core.scoring import collect_signals, score_signals

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


@pytest.fixture(autouse=True)
def _page_fetch(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_FETCH_ENABLED", True)
    page_probe._cache.clear()
    yield
    page_probe._cache.clear()


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


def _probe(monkeypatch, url, responses):
    fetch = _fake_fetch(responses)
    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    return page_probe.probe_page(url), fetch


FORM = ("<form action='/post'><input name=tckn placeholder='T.C. kimlik no'>"
        "<input type=password name=sifre><input name=kartno></form>")
GARANTI = ("<html><head><title>Garanti BBVA İnternet Şubesi</title></head><body><h1>Garanti BBVA</h1>"
           + FORM + "</body></html>")
HTML_UTF8 = {"content-type": "text/html; charset=utf-8"}


# --- B-01: icerik turu ve kodlama farklari ---------------------------------------------

B01_VARIANTS = {
    # (1) Content-Type yok, govdede '<html' yok (<html> HTML'de istege baglidir)
    "baslik-yok": ({}, ("<!doctype html><head><title>Garanti BBVA İnternet Şubesi</title></head><body>"
                        "<h1>Garanti BBVA</h1>" + FORM + "</body>").encode("utf-8")),
    # (2) application/xml + XHTML ad alani
    "xhtml": ({"content-type": "application/xml"}, (
        "<?xml version='1.0' encoding='UTF-8'?><html xmlns='http://www.w3.org/1999/xhtml'><head>"
        "<title>Garanti BBVA İnternet Şubesi</title><script src='/a.js'/></head><body><h1>Garanti BBVA</h1>"
        "<form action='/post'><input name='tckn'/><input type='password' name='sifre'/><input name='kartno'/>"
        "</form></body></html>").encode("utf-8")),
    # (3) UTF-16 (BOM); baslik UTF-8 dese de tarayici BOM'a uyar
    "utf16": (HTML_UTF8, b"\xff\xfe" + GARANTI.encode("utf-16-le")),
    # (4) image/svg+xml icinde <foreignObject> ile HTML form
    "svg": ({"content-type": "image/svg+xml"}, (
        "<svg xmlns='http://www.w3.org/2000/svg' width='800' height='600'><title>logo</title>"
        "<foreignObject width='800' height='600'><html xmlns='http://www.w3.org/1999/xhtml'><head>"
        "<title>Garanti BBVA İnternet Şubesi</title></head><body><h1>Garanti BBVA</h1>"
        "<form action='/post'><input name='tckn'/><input type='password' name='sifre'/><input name='kartno'/>"
        "</form></body></html></foreignObject></svg>").encode("utf-8")),
    # (5) windows-1254, kodlama yalnizca <meta charset> ile
    "cp1254": ({"content-type": "text/html"}, (
        "<html><head><meta charset='windows-1254'><title>İş Bankası İnternet Şubesi</title></head><body>"
        "<h1>İşCep</h1>" + FORM + "</body></html>").encode("cp1254")),
    # (6) kurum adi gorunmez karakterle bolunmus
    "u200b": (HTML_UTF8, GARANTI.replace("Garanti BBVA", "Gar​anti BB​VA").encode("utf-8")),
}


@pytest.mark.parametrize("variant", sorted(B01_VARIANTS))
def test_b01_retest_each_variant_scores_like_the_plain_page(monkeypatch, variant):
    """Yeniden test: alti cesit olagan sayfayla ayni duzeyde (75 uzeri) puan almali; brifingde kurum
    kimligi ve form bulgulari yer almali."""
    headers, body = B01_VARIANTS[variant]
    page, _ = _probe(monkeypatch, f"http://zeytin-dali.com/{variant}", [(200, headers, body)])
    assert page["status"] == "ok", page
    assert {"Şifre", "Kart bilgisi", "T.C. kimlik no"} <= set(page["fields"]), page["fields"]
    score, level, reasons, ctx = analyze(f"http://zeytin-dali.com/{variant}", page=page, tls="http_link")
    assert score > 75 and level == "CRITICAL", (variant, score, names(reasons))
    assert any("kimliği taşıyor" in n for n in names(reasons)), names(reasons)
    assert "Hassas bilgi toplayan form" in names(reasons)
    assert ctx["target_brand"] in ("Garanti BBVA", "Türkiye İş Bankası")


def test_b01_windows1254_title_is_decoded():
    _, body = B01_VARIANTS["cp1254"]
    html = page_probe._decode_html(body, None)
    assert "İş Bankası İnternet Şubesi" in html


def test_b01_invisible_characters_are_stripped_and_reported(monkeypatch):
    assert normalize_text("Gar​anti BB⁠VA­") == "garanti bbva"
    headers, body = B01_VARIANTS["u200b"]
    page, _ = _probe(monkeypatch, "http://nar-cicegi.com/c5", [(200, headers, body)])
    assert page["hidden_chars"] and page["title"] == "Garanti BBVA İnternet Şubesi"
    _, _, reasons, _ = analyze("http://nar-cicegi.com/c5", page=page)
    assert "Kurum adı gizlenerek yazılmış" in names(reasons)


@pytest.mark.parametrize("headers,body", [
    ({"content-type": "application/octet-stream"}, bytes(range(256)) * 20),
    ({}, b"\x00\x01\x02\x03binary\xff\xfe\xfd"),
    ({"content-type": "image/png"}, b"\x89PNG\r\n\x1a\n" + b"\x00" * 100),
])
def test_b01_retest_non_html_response_is_reported_as_uninspected(monkeypatch, headers, body):
    """Yeniden test: HTML olmayan yanit (rastgele ikili veri) "incelenemedi" bulgusu uretmeli."""
    page, _ = _probe(monkeypatch, "http://rastgele-ikili.com/x", [(200, headers, body)])
    assert page["status"] == "not_html"
    _, _, reasons, _ = analyze("http://rastgele-ikili.com/x", page=page)
    assert "Sayfa içeriği incelenemedi" in names(reasons)
    from backend.core.analyzer_interface import inspection_coverage

    assert inspection_coverage(page) == "partial"


def test_b01_empty_response_is_reported(monkeypatch):
    page, _ = _probe(monkeypatch, "http://bos-sayfa.com/", [(200, {"content-type": "text/html"}, b"   ")])
    assert page["status"] == "empty"
    assert "Sayfa içeriği incelenemedi" in names(analyze("http://bos-sayfa.com/", page=page)[2])


def test_b01_charset_priority_bom_then_header_then_meta():
    assert page_probe._detect_encoding(b"\xef\xbb\xbfabc", "windows-1254")[0] == "utf-8"
    assert page_probe._detect_encoding(b"<meta charset=utf-8>", "iso-8859-9")[0] == "cp1254"
    assert page_probe._detect_encoding(b"<meta http-equiv='Content-Type' content='text/html; charset=windows-1254'>",
                                       None)[0] == "cp1254"
    # BOM'suz bayt akisinda <meta charset=utf-16> tarayicida UTF-8'dir
    assert page_probe._detect_encoding(b"<meta charset=utf-16>", None)[0] == "utf-8"
    # Bilinmeyen etiket yok sayilir
    assert page_probe._detect_encoding(b"<meta charset=rot13>abc", "undefined")[0] == "utf-8"


# --- B-02: izlenmeyen yonlendirmeler ve betikle uretilen icerik ---------------------------

TARGET = "http://hedef-z09.com/giris"
B02_FOLLOWED = {
    "refresh-basligi": ({"content-type": "text/html", "refresh": f"0; url={TARGET}"},
                        b"<html><head><title>Bekleyin</title></head><body></body></html>"),
    "svg-meta": (HTML_UTF8, f"<html><body><svg><meta http-equiv='refresh' content='0;url={TARGET}'></svg>"
                            f"</body></html>".encode()),
    "yinelenen-oznitelik": (HTML_UTF8, f"<html><head><meta http-equiv='refresh' http-equiv='x' "
                                       f"content='0;url={TARGET}'></head></html>".encode()),
    "bosluk-ayirici": (HTML_UTF8, f"<html><head><meta http-equiv='refresh' content='0 url={TARGET}'>"
                                  f"</head></html>".encode()),
    "bos-yorum": (HTML_UTF8, f"<html><head><!--><meta http-equiv='refresh' content='0;url={TARGET}'>"
                             f"<!-- --></head></html>".encode()),
}
TARGET_PAGE = (200, HTML_UTF8, GARANTI.encode("utf-8"))


@pytest.mark.parametrize("variant", sorted(B02_FOLLOWED))
def test_b02_retest_interstitials_are_followed_and_score_like_target(monkeypatch, variant):
    """Yeniden test: (1)-(5) numarali ara sayfalar izlenmeli ve hedef sayfayla ayni duzeyde puan almali."""
    headers, body = B02_FOLLOWED[variant]
    url = f"http://yildiz-optik.com/{variant}"
    page, fetch = _probe(monkeypatch, url, [(200, headers, body), TARGET_PAGE])
    assert fetch.calls == [url, TARGET], fetch.calls
    assert page["status"] == "ok" and page["final_host"] == "hedef-z09.com"
    score, level, reasons, _ = analyze(url, page=page, tls="http_link")
    target_score, *_ = analyze(TARGET, page=page_probe.probe_page(TARGET), tls="http_link")
    assert score > 75 and level == "CRITICAL", (score, names(reasons))
    assert score >= target_score - 5
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(reasons))


B02_SCRIPT = {
    # (6) gizlenmis betikle yonlendirme
    "gizli-betik": b"<html><head><script>window['loc'+'ation']['hr'+'ef']=atob('aHR0cDovL2hlZGVm');</script>"
                   b"</head><body></body></html>",
    # (7) sayfanin tamami betikle uretiliyor
    "document-write": b"<html><head><title>Y\xc3\xbckleniyor</title></head><body>"
                      b"<script>document.write(atob('PGgxPkdhcmFudGk8L2gxPg=='))</script></body></html>",
}


@pytest.mark.parametrize("variant", sorted(B02_SCRIPT))
def test_b02_retest_script_generated_pages_are_not_low_risk(monkeypatch, variant):
    """Yeniden test: (6) ve (7) "incelenemedi / betige bagli icerik" bulgusu uretmeli ve 25'in altinda kalmamali."""
    url = f"http://pinar-terzi.com/{variant}"
    page, _ = _probe(monkeypatch, url, [(200, HTML_UTF8, B02_SCRIPT[variant])])
    assert page["status"] == "ok" and page["script_rendered"]
    for tls in (None, "http_link"):
        score, level, reasons, _ = analyze(url, page=page, tls=tls)
        assert "Sayfa içeriği betikle üretiliyor; incelenemedi" in names(reasons)
        assert score >= 25 and level != "LOW", (score, names(reasons))
    from backend.core.analyzer_interface import inspection_coverage

    assert inspection_coverage(page) == "partial"


def test_b02_refresh_parser_follows_whatwg_rules():
    p = page_probe._parse_refresh
    assert p("0; url=https://a.com/x") == (0, "https://a.com/x")
    assert p("0 url=https://a.com/x") == (0, "https://a.com/x")
    assert p("0,https://a.com/x") == (0, "https://a.com/x")
    assert p("3;URL='https://a.com/x'") == (3, "https://a.com/x")
    assert p("1.5; url=\"/y\" trailing") == (1, "/y")
    assert p("0") == (0, None)
    assert p("abc") is None
    assert page_probe._refresh_target("300; url=/a") is None


def test_b02_plain_page_with_scripts_and_text_is_not_script_rendered(monkeypatch):
    body = ("<html><head><title>Fırın</title><script src=/a.js></script></head><body><p>"
            + "Ekmek ve pasta çeşitlerimiz. " * 20 + "</p></body></html>").encode()
    page, _ = _probe(monkeypatch, "http://mesru-firin.com/", [(200, HTML_UTF8, body)])
    assert not page["script_rendered"]


# --- B-03: yarim birakilan istekler ------------------------------------------------------

def test_b03_rate_limit_is_enforced_before_the_body_is_read(monkeypatch):
    """Hiz siniri asildiginda govde HIC okunmadan 429 doner."""
    from backend.api import routes_analyze

    routes_analyze._rate_limiter._events.clear()
    monkeypatch.setattr(routes_analyze._rate_limiter, "hit", lambda ip: 30)
    mw = routes_analyze.AnalyzeRateLimitMiddleware(lambda *a: pytest.fail("uygulamaya ulasmamali"))
    sent = []

    async def receive():
        pytest.fail("govde okunmamali")

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/analyze/url", "client": ("198.51.100.90", 1234),
             "headers": []}
    asyncio.run(mw(scope, receive, send))
    assert sent[0]["status"] == 429
    assert (b"retry-after", b"30") in sent[0]["headers"]


def test_b03_incomplete_body_times_out(monkeypatch):
    from backend.core.body_limit import BodySizeLimitMiddleware

    async def app(scope, receive, send):
        try:
            await receive()
            await receive()
        except Exception as exc:  # HTTPException(408)
            await send({"type": "http.response.start", "status": getattr(exc, "status_code", 500), "headers": []})
            await send({"type": "http.response.body", "body": b""})

    mw = BodySizeLimitMiddleware(app, max_bytes=4000, read_timeout=0.2)
    calls = {"n": 0}

    async def receive():
        calls["n"] += 1
        if calls["n"] == 1:
            return {"type": "http.request", "body": b"{\"url\"", "more_body": True}
        await asyncio.sleep(5)

    sent = []

    async def send(message):
        sent.append(message)

    started = time.monotonic()
    asyncio.run(mw({"type": "http", "headers": [(b"content-length", b"4000")]}, receive, send))
    assert sent[0]["status"] == 408 and time.monotonic() - started < 2


def test_b03_proxy_and_app_server_have_timeouts_and_limits():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    for token in ("read_header", "read_body", "write", "idle", "max_header_size"):
        assert token in caddy, token
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "--limit-concurrency" in dockerfile and "--timeout-keep-alive" in dockerfile
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for name in ("backend", "proxy"):
        svc = compose["services"][name]
        assert "healthcheck" in svc, name
        assert svc.get("logging", {}).get("options", {}).get("max-size"), name


# --- B-04: hedef kilidi ve karantina alan adi duzeyinde -----------------------------------

def test_b04_retest_slow_platform_address_does_not_block_other_pages():
    """Uc saldirgan istemci platformdaki yavas adresi tutarken baska kullanicinin sekiz analizi incelenebilmeli."""
    held = [targets.acquire("google.com", ip="45.155.99.20", protected=True, scope="script.google.com/macros",
                            wait=0.05) for _ in range(3)]
    try:
        ok = 0
        for i in range(8):
            with targets.acquire("google.com", ip="45.155.99.20", protected=True,
                                 scope=f"sites.google.com/view{i}", wait=0.05):
                ok += 1
        assert ok == 8
    finally:
        for h in held:
            h.__exit__(None, None, None)


def test_b04_retest_slow_address_on_unlisted_platform_does_not_quarantine_the_domain(monkeypatch):
    """Katalog disi platformda yavas adresin analizinden sonra ayni alan adindaki baska sayfa incelenebilmeli."""
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "45.155.99.21")
    monkeypatch.setattr(page_probe, "MIN_HOP_SECONDS", 0.05)

    def pinned(parts, host, ip, port, deadline):
        if parts.path.startswith("/ipfs"):
            time.sleep(0.06)
            raise page_probe._FetchError("budget exhausted")
        return page_probe._Response(200, HTML_UTF8, GARANTI.encode())

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    token = netguard.set_probe_context(ProbeContext("198.51.100.70"))
    try:
        assert page_probe.probe_page("http://not-paylas.net/ipfs/bekleyen")["status"] == "error"
    finally:
        netguard.reset_probe_context(token)
    page = page_probe.probe_page("http://not-paylas.net/n/oltalama")
    assert page["status"] == "ok"
    assert analyze("http://not-paylas.net/n/oltalama", page=page)[0] > 75
    # Ayni yavas adres karantinada kalir
    assert page_probe.probe_page("http://not-paylas.net/ipfs/baska")["status"] == "slow_target"


def test_b04_domain_quarantine_needs_independent_clients_and_no_recent_success():
    for i in range(3):
        targets.record_timeout("yavas-tek.com", client=f"198.51.100.{i}", scope=f"yavas-tek.com/p{i}")
    assert targets.is_slow("yavas-tek.com")
    # Basariyla yanit veren baska adres varken alan adinin tamami kapatilmaz
    targets.record_success("platform-b04.net", scope="platform-b04.net/x")
    for i in range(3):
        targets.record_timeout("platform-b04.net", client=f"198.51.100.{10 + i}", scope=f"platform-b04.net/p{i}")
    assert not targets.is_slow("platform-b04.net")
    # Katalogdaki kurumlarin alan adi hicbir zaman tumuyle karantinaya alinmaz
    for i in range(4):
        targets.record_timeout("google.com", client=f"198.51.100.{20 + i}", protected=True,
                               scope=f"script.google.com/m{i}")
    assert not targets.is_slow("google.com")


def test_b04_same_address_is_probed_once_and_result_shared(monkeypatch):
    calls = []
    gate = threading.Event()

    def fetch(url, deadline, pinned=None):
        calls.append(url)
        gate.wait(2)
        return page_probe._Response(200, HTML_UTF8, GARANTI.encode())

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    results = []
    threads = [threading.Thread(target=lambda: results.append(page_probe.probe_page("http://ortak-b04.com/a")))
               for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.2)
    gate.set()
    for t in threads:
        t.join(5)
    # A-08: sonucu en fazla MAX_SHARED_WAITERS istek bekler; fazlasi yuva tutmadan vazgecer
    assert len(calls) == 1 and len(results) == 4
    assert sum(r["status"] == "ok" for r in results) == 1 + page_probe.MAX_SHARED_WAITERS
    assert sum(r["status"] == "target_busy" for r in results) == 1


def test_b04_client_with_repeated_long_probes_gets_short_budget(monkeypatch):
    from backend.api import routes_analyze

    def pipeline(raw_url, db=None):
        netguard.current_probe_context().record_slow("script.google.com/macros")
        return {}

    monkeypatch.setattr(routes_analyze, "analyze_url_pipeline", pipeline)
    for _ in range(netguard.CLIENT_SLOW_PROBES):
        routes_analyze._pipeline_job("x", "198.51.100.80")
    budget = targets.budget_for("198.51.100.80")
    assert budget.reason == "client_slow_probes" and budget.page_budget == netguard.PENALTY_BUDGET_SECONDS
    assert targets.budget_for("198.51.100.81").reason == "default"


# --- B-05: IP karantinasi -----------------------------------------------------------------

def test_b05_retest_sites_on_shared_ip_stay_inspectable(monkeypatch):
    """Uc istekten sonra ayni IP'deki siteler yine incelenebilmeli ve onceki puanlarini almali."""
    ip = "45.155.99.30"
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: ip)
    for i, name in enumerate(("a1-yavas.com", "a2-yavas.com", "a3-yavas.com")):
        targets.record_timeout(name, ip=ip, client=f"198.51.100.{100 + i % 2}", scope=f"{name}/")
    assert targets.ip_degraded(ip)

    pages = {
        "mesru-firin-kardesler.com": b"<html><head><title>Kardesler Firini</title></head><body><p>" +
                                     b"Taze ekmek her sabah. " * 30 + b"</p></body></html>",
        "kampanya-hediye-cekilis.com": GARANTI.encode(),
    }

    def pinned(parts, host, ip_, port, deadline):
        assert deadline - time.monotonic() <= netguard.DEGRADED_PAGE_BUDGET_SECONDS + 0.1
        return page_probe._Response(200, HTML_UTF8, pages[host])

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    legit = page_probe.probe_page("http://mesru-firin-kardesler.com/")
    phish = page_probe.probe_page("http://kampanya-hediye-cekilis.com/")
    assert legit["status"] == "ok" and phish["status"] == "ok"
    assert analyze("http://mesru-firin-kardesler.com/", page=legit)[0] < 25
    assert analyze("http://kampanya-hediye-cekilis.com/", page=phish)[0] > 75


def test_b05_catalog_addresses_are_not_degraded(monkeypatch):
    ip = "45.155.99.31"
    for i in range(3):
        targets.record_timeout(f"n{i}.com", ip=ip, client="198.51.100.110", scope=f"n{i}.com/")
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: ip)
    seen = {}

    def pinned(parts, host, ip_, port, deadline):
        seen["budget"] = deadline - time.monotonic()
        return page_probe._Response(200, HTML_UTF8, b"<html><title>Garanti BBVA</title></html>")

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    assert page_probe.probe_page("https://www.garantibbva.com.tr/")["status"] == "ok"
    assert seen["budget"] > netguard.DEGRADED_PAGE_BUDGET_SECONDS + 1


# --- B-06: resmi alan adlari altindaki kullanici icerigi ----------------------------------

LURE = ("<html><head><title>Garanti BBVA - Hesap Bildirimi</title></head><body><h1>Hesabınız kısıtlandı</h1>"
        "<p>İşlemlerinize devam etmek için kimliğinizi doğrulayın.</p>"
        "<a href='https://garanti-dogrulama.example/k'>Kimliğimi doğrula</a></body></html>")
B06_ADDRESSES = (
    "http://lookerstudio.google.com/reporting/9f3a-11",
    "http://groups.google.com/g/duyuru/c/abc",
    "http://paypal.me/odeme9f3a",
    "http://www.facebook.com/notes/9f3a",
    "http://www.linkedin.com/pulse/9f3a",
    "http://www.dropbox.com/scl/fi/9f3a/belge.html",
    "http://acrobat.adobe.com/id/urn:aaid:sc:9f3a",
)


@pytest.mark.parametrize("url", B06_ADDRESSES)
def test_b06_retest_user_content_under_official_domains_is_not_official(monkeypatch, url):
    """Yeniden test: yedi adres "resmi alan adi" indirimi almamali; Garanti BBVA kimligi bulgu olmali (skor >= 50)."""
    page, _ = _probe(monkeypatch, url, [(200, HTML_UTF8, LURE.encode())])
    host = parse_url_components(url)["domain"]
    assert official_brand(host) is None and owner_brand(host) is not None
    score, _, reasons, _ = analyze(url, page=page, age=9000)
    assert not any("resmi alan adı" in n for n in names(reasons)), names(reasons)
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(reasons)), names(reasons)
    assert score >= 50, (score, names(reasons))


def test_b06_listed_trusted_hosts_keep_official_status():
    for host in ("accounts.google.com", "www.google.com", "login.microsoftonline.com", "www.paypal.com",
                 "www.garantibbva.com.tr", "fonts.gstatic.com"):
        assert official_brand(host) is not None, host


def test_b06_known_open_redirect_target_is_reported():
    score, _, reasons, ctx = analyze("https://www.google.com/url?q=https://garantibbva-giris.xyz/k", age=9000)
    assert "Bilinen açık yönlendirme" in names(reasons)
    assert not any("resmi alan adı" in n for n in names(reasons))
    assert ctx["target_brand"] == "Garanti BBVA" and score >= 50


# --- B-07: katalogda kayitli olmayan resmi adres ------------------------------------------

def test_b07_retest_unregistered_catalog_name_gets_no_official_discount():
    assert official_brand("cepte-sok.com") is None
    assert official_brand("ceptesok.com") is not None
    page = {"status": "ok", "title": "Cepte Şok - Üyelik ve Kart Doğrulama",
            "identity": ["Cepte Şok - Üyelik ve Kart Doğrulama"], "logos": [], "text": "",
            "password_input": True, "card_input": True, "tckn_input": True,
            "fields": ["Şifre", "Kart bilgisi", "T.C. kimlik no"]}
    score, _, reasons, _ = analyze("http://cepte-sok.com/uyelik/dogrula", page=page)
    assert not any("resmi alan adı" in n for n in names(reasons))
    assert score > 75, (score, names(reasons))


def test_b07_unverified_names_removed_from_catalog():
    removed = {"cepte-sok.com", "araskargo.com", "ckuludag.com.tr", "dergilik.com.tr", "fastpay.com.tr",
               "garantibbvafiloleasing.com.tr", "hgs.com.tr", "sendeo.com.tr", "trumore.com", "istanbul.istanbul"}
    domains = {d for b in catalog()["brands"] for d in b["domains"]}
    assert not removed & domains


def test_b07_recently_registered_official_domain_loses_trust():
    page = {"status": "ok", "title": "Garanti BBVA", "identity": ["Garanti BBVA"], "logos": [], "text": "",
            "password_input": True, "card_input": True, "fields": ["Şifre", "Kart bilgisi"]}
    score, _, reasons, _ = analyze("https://garantibbva.com.tr/giris", page=page, age=12)
    assert any("yakın zamanda kaydedilmiş" in n for n in names(reasons))
    assert not any("resmi alan adı" in n for n in names(reasons))
    assert score >= 50
    # Koklu resmi adres etkilenmez
    assert analyze("https://garantibbva.com.tr/giris", page=page, age=9000)[0] < 25


def test_b07_catalog_health_tool_exists():
    tool = ROOT / "backend" / "tools" / "catalog_health.py"
    assert tool.is_file()
    text = tool.read_text(encoding="utf-8")
    assert "rdap" in text.lower() and "getaddrinfo" in text


# --- B-08: anonim yeniden analiz kayitli karari dusurmemeli -------------------------------

def test_b08_retest_reanalysis_cannot_erase_critical_verdict(monkeypatch):
    from backend.api import routes_analyze
    from backend.models.database import SessionLocal, init_db
    from backend.models.ioc_model import AnalysisResultModel, IOCModel

    init_db()
    monkeypatch.setattr(settings, "MAX_RESULTS_PER_IOC", 20)
    url = "http://kayit-b08.example/giris"

    def result(score, level):
        return {"url": url, "risk_score": score, "risk_level": level,
                "reasons": [{"rule_name": level, "description": "x", "severity": "high", "contribution": score}],
                "ioc_details": {"domain": "kayit-b08.example"}, "mitre_techniques": [], "related_domains": []}

    db = SessionLocal()
    try:
        first = routes_analyze._persist(result(89, "CRITICAL"), db)
        for _ in range(22):
            routes_analyze._persist(result(32, "MEDIUM"), db)
        ioc = db.query(IOCModel).filter(IOCModel.id == first.id).one()
        assert ioc.risk_level == "CRITICAL" and ioc.risk_score == 89
        assert ioc.last_risk_level == "MEDIUM" and ioc.last_risk_score == 32
        rows = db.query(AnalysisResultModel).filter(AnalysisResultModel.ioc_id == ioc.id).all()
        assert any(r.risk_level == "CRITICAL" for r in rows)
        assert len(rows) <= settings.MAX_RESULTS_PER_IOC + 2
        # Analistin liste karari dogrudan uygulanir
        routes_analyze._persist(dict(result(0, "SAFE"), ioc_details={"domain": "kayit-b08.example",
                                                                     "abuse_status": "whitelisted"}), db)
        db.refresh(ioc)
        assert ioc.risk_level == "SAFE"
        db.delete(ioc)
        db.commit()
    finally:
        db.close()


def test_b08_row_cap_removes_low_risk_records_first(monkeypatch):
    from backend.core import retention
    from backend.models.database import SessionLocal, init_db
    from backend.models.ioc_model import IOCModel

    init_db()
    db = SessionLocal()
    try:
        db.query(IOCModel).delete()
        db.commit()
        critical = IOCModel(type="url", value="https://kritik-b08.example/", risk_score=95, risk_level="CRITICAL")
        db.add(critical)
        db.flush()
        for i in range(5):
            db.add(IOCModel(type="url", value=f"https://dusuk-b08-{i}.example/", risk_score=5, risk_level="LOW"))
        db.commit()
        monkeypatch.setattr(settings, "IOC_MAX_ROWS", 3)
        retention.enforce_row_cap(db)
        assert db.query(IOCModel).filter(IOCModel.value == "https://kritik-b08.example/").count() == 1
        assert db.query(IOCModel).count() == 3
        db.query(IOCModel).delete()
        db.commit()
    finally:
        db.close()


# --- B-09: IP turundeki liste kurallari --------------------------------------------------

@pytest.fixture()
def ip_rule():
    from backend.models.database import SessionLocal, init_db
    from backend.models.list_model import ListModel

    init_db()
    db = SessionLocal()
    rule = ListModel(list_type="blacklist", entry_type="ip", pattern="45.155.99.10", description="b09")
    db.add(rule)
    db.commit()
    yield db
    db.delete(rule)
    db.commit()
    db.close()


def _mock_network(monkeypatch, ip="45.155.99.10", page=None):
    import backend.core.analyzer_interface as ai

    monkeypatch.setattr(ai, "resolve_ip", lambda d: ip)
    monkeypatch.setattr(ai, "lookup_domain_registration",
                        lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "none")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation",
                        lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    monkeypatch.setattr(ai, "probe_page", page or (lambda u: {"status": "error"}))


@pytest.mark.parametrize("raw", ["http://[::ffff:45.155.99.10]/giris", "http://45.155.99.10/giris",
                                 "http://bu-ipye-cozumlenir.com/giris"])
def test_b09_retest_ip_rule_applies_to_mapped_and_resolved_addresses(monkeypatch, ip_rule, raw):
    _mock_network(monkeypatch)
    result = analyze_url_pipeline(raw, db=ip_rule)
    assert result["risk_score"] == 100
    assert result["reasons"][0]["rule_name"] == "Engel listesi eşleşmesi"


def test_b09_ip_rule_applies_to_redirect_hops(monkeypatch, ip_rule):
    _mock_network(monkeypatch, ip="93.184.216.34",
                  page=lambda u: {"status": "ok", "final_host": "son.example", "ips": ["93.184.216.34", "45.155.99.10"],
                                  "fields": [], "identity": [], "logos": [], "text": ""})
    result = analyze_url_pipeline("http://ara-adim.com/x", db=ip_rule)
    assert result["risk_score"] == 100


def test_b09_canonical_host_unwraps_embedded_ipv4():
    assert parse_url_components("http://[::ffff:45.155.99.10]/")["domain"] == "45.155.99.10"
    assert parse_url_components("http://[64:ff9b::2d9b:630a]/")["domain"] == "45.155.99.10"


# --- B-10: tespit dogrulugu ----------------------------------------------------------------

def test_b10_retest_news_page_mentioning_a_bank_stays_below_50(monkeypatch):
    body = ("<html><head><title>Garanti BBVA yeni konut kredisi kampanyasını duyurdu - Ekonomi Haberleri</title>"
            "</head><body><h1>Garanti BBVA yeni konut kredisi kampanyasını duyurdu</h1><p>"
            + "Banka açıklamasında faiz oranlarının düşürüldüğü belirtildi. " * 20 + "</p>"
            + "".join(f"<a href='https://haber-{i}.example/h'>Haber {i}</a>" for i in range(30))
            + "</body></html>")
    url = "http://ekonomi-haber-gazetesi.com/garanti-bbva-konut-kredisi"
    page, _ = _probe(monkeypatch, url, [(200, HTML_UTF8, body.encode())])
    for tls in (None, "http_link"):
        score, _, reasons, _ = analyze(url, page=page, tls=tls)
        assert score < 50, (score, names(reasons))
    assert "Sayfa başlığında Garanti BBVA adı geçiyor" in names(analyze(url, page=page)[2])


@pytest.mark.parametrize("headers,body,name", [
    ({"content-type": "application/vnd.android.package-archive"}, b"PK\x03\x04" + b"\x00" * 40, "kargo.apk"),
    ({"content-type": "application/octet-stream", "content-disposition": "attachment; filename=\"takip.apk\""},
     b"PK\x03\x04AndroidManifest.xml" + b"\x00" * 40, "takip.apk"),
])
def test_b10_retest_apk_download_produces_file_type_finding(monkeypatch, headers, body, name):
    url = f"http://kargo-takip-b10.com/{name}"
    page, _ = _probe(monkeypatch, url, [(200, headers, body)])
    assert page["status"] == "download" and page["download"]["kind"] == "Android uygulaması (APK)"
    assert page["download"]["sha256"]
    score, _, reasons, _ = analyze(url, page=page)
    assert "Adres doğrudan dosya indiriyor: Android uygulaması (APK)" in names(reasons)
    assert score >= 50


# --- B-11: ek gozlemler ---------------------------------------------------------------------

def test_b11_page_probe_reuses_the_address_resolved_by_the_pipeline(monkeypatch):
    resolved = []
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: resolved.append(host) or "93.184.216.34")
    seen = {}

    def pinned(parts, host, ip, port, deadline):
        seen["ip"] = ip
        return page_probe._Response(200, HTML_UTF8, b"<html><title>x</title><p>merhaba dunya</p></html>")

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    token = netguard.set_probe_context(ProbeContext("198.51.100.120", pinned={"tek-cozum.com": "203.0.113.50"}))
    try:
        assert page_probe.probe_page("http://tek-cozum.com/")["status"] == "ok"
    finally:
        netguard.reset_probe_context(token)
    assert resolved == [] and seen["ip"] == "203.0.113.50"


def test_b11_tab_in_address_is_reported_as_obfuscation():
    _, _, reasons, _ = analyze("ht\ttp://gizli-adres.com/gi\nris")
    assert "Adreste gizlenmiş karakter" in names(reasons)


def test_b11_login_delay_does_not_hold_worker_threads():
    import inspect

    from backend.api import routes_auth

    assert inspect.iscoroutinefunction(routes_auth.admin_login)
    assert "time.sleep" not in inspect.getsource(routes_auth.admin_login)
