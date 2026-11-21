"""Guvenlik zafiyet raporu (6) — A-01..A-14 icin regresyon testleri. Ag erisimi gerektirmez.

Her bulgu icin raporun "Yeniden test" olcutu, laboratuvar yerine sahte ag katmaniyla sinanir. Icerik
bulgularinda (A-01..A-04) genel kural da sinanir: statik ayristiricinin goremedigi bir yapi iceren sayfa
"tam incelendi" sayilmaz ve karar "LOW" olamaz.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import asyncio
import base64
import html as html_lib
import threading
import time
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core import netguard, page_probe
from backend.core.analyzer_interface import analyze_url_pipeline, inspection_coverage, parse_url_components
from backend.core.brands import official_brand
from backend.core.netguard import ProbeContext, targets
from backend.core.scoring import collect_signals, score_signals
from backend.tools import catalog_health

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


def names(reasons):
    return [r["rule_name"] for r in reasons]


def analyze(raw, page=None, age=None, tls=None):
    parsed = parse_url_components(raw)
    url = f"{parsed['scheme'] or 'https'}://{parsed['authority']}{parsed['rest']}"
    if page is not None and "final_host" not in page:
        page = dict(page, final_host=parsed["domain"])
    signals, mitigations, context = collect_signals(
        {**parsed, "url": url}, {"resolved": True, "page": page or {}, "age_days": age, "tls": tls})
    score, level, reasons = score_signals(signals, mitigations)
    return score, level, reasons, context


HTML = {"content-type": "text/html; charset=utf-8"}
FORM = ("<form action='/post' method=post><input name=tckn placeholder='T.C. Kimlik No'>"
        "<input type=password name=sifre><input name=kartno placeholder='Kart numarası'><button>Giriş</button></form>")


def phish(title="Garanti BBVA İnternet Şubesi", h1="Garanti BBVA", form=FORM, head="", body=""):
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>{head}</head>"
            f"<body>{body}<h1>{h1}</h1>{form}</body></html>")


def serve(monkeypatch, pages):
    """pages: {url: (status, headers, body)}; bilinmeyen adres 404 doner. Cagrilan adresler doner."""
    calls = []

    def fetch(url, deadline, pinned=None):
        calls.append(url)
        status, headers, body = pages.get(url, (404, HTML, b"<html><body>yok</body></html>"))
        return page_probe._Response(status, headers, body if isinstance(body, bytes) else body.encode("utf-8"))

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    return calls


def probe(monkeypatch, pages, url):
    calls = serve(monkeypatch, pages)
    return page_probe.probe_page(url), calls


def pipeline(monkeypatch, pages, url, ip="93.184.216.34"):
    import backend.core.analyzer_interface as ai

    serve(monkeypatch, pages)
    monkeypatch.setattr(ai, "resolve_ip", lambda d: ip)
    monkeypatch.setattr(ai, "resolve_all_public", lambda d: [ip])
    monkeypatch.setattr(ai, "lookup_domain_registration",
                        lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "valid")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation", lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    return analyze_url_pipeline(url)


def assert_not_silently_low(result):
    """Genel kural: sayfa ya bulgulariyla yakalanir ya da "tam incelenmedi" olarak bildirilir."""
    cov = result["ioc_details"]["inspection_coverage"]
    assert not (result["risk_level"] == "LOW" and cov == "full"), (result["risk_score"], names(result["reasons"]))
    assert result["risk_level"] != "LOW", (result["risk_level"], cov)


# --- A-01: betik gerektirmeyen yollarla icerigin gizlenmesi ---------------------------------

T = "https://hedef-a01.com/giris"
FULL = "position:fixed;top:0;left:0;width:100%;height:100%;border:0"
WRAP = "<!doctype html><html><head><meta charset='utf-8'><title>Hoş geldiniz</title></head>%s</html>"
XHTML_ENTITY = (
    "<?xml version='1.0' encoding='utf-8'?><!DOCTYPE html [<!ENTITY govde \"&#60;form xmlns='http://www.w3.org/1999/xhtml'"
    "&#62;&#60;input type='password' name='sifre'/&#62;&#60;/form&#62;\">]><html xmlns='http://www.w3.org/1999/xhtml'>"
    "<head><title>Hoş geldiniz</title></head><body>&govde;</body></html>")
A01 = {
    "iframe": ({"https://a01.com/iframe": (200, HTML, WRAP % f"<body><iframe src='/k' style='{FULL}'></iframe></body>"),
                "https://a01.com/k": (200, HTML, phish())}, "found"),
    "srcdoc": ({"https://a01.com/srcdoc": (200, HTML, WRAP % (
        "<body><iframe srcdoc=\"" + html_lib.escape(phish(), quote=True) + "\"></iframe></body>"))}, "found"),
    "object": ({"https://a01.com/object": (200, HTML, WRAP % "<body><object data='/k' type='text/html'></object></body>"),
                "https://a01.com/k": (200, HTML, phish())}, "found"),
    "frameset": ({"https://a01.com/frameset": (200, HTML, WRAP % "<frameset rows='100%'><frame src='/k'></frameset>"),
                  "https://a01.com/k": (200, HTML, phish())}, "found"),
    "svg-style-form": ({"https://a01.com/svg-style-form": (200, HTML, WRAP % (
        "<body><svg><style><div><h1>Garanti BBVA İnternet Şubesi</h1>" + FORM + "</div></style></svg></body>"))}, "found"),
    "svg-style-refresh": ({"https://a01.com/svg-style-refresh": (200, HTML, WRAP % (
        f"<body><svg><style><meta http-equiv='refresh' content='0;url={T}'></style></svg></body>")),
        T: (200, HTML, phish())}, "found"),
    "xhtml-entity": ({"https://a01.com/xhtml-entity": (200, {"content-type": "application/xhtml+xml"}, XHTML_ENTITY)},
                     "partial"),
    "truncated": ({"https://a01.com/truncated": (200, HTML, "<!doctype html><html><head><!-- " + "x" * (
        page_probe.MAX_BYTES + 5000) + " --><title>Garanti BBVA</title></head><body>" + FORM + "</body></html>")}, "partial"),
    "meta-12s": ({"https://a01.com/meta-12s": (200, HTML, WRAP % (
        f"<head><meta http-equiv='refresh' content='12; url={T}'></head><body><p>Lütfen bekleyin</p></body>")),
        T: (200, HTML, phish())}, "found"),
    "header-12s": ({"https://a01.com/header-12s": (200, dict(HTML, refresh=f"12; url={T}"),
                                                   WRAP % "<body><p>Lütfen bekleyin</p></body>"),
                    T: (200, HTML, phish())}, "found"),
    "frame-missing": ({"https://a01.com/frame-missing": (200, HTML, WRAP % "<body><iframe src='data:text/html,<form>'></iframe></body>")},
                      "partial"),
    "meta-600s": ({"https://a01.com/meta-600s": (200, HTML, WRAP % (
        f"<head><meta http-equiv='refresh' content='600; url={T}'></head><body><p>Bekleyin</p></body>"))}, "partial"),
}


@pytest.mark.parametrize("variant", sorted(A01))
def test_a01_retest_hidden_content_is_found_or_reported(monkeypatch, variant):
    """Yeniden test: hicbir cesit "sayfa: ok, kapsam: full, Dusuk risk" vermemeli; form ya bulunur (skor > 75)
    ya da "incelenemedi" bulgusuyla kapsam `partial` olur (skor >= 25)."""
    pages, expected = A01[variant]
    result = pipeline(monkeypatch, pages, f"https://a01.com/{variant}")
    assert_not_silently_low(result)
    if expected == "found":
        assert result["risk_score"] > 75, (result["risk_score"], names(result["reasons"]))
        assert any("Hassas bilgi toplayan form" in n for n in names(result["reasons"]))
    else:
        assert result["ioc_details"]["inspection_coverage"] == "partial"
        assert "Sayfanın bir bölümü incelenemedi" in names(result["reasons"])
        assert result["risk_score"] >= 25


def test_a01_delayed_refresh_is_followed_and_reported(monkeypatch):
    pages, _ = A01["meta-12s"]
    page, calls = probe(monkeypatch, pages, "https://a01.com/meta-12s")
    assert calls == ["https://a01.com/meta-12s", T] and page["redirect_delay"] == 12
    assert "Gecikmeli yönlendirme" in names(analyze("https://a01.com/meta-12s", page=page)[2])


def test_a01_self_refreshing_page_is_not_a_redirect(monkeypatch):
    url = "https://haber-a01.com/canli"
    body = WRAP % f"<head><meta http-equiv='refresh' content='30; url={url}'></head><body><p>{'Haber metni. ' * 50}</p></body>"
    page, calls = probe(monkeypatch, {url: (200, HTML, body)}, url)
    # E-05: kendine yenileyen sayfa bir kez yeniden istenir; ikinci yanit ayni sayfaysa yonlendirme sayilmaz
    # 9. tur: 10-60 sn gecikme beklenmedigi icin sayfa "tam incelendi" sayilmaz
    assert calls == [url, url] and page["status"] == "ok" and page["opaque"] == ["self_refresh"]
    assert page["redirects"] == [url] and page["steps"] == []


def test_a01_static_page_is_fully_inspected(monkeypatch):
    """Karsi ornek: betik, cerceve ve yonlendirme icermeyen statik sayfa tam incelenir."""
    url = "https://duz-sayfa-a01.com/"
    body = WRAP % f"<body><h1>Fırın</h1><p>{'Taze ekmek. ' * 30}</p><a href='/iletisim'>İletişim</a></body>"
    result = pipeline(monkeypatch, {url: (200, HTML, body)}, url)
    assert result["ioc_details"]["inspection_coverage"] == "full" and result["risk_level"] == "LOW"


# --- A-02: betik kuralinin atlatilmasi ---------------------------------------------------

_B64 = base64.b64encode(phish().encode()).decode()
WRITE = f"<script>document.write(atob('{_B64}'))</script>"
FILL = "<p style='display:none'>" + "Sitemize hoş geldiniz. Bilgi almak için bizimle iletişime geçebilirsiniz. " * 6 + "</p>"
A02 = {
    "gizli-dolgu": "<body>" + FILL + WRITE + "</body>",
    "gizli-girdi": "<body><input type='hidden' name='v' value='1'>" + WRITE + "</body>",
    "gizli-betik-yonlendirme": "<body>" + FILL + "<script>window['loc'+'ation']['hr'+'ef']=atob('aHR0cA==')</script></body>",
}


@pytest.mark.parametrize("variant", sorted(A02))
def test_a02_retest_script_rule_cannot_be_padded_away(monkeypatch, variant):
    """Yeniden test: uc adres "betige bagli icerik / incelenemedi" bulgusu uretmeli, kapsam `partial`, skor >= 25."""
    url = f"https://a02.com/{variant}"
    body = "<!doctype html><html><head><meta charset='utf-8'><title>Yükleniyor</title></head>" + A02[variant] + "</html>"
    result = pipeline(monkeypatch, {url: (200, HTML, body)}, url)
    assert "Sayfa içeriği betikle üretiliyor; incelenemedi" in names(result["reasons"])
    assert result["ioc_details"]["inspection_coverage"] == "partial"
    assert result["risk_score"] >= 25 and result["risk_level"] != "LOW"


def test_a02_any_executable_script_lowers_coverage(monkeypatch):
    """Esik yok: gorunur metni bol, betik iceren sayfa da "tam incelendi" sayilmaz; karar LOW olamaz."""
    url = "https://a02.com/dolu-sayfa"
    body = WRAP % f"<body><p>{'Görünür ve uzun bir metin. ' * 40}</p>{WRITE}</body>"
    result = pipeline(monkeypatch, {url: (200, HTML, body)}, url)
    assert result["ioc_details"]["inspection_coverage"] == "partial"
    assert "script" in result["ioc_details"]["inspection_gaps"]
    assert result["risk_level"] == "UNKNOWN"
    # JSON/sablon betikleri ve olay oznitelikleri
    doc, _ = page_probe._inspect_html("<p>x</p><script type='application/ld+json'>{}</script>", url)
    assert doc["opaque"] == []
    doc, _ = page_probe._inspect_html("<p>x</p><img src=a.png onerror='x()'>", url)
    assert doc["opaque"] == ["script"]


# --- A-03: kurum adinin gizlenmesi -------------------------------------------------------------

PWONLY = "<form action='/post' method=post><input name=kullanici><input type=password name=sifre><button>Giriş</button></form>"
A03 = {
    "satir-ici-etiket": phish(title="Giriş", h1="Gar<b></b>anti BB<i></i>VA İnternet Şubesi"),
    "rlo": phish(title="Giriş", h1="‮isebuŞ tenretnİ AVBB itnaraG‬"),
    "nul": phish(title="Giriş", h1="Gar\x00anti BB\x00VA İnternet Şubesi"),
    "css-dolgu": phish(title="Giriş", h1="Gar<span style='display:none'>zq</span>anti BB<span style='font-size:0'>k</span>VA"),
    "yalnizca-parola": phish(title="Giriş", h1="Gar<b></b>anti BB<i></i>VA İnternet Şubesi", form=PWONLY),
    "harf-harf": phish(title="Giriş", h1="G a r a n t i  B B V A"),
}


@pytest.mark.parametrize("variant", sorted(A03))
def test_a03_retest_hidden_brand_name_is_recognised(monkeypatch, variant):
    """Yeniden test: bes adresin her biri "Sayfa Garanti BBVA kimligi tasiyor" bulgusunu uretmeli, skor > 75."""
    url = f"https://a03.com/{variant}"
    page, _ = probe(monkeypatch, {url: (200, HTML, A03[variant])}, url)
    score, level, reasons, ctx = analyze(url, page=page)
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(reasons)), (variant, page["identity"], names(reasons))
    assert score > 75 and ctx["target_brand"] == "Garanti BBVA", (score, names(reasons))
    if variant in ("rlo", "harf-harf"):
        assert "Kurum adı gizlenerek yazılmış" in names(reasons)


def test_a03_block_elements_still_separate_text():
    doc, _ = page_probe._inspect_html("<p>Garanti</p><p>BBVA</p><div>bir</div>iki<br>uc", "https://x.com/")
    assert doc["text"] == "Garanti BBVA bir iki uc"


# --- A-04: B-10 duzeltmesinin yan etkisi ---------------------------------------------------------

LURE = ("<!doctype html><html><head><meta charset='utf-8'><title>Garanti BBVA - Hesap Bildirimi</title></head><body>"
        "<h1>Garanti BBVA</h1><p>Hesabınızda olağan dışı işlem tespit edildi. Kısıtlamayı kaldırmak için devam edin.</p>"
        "%s</body></html>")
A04 = {
    "anlamsiz-alan-adlari": phish(form=(
        "<form action='/post' method=post><label>T.C. Kimlik No</label><input type=text name=f1><label>Müşteri Şifresi</label>"
        "<input type=text name=f2 style='-webkit-text-security:disc'><label>Kart Numarası</label><input type=text name=f3>"
        "<button>Giriş</button></form>")),
    "devam-et": LURE % ("<p><a href='http://garanti-dogrulama-merkezi.xyz/giris'>Devam et</a></p><p>"
                        + "".join(f"<a href='/sayfa/{i}'>Bilgi {i}</a> " for i in range(11)) + "</p>"),
    "dugme": LURE % "<form action='http://garanti-dogrulama-merkezi.xyz/giris' method='get'><button>Devam</button></form>",
}


@pytest.mark.parametrize("variant", sorted(A04))
def test_a04_retest_phishing_page_is_not_downgraded_to_a_mention(monkeypatch, variant):
    """Yeniden test: uc adres "Sayfa Garanti BBVA kimligi tasiyor" bulgusunu uretmeli ve en az 70 puan almali."""
    url = f"https://a04.com/{variant}"
    page, _ = probe(monkeypatch, {url: (200, HTML, A04[variant])}, url)
    score, _, reasons, _ = analyze(url, page=page)
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(reasons)), names(reasons)
    assert score >= 70, (score, names(reasons))
    if variant == "anlamsiz-alan-adlari":
        assert {"Şifre", "Kart bilgisi", "T.C. kimlik no"} <= set(page["fields"])


def test_a04_news_page_with_search_box_stays_below_50(monkeypatch):
    """B-10 (a) olcutu korunur: baslikta kurum adi gecen, arama kutusu ve cok sayida dis baglanti tasiyan
    uzun haber sayfasi 50'nin altinda kalir."""
    url = "https://ekonomi-haber-a04.com/garanti-bbva-konut-kredisi"
    body = ("<html><head><title>Garanti BBVA yeni konut kredisi kampanyasını duyurdu - Ekonomi Haberleri</title></head>"
            "<body><form action='/ara'><input type=search name=q><button>Ara</button></form>"
            "<h1>Garanti BBVA yeni konut kredisi kampanyasını duyurdu</h1><p>"
            + "Banka açıklamasında faiz oranlarının düşürüldüğü belirtildi. " * 40 + "</p>"
            + "".join(f"<a href='https://kaynak-{i}.example/h'>Kaynak {i}</a>" for i in range(12)) + "</body></html>")
    page, _ = probe(monkeypatch, {url: (200, HTML, body)}, url)
    for tls in (None, "http_link"):
        score, _, reasons, _ = analyze(url, page=page, tls=tls)
        assert score < 50, (score, names(reasons))
    assert "Sayfa başlığında Garanti BBVA adı geçiyor" in names(analyze(url, page=page)[2])


# --- A-05: yoklama isteginin tarayicidan ayirt edilmesi -----------------------------------------

def test_a05_probe_sends_browser_navigation_headers(monkeypatch):
    seen = {}

    class Msg:
        def get_all(self, name):
            return ["t=1; Path=/"] if seen.setdefault("n", 0) == 0 else []

    class Resp:
        status = 200
        msg = Msg()

        def getheaders(self):
            return [("Content-Type", "text/html")]

        def read1(self, n):
            data, seen["body"] = seen.get("body", b"<html><p>merhaba</p></html>"), b""
            return data

    class Conn:
        def __init__(self, *a, **k):
            pass

        def request(self, method, target, headers=None):
            seen.setdefault("requests", []).append(dict(headers))

        def getresponse(self):
            return Resp()

        def close(self):
            seen["n"] = seen.get("n", 0) + 1
            seen.pop("body", None)

    monkeypatch.setattr(page_probe, "PinnedHTTPSConnection", Conn)
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "93.184.216.34")
    token = page_probe._probe_state.set({"cookies": {}, "reduced": False})
    try:
        page_probe._fetch_once("https://baslik-a05.com/a", time.monotonic() + 5)
        page_probe._fetch_once("https://baslik-a05.com/b", time.monotonic() + 5)
    finally:
        page_probe._probe_state.reset(token)
    first, second = seen["requests"]
    for name in ("Accept", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Site", "Upgrade-Insecure-Requests",
                 "sec-ch-ua", "Accept-Language", "Accept-Encoding", "User-Agent"):
        assert name in first, name
    # E-06: tarayici gibi 'Connection: keep-alive'; ilk istekte Referer yok
    assert "text/html" in first["Accept"] and first["Connection"] == "keep-alive" and "Referer" not in first
    assert f"Chrome/{settings.PROBE_CHROME_MAJOR}." in first["User-Agent"]
    # Cerez zincir boyunca tasinir (cerez sinamasi yapan sunucu)
    assert "Cookie" not in first and second.get("Cookie") == "t=1"


def test_a05_cloaking_note_is_shown_for_every_low_result(monkeypatch):
    url = "http://duzsayfaa05.com/"
    body = WRAP % f"<body><p>{'Metin. ' * 60}</p></body>"
    result = pipeline(monkeypatch, {url: (200, HTML, body)}, url)
    assert result["risk_level"] == "LOW" and len(result["reasons"]) > 1
    assert "Gizlenme olasılığı" in names(result["reasons"])


# --- A-06: guvenilen adlarin altindaki kullanici icerigi ---------------------------------------

LURE_PAGE = LURE % "<p><a href='http://garanti-dogrulama-merkezi.xyz/giris'>Kimliğimi doğrula</a></p>"


@pytest.mark.parametrize("url", [
    "https://www.google.com/maps/d/viewer?mid=1xQ6a06",
    "https://www.paypal.com/paypalme/odeme6a06",
    "https://outlook.office.com/book/GarantiBBVADestek@ornek.onmicrosoft.com/",
    # Katalogda yolu LISTELENMEMIS guvenilen adres: icerik kosulu yine yakalar
    "https://www.google.com/yeni-bir-urun/paylasim/6a06",
])
def test_a06_retest_user_content_under_trusted_hosts(monkeypatch, url):
    """Yeniden test: "resmi alan adi" indirimi yok; Garanti BBVA kimligi bulgu; skor >= 50."""
    page, _ = probe(monkeypatch, {url: (200, HTML, LURE_PAGE)}, url)
    score, _, reasons, _ = analyze(url, page=page, age=9000)
    assert not any("resmi alan adı" in n for n in names(reasons)), names(reasons)
    assert any("Garanti BBVA kimliği taşıyor" in n for n in names(reasons)), names(reasons)
    assert score >= 50


def test_a06_trusted_host_own_pages_keep_official_status(monkeypatch):
    assert official_brand("accounts.google.com") is not None
    url = "https://accounts.google.com/signin"
    page, _ = probe(monkeypatch, {url: (200, HTML, WRAP % "<body><h1>Google Hesabı</h1><form><input type=password name=p></form></body>")}, url)
    score, _, reasons, _ = analyze(url, page=page, age=9000)
    assert any("resmi alan adı" in n for n in names(reasons)) and score < 25
    # Resmi sitede ortak kurum adi gecen, bilgi istemeyen ve dis baglanti tasimayan sayfa indirimi kaybetmez
    url = "https://www.garantibbva.com.tr/kartlar/miles-and-smiles"
    body = WRAP.replace("Hoş geldiniz", "Miles&Smiles Kredi Kartı") % f"<body><h1>Miles&amp;Smiles</h1><p>{'Kart özellikleri. ' * 150}</p></body>"
    page, _ = probe(monkeypatch, {url: (200, HTML, body)}, url)
    score, _, reasons, _ = analyze(url, page=page, age=9000)
    assert any("resmi alan adı" in n for n in names(reasons)) and score < 25, (score, names(reasons))


# --- A-07: yarim birakilan isteklerle ortak sinirin doldurulmasi --------------------------------

def test_a07_per_client_gate_rejects_before_reading_the_body():
    from backend.core.body_limit import ClientRequestGateMiddleware

    release = asyncio.Event()
    entered = []

    async def app(scope, receive, send):
        entered.append(scope["client"][0])
        await release.wait()

    gate = ClientRequestGateMiddleware(app, max_inflight=3)

    async def run():
        async def receive():
            pytest.fail("govde okunmamali")

        def scope(ip):
            return {"type": "http", "method": "POST", "path": "/admin/login", "client": (ip, 1), "headers": []}

        held = [asyncio.create_task(gate(scope("198.51.100.5"), receive, None)) for _ in range(3)]
        await asyncio.sleep(0.05)
        sent = []

        async def send(message):
            sent.append(message)

        # Ayni istemcinin dorduncu istegi govde okunmadan 429 alir
        await gate(scope("198.51.100.5"), receive, send)
        assert sent[0]["status"] == 429
        # Baska istemci etkilenmez
        other = asyncio.create_task(gate(scope("198.51.100.6"), receive, None))
        await asyncio.sleep(0.05)
        assert entered.count("198.51.100.6") == 1
        release.set()
        await asyncio.gather(*held, other)
        # Yuvalar birakilir
        assert gate._inflight == {}

    asyncio.run(run())


def test_a07_admin_network_restriction_is_applied_before_the_body(client, monkeypatch):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "ADMIN_TRUSTED_NETWORKS", "10.20.0.0/16")
    monkeypatch.setattr(settings, "ADMIN_RESTRICT_TO_TRUSTED", True)
    monkeypatch.setattr(routes_auth, "client_ip", lambda request: "198.51.100.7")
    # Gecersiz govde: denetim govdeden once calisiyorsa 422 degil 403 doner
    r = client.post("/admin/login", content=b"{bozuk", headers={"content-type": "application/json"})
    assert r.status_code == 403
    r = client.post("/lists", content=b"{bozuk", headers={"content-type": "application/json"})
    assert r.status_code == 403


def test_a07_proxy_buffers_bodies_and_shared_limit_is_a_backstop():
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "request_buffers" in caddy
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    limit = int(dockerfile.split('"--limit-concurrency", "')[1].split('"')[0])
    assert limit >= 100 * settings.MAX_INFLIGHT_PER_CLIENT


# --- A-08 / A-09 / A-10: paylasilan yoklama durumu ---------------------------------------------

def test_a08_waiters_for_the_same_address_are_capped(monkeypatch):
    gate = threading.Event()
    calls = []

    def fetch(url, deadline, pinned=None):
        calls.append(url)
        gate.wait(3)
        return page_probe._Response(200, HTML, phish().encode())

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    results = []
    started = time.monotonic()
    threads = [threading.Thread(target=lambda: results.append((page_probe.probe_page("https://ortak-a08.com/a"),
                                                              time.monotonic() - started))) for _ in range(13)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    # 13 istekten 10'u beklemeden vazgecmis olmali: yuva tutmazlar
    early = [r for r in results if r[0]["status"] == "target_busy"]
    assert len(early) == 13 - 1 - page_probe.MAX_SHARED_WAITERS and all(d < 0.3 for _, d in early)
    gate.set()
    for t in threads:
        t.join(5)
    assert len(calls) == 1 and sum(r[0]["status"] == "ok" for r in results) == 1 + page_probe.MAX_SHARED_WAITERS


def test_a09_retest_failure_from_reduced_budget_is_not_shared(monkeypatch):
    """Yeniden test: cezali istemcinin "incelenemedi" sonucundan sonra baska kullanici sayfayi inceleyebilmeli."""
    url = "https://yavasca-a09.com/sayfa"
    state = {"fail": True}

    def fetch(u, deadline, pinned=None):
        if state["fail"]:
            raise page_probe._FetchError("budget exhausted")
        return page_probe._Response(200, HTML, phish().encode())

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    token = netguard.set_probe_context(ProbeContext("198.51.100.91", page_budget=netguard.PENALTY_BUDGET_SECONDS))
    try:
        assert page_probe.probe_page(url)["status"] == "error"
    finally:
        netguard.reset_probe_context(token)
    state["fail"] = False
    page = page_probe.probe_page(url)
    assert page["status"] == "ok" and "cached_at" not in page


def test_a09_full_budget_failures_are_cached_only_briefly(monkeypatch):
    url = "https://kapali-a09.com/"
    monkeypatch.setattr(page_probe, "_fetch_once", lambda u, d, pinned=None: (_ for _ in ()).throw(page_probe._FetchError("x")))
    assert page_probe.probe_page(url)["status"] == "error"
    assert page_probe._cache.get(url)[2] == page_probe.FAILURE_CACHE_TTL_SECONDS
    assert page_probe.FAILURE_CACHE_TTL_SECONDS <= 60 < page_probe.CACHE_TTL_SECONDS


def test_a10_retest_known_sites_on_degraded_ip_keep_full_budget(monkeypatch):
    """Yeniden test: uc istekten sonra daha once incelenmis sitenin agir sayfasi yine incelenebilmeli."""
    ip = "45.155.99.30"
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: ip)
    budgets = {}

    def pinned(parts, host, ip_, port, deadline):
        budgets[host + parts.path] = deadline - time.monotonic()
        return page_probe._Response(200, HTML, (WRAP % f"<body><p>{'Ekmek. ' * 60}</p></body>").encode())

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    assert page_probe.probe_page("http://mesru-firin-a10.com/urunler")["status"] == "ok"
    for i, name in enumerate(("a1-yavas.com", "a2-yavas.com", "a3-yavas.com")):
        targets.record_timeout(name, ip=ip, client=f"198.51.100.{100 + i % 2}", scope=f"{name}/")
    assert targets.ip_degraded(ip)
    assert page_probe.probe_page("http://mesru-firin-a10.com/agir/kampanyalar")["status"] == "ok"
    assert budgets["mesru-firin-a10.com/agir/kampanyalar"] > netguard.DEGRADED_PAGE_BUDGET_SECONDS + 1
    # Daha once gorulmemis ad kisa butce alir (D-03 korumasi surer)
    page_probe.probe_page("http://yeni-ad-a10.com/")
    assert budgets["yeni-ad-a10.com/"] <= netguard.DEGRADED_PAGE_BUDGET_SECONDS + 0.1


# --- A-11: yinelenen gosterge kaydi -----------------------------------------------------------

def _result(url, score=86, level="CRITICAL"):
    return {"url": url, "risk_score": score, "risk_level": level, "reasons": [],
            "ioc_details": {"domain": "yaris-a11.example"}, "mitre_techniques": [], "related_domains": []}


def test_a11_retest_concurrent_first_analyses_create_one_record():
    from backend.api import routes_analyze
    from backend.models.database import SessionLocal, init_db
    from backend.models.ioc_model import IOCModel

    init_db()
    url = f"http://yaris-a11.example/k/{time.time_ns()}"
    ids, errors = [], []
    barrier = threading.Barrier(6)

    def worker():
        db = SessionLocal()
        try:
            barrier.wait(5)
            ids.append(routes_analyze._persist(_result(url), db).id)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(6)]
    [t.start() for t in threads]
    [t.join(20) for t in threads]
    db = SessionLocal()
    try:
        rows = db.query(IOCModel).filter(IOCModel.value == url).all()
        assert not errors and len(rows) == 1, (errors, len(rows))
        assert {i for i in ids if i is not None} <= {rows[0].id}
        db.delete(rows[0])
        db.commit()
    finally:
        db.close()


def test_a11_unique_index_and_migration_merges_existing_duplicates(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect, text

    from backend.models import database

    engine = create_engine(f"sqlite:///{tmp_path}/eski.db", future=True)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE iocs (id INTEGER PRIMARY KEY, type VARCHAR(50), value TEXT, value_hash VARCHAR(64), risk_score INTEGER, risk_level VARCHAR(20))"))
        conn.execute(text("CREATE TABLE analysis_results (id INTEGER PRIMARY KEY, ioc_id INTEGER, risk_score INTEGER)"))
        for table in ("domains", "ip_addresses", "urls"):
            conn.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, ioc_id INTEGER)"))
        conn.execute(text("CREATE TABLE campaign_iocs (campaign_id INTEGER, ioc_id INTEGER)"))
        for i, score in ((1, 30), (2, 86), (3, 40)):
            conn.execute(text("INSERT INTO iocs VALUES (:i, 'url', 'http://x/', 'h1', :s, 'X')"), {"i": i, "s": score})
            conn.execute(text("INSERT INTO analysis_results (ioc_id, risk_score) VALUES (:i, :s)"), {"i": i, "s": score})
            conn.execute(text("INSERT INTO urls (ioc_id) VALUES (:i)"), {"i": i})
        conn.execute(text("INSERT INTO campaign_iocs VALUES (7, 3)"))
    monkeypatch.setattr(database, "engine", engine)
    database.migrate_ioc_unique()
    database.migrate_ioc_unique()  # idempotent
    with engine.begin() as conn:
        assert conn.execute(text("SELECT id, risk_score FROM iocs")).fetchall() == [(1, 86)]
        assert conn.execute(text("SELECT COUNT(*) FROM analysis_results WHERE ioc_id = 1")).scalar() == 3
        assert conn.execute(text("SELECT ioc_id FROM campaign_iocs")).fetchall() == [(1,)]
        assert conn.execute(text("SELECT COUNT(*) FROM urls")).scalar() == 1
    assert "ux_iocs_type_value_hash" in {i["name"] for i in inspect(engine).get_indexes("iocs")}


# --- A-12: katalog saglik araci --------------------------------------------------------------

def test_a12_retest_rdap_404_is_only_unregistered_when_the_tld_has_rdap():
    assert catalog_health.parse_rdap(404, None, True)["registry"] == "not_registered"
    assert catalog_health.parse_rdap(404, None, False)["registry"] == "unverifiable"
    assert catalog_health.parse_rdap(404, None, None)["registry"] == "unverifiable"
    assert catalog_health.parse_rdap(429, None, True)["registry"] == "unverifiable"
    ok = catalog_health.parse_rdap(200, {"status": ["client hold"], "events": [
        {"eventAction": "expiration", "eventDate": "2099-01-01T00:00:00Z"}]}, True)
    assert ok["registry"] == "registered" and ok["status"] == ["client hold"] and ok["days_left"] > 1000


def test_a12_tr_names_use_trabis_whois(monkeypatch):
    answers = {
        "garantibbva.com.tr": "** Domain Name: garantibbva.com.tr\nDomain Status: Active\nFrozen Status: -\n",
        "kayitsiz-a12.com.tr": "No match found for kayitsiz-a12.com.tr\n",
    }
    asked = []

    def whois(server, query, timeout=10.0):
        asked.append(server)
        return answers.get(query)

    monkeypatch.setattr(catalog_health, "_whois", whois)
    monkeypatch.setattr(catalog_health, "_rdap", lambda *a, **k: pytest.fail(".tr icin RDAP sorulmamali"))
    assert catalog_health.registration("garantibbva.com.tr")["registry"] == "registered"
    assert catalog_health.registration("kayitsiz-a12.com.tr")["registry"] == "not_registered"
    assert catalog_health.registration("yanit-yok-a12.com.tr")["registry"] == "unverifiable"
    assert set(asked) == {catalog_health.TR_WHOIS}


def test_a12_only_errors_fail_the_job():
    c = catalog_health.classify
    assert c({"domain": "a.com", "resolves": True, "registry": "not_registered"})["errors"] == ["kayıtlı değil"]
    assert c({"domain": "a.com", "resolves": True, "registry": "registered", "status": ["client hold"]})["errors"]
    assert c({"domain": "a.com", "resolves": True, "registry": "registered", "days_left": 5})["errors"]
    item = c({"domain": "a.com", "resolves": False, "registry": "unverifiable"})
    assert item["errors"] == [] and len(item["warnings"]) == 2
    # Kabul edilmis durum uyariyi bastirir; hatayi bastirmaz
    exc = {"microsoftonline.com": "alt alan adlari cozumlenir"}
    assert c({"domain": "microsoftonline.com", "resolves": False, "registry": "registered"}, exc)["warnings"] == []
    assert c({"domain": "microsoftonline.com", "resolves": False, "registry": "not_registered"}, exc)["errors"]


def test_a12_catalog_documents_known_exceptions():
    import json

    data = json.loads((ROOT / "backend" / "data" / "tr_brands.json").read_text(encoding="utf-8"))
    assert "microsoftonline.com" in data["health_exceptions"]


# --- A-13: karar sunucuda uretilir ---------------------------------------------------------------

@pytest.mark.parametrize("page,coverage", [
    ({"status": "not_html"}, "partial"), ({"status": "error"}, "none"), ({"status": "too_many_redirects"}, "none"),
    ({"status": "ok", "script_rendered": True, "opaque": ["script"], "fields": [], "identity": [], "logos": [], "text": ""},
     "partial"),
])
def test_a13_retest_uninspected_pages_are_never_low(page, coverage):
    """Yeniden test: kapsam tam degilken risk_level "LOW" olmamali; koklu alan adi bulguyu azaltmamali."""
    assert inspection_coverage(page) == coverage
    score, level, reasons, _ = analyze("https://eskisite-a13.com/x", page=page, age=4400)
    floor = 30 if page.get("script_rendered") else 15
    assert score >= floor, (score, names(reasons))


def test_a13_pipeline_returns_unknown_level(monkeypatch):
    url = "https://eskisite-a13.com/ikili"
    result = pipeline(monkeypatch, {url: (200, {"content-type": "application/octet-stream"}, bytes(range(256)) * 8)}, url)
    assert result["ioc_details"]["inspection_coverage"] == "partial" and result["risk_level"] == "UNKNOWN"
    # Katalogdaki resmi adres: karar adresin sahipligine dayanir
    url = "https://www.garantibbva.com.tr/"
    body = WRAP.replace("Hoş geldiniz", "Garanti BBVA") % "<body><div id=root></div><script src=/app.js></script></body>"
    result = pipeline(monkeypatch, {url: (200, HTML, body)}, url)
    assert result["ioc_details"]["inspection_coverage"] == "partial" and result["risk_level"] == "LOW"


def test_a13_frontend_uses_server_side_level():
    verdict = (ROOT / "src" / "lib" / "verdict.js").read_text(encoding="utf-8")
    assert "level === 'unknown'" in verdict


# --- A-14: ek gozlemler -------------------------------------------------------------------------

def test_a14_raw_deflate_bodies_are_decoded():
    body = b"<html><title>Garanti BBVA</title></html>"
    co = zlib.compressobj(wbits=-15)
    assert page_probe._decode_body(co.compress(body) + co.flush(), "deflate") == body
    assert page_probe._decode_body(zlib.compress(body), "deflate") == body


def test_a14_redirect_to_non_standard_port_is_reported(monkeypatch):
    url = "https://ara-a14.com/git"

    def fetch(u, deadline, pinned=None):
        if u == url:
            return page_probe._Response(302, {"location": "http://hedef-a14.com:8081/giris"}, b"")
        raise page_probe.PortNotAllowedError(u)

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page = page_probe.probe_page(url)
    assert page["status"] == "port_not_allowed"
    assert "Sayfa içeriği incelenemedi" in names(analyze(url, page=page)[2])


def test_a14_redirect_chain_of_five_is_followed(monkeypatch):
    pages = {f"https://zincir-a14.com/{i}": (302, {"location": f"/{i + 1}"}, b"") for i in range(6)}
    pages["https://zincir-a14.com/6"] = (200, HTML, phish())
    page, calls = probe(monkeypatch, pages, "https://zincir-a14.com/0")
    assert page["status"] == "ok" and len(calls) == 7 and "Şifre" in page["fields"]


def test_a14_ip_rule_checks_every_resolved_address(monkeypatch):
    import backend.core.analyzer_interface as ai
    from backend.models.database import SessionLocal, init_db
    from backend.models.list_model import ListModel

    init_db()
    db = SessionLocal()
    rule = ListModel(list_type="blacklist", entry_type="ip", pattern="45.155.99.10", description="a14")
    db.add(rule)
    db.commit()
    try:
        monkeypatch.setattr(ai, "resolve_ip", lambda d: "93.184.216.34")
        monkeypatch.setattr(ai, "resolve_all_public", lambda d: ["93.184.216.34", "45.155.99.10"])
        result = analyze_url_pipeline("http://cok-adresli-a14.com/", db=db)
        assert result["risk_score"] == 100 and result["reasons"][0]["rule_name"] == "Engel listesi eşleşmesi"
    finally:
        db.delete(rule)
        db.commit()
        db.close()
