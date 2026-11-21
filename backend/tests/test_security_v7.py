"""Guvenlik zafiyet raporu (7) — E-01..E-17 icin regresyon testleri. Ag erisimi gerektirmez.

Her bulgu icin raporun "Yeniden test" olcutu ve en az iki komsu cesit, laboratuvar yerine sahte ag katmaniyla
sinanir. Test sayfalari rapordaki kanit sayfalarinin (rapor/kanitlar_v7/araclar/r7.py) aynisidir. Analizler
gecerli TLS ile calistirilir: rapordaki 13-15 puanlik "Sifresiz baglanti" katkisi yoktur, olcut daha siki uygulanir.

Genel kural (rapor 7.1): platformun gordugu belge tarayicinin gordugunden farkli olabiliyorsa sonuc
"sayfa: ok, kapsam: full, Dusuk risk" OLAMAZ.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import json
import random
import time
from datetime import date
from pathlib import Path

import pytest

from backend.core import page_probe, urls
from backend.core.analyzer_interface import InvalidTargetError, analyze_url_pipeline, parse_url_components
from backend.core.brands import normalize_text
from backend.sandbox import html_extract
from backend.sandbox import pool as parse_pool
from backend.tests.test_security_v6 import _page_fetch, analyze, names  # noqa: F401  (_page_fetch: autouse fixture)

ROOT = Path(__file__).resolve().parents[2]
HTML = {"content-type": "text/html; charset=utf-8"}
T = "hedef-z09.com"
BS = chr(92)
FULL = "position:fixed;top:0;left:0;width:100%;height:100%;border:0"
PW = ("<form action='/post' method=post><input name=kullanici placeholder='Müşteri numarası'>"
      "<input type=password name=sifre><button>Giriş</button></form>")
BODY = "<h1>Garanti BBVA İnternet Şubesi</h1>" + PW
PLAIN = ("<!doctype html><html><head><meta charset='utf-8'><title>Hoş geldiniz</title></head>"
         "<body><p>Merhaba.</p></body></html>")
CARD = ("<h1>Garanti BBVA</h1><form action='/post' method=post><input name=tckn placeholder='T.C. Kimlik No'>"
        "<input name=kartno placeholder='Kart numarası'><button>Giriş</button></form>")


def doc(body, title="Hoş geldiniz", head=""):
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>{head}</head>"
            f"<body>{body}</body></html>")


LOADING = ("<!doctype html><html><head><meta charset='utf-8'><title>Yükleniyor</title>%s</head>"
           "<body><p>Lütfen bekleyin…</p></body></html>")
TARGET_PAGES = {
    f"https://{T}/giris7": (200, HTML, doc(CARD, title="Garanti BBVA İnternet Şubesi")),
    f"https://{T}/cerceve7": (200, HTML, doc(CARD, title="Garanti BBVA")),
    f"https://{T}/@www.garantibbva.com.tr/": (200, HTML, doc(CARD, title="Garanti BBVA İnternet Şubesi")),
}


def run(monkeypatch, url, pages=None, handler=None, db=None, ip="93.184.216.34"):
    """Analiz hattini sahte ag katmaniyla calistirir. `pages`: {adres: (durum, basliklar, govde)};
    `handler(istek)`: (durum, basliklar, govde, cerezler). Doner: (sonuc, istekler)."""
    import backend.core.analyzer_interface as ai

    calls = []

    def fetch(target, deadline, pinned=None):
        parsed = urls.parse(target)
        state = page_probe._probe_state.get() or {}
        request = {"url": target, "host": parsed.host, "path": parsed.path,
                   "cookie": page_probe._cookie_header(parsed.host, parsed.path, parsed.scheme == "https") or "",
                   "headers": dict(page_probe._request_headers(parsed.scheme, state.get("nav")))}
        calls.append(request)
        cookies = []
        if handler is not None:
            status, headers, body, cookies = handler(request)
        else:
            status, headers, body = (pages or {}).get(target, (404, HTML, "<html><body>yok</body></html>"))
        page_probe._store_cookies(parsed.host, cookies or [], parsed.path, parsed.scheme == "https")
        return page_probe._Response(status, headers, body if isinstance(body, bytes) else body.encode("utf-8"))

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    monkeypatch.setattr(ai, "resolve_ip", lambda d: ip)
    monkeypatch.setattr(ai, "resolve_all_public", lambda d: [ip])
    monkeypatch.setattr(ai, "lookup_domain_registration",
                        lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "valid")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation", lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    return analyze_url_pipeline(url, db=db), calls


def coverage(result):
    return result["ioc_details"]["inspection_coverage"]


def assert_caught(result, minimum=75):
    assert result["risk_score"] >= minimum, (result["risk_score"], result["risk_level"], names(result["reasons"]))


def assert_caught_or_partial(result, minimum=50):
    """Raporun olcutu: en az `minimum` puan YA DA kapsam `partial` (karar LOW olamaz)."""
    assert result["risk_level"] != "LOW", (result["risk_score"], names(result["reasons"]))
    assert result["risk_score"] >= minimum or coverage(result) != "full", (result["risk_score"], coverage(result))


# --- E-01: HTML agac kurma farklari ------------------------------------------------------------

E01 = {
    "kontrol": doc(BODY),
    # (a) HTML belgesinde CDATA bolumu yoktur; tarayici ilk '>' ile biten sahte yorum sayar
    "cdata": doc("<![CDATA[x>" + BODY),
    # (b) foreignObject icindeki ic <svg>: <style> icerigi etiket olarak okunur, <p> SVG'den cikar
    "foreignobject-svg-style": doc("<svg width='100%' height='600'><foreignObject width='100%' height='600'>"
                                   "<svg><style><p></p>" + BODY + "</style></svg></foreignObject></svg>"),
    # (c) SVG icindeki <textarea> / <title> ham metin ogesi degildir
    "svg-textarea": doc("<svg><textarea><p></p>" + BODY),
    "svg-title": doc("<svg><title><p></p>" + BODY),
    # Komsu cesitler
    "math-style": doc("<math><style><p></p>" + BODY),
    "noscript-comment": doc("<noscript><!--</noscript>" + BODY + "<!-- -->"),
    "noscript-attribute": doc("<noscript><a title=\"</noscript>" + BODY + "<p title=\"\">"),
    "table-foster": doc("<table><tr>" + BODY + "</tr></table>"),
    "select-breakout": doc("<select><option>x" + "<input>" + "</select>" + BODY),
    "p-hidden-autoclose": doc("<p hidden>" + BODY),
    "shadow-template": doc("<div><template shadowrootmode='open'>" + BODY + "</template></div>"),
    "bogus-comment": doc("<?php x ?>" + BODY),
    "nul-in-tag": doc("<in\x00put>" + BODY),
}


@pytest.mark.parametrize("variant", sorted(E01))
def test_e01_retest_tree_construction_variants_are_seen(monkeypatch, variant):
    """Yeniden test: tarayicinin cizdigi form, onune ne eklenirse eklensin platforma da gorunur (>= 75)."""
    url = f"https://papatya-e01.com/v7/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, E01[variant])})
    assert_caught(result)
    assert "Şifre" in result["ioc_details"]["page_fields"]


def test_e01_parser_is_a_tree_builder_and_independent_of_the_python_patch_version():
    """Ayristirma Python'un HTMLParser sinifina dayanmaz: gelistirme (3.11.0) ve uretim (3.11.18) ayni
    sonucu verir; bilgi belirtec akisindan degil kurulan agactan okunur."""
    source = (ROOT / "backend/core/page_probe.py").read_text(encoding="utf-8")
    assert "html.parser" not in source and "HTMLParser" not in source
    assert "html.parser" not in (ROOT / "backend/sandbox/html_extract.py").read_text(encoding="utf-8")
    facts = html_extract.extract(E01["svg-textarea"])
    assert facts["password_inputs"] == 1 and facts["h1"] == "Garanti BBVA İnternet Şubesi"
    # <noscript>, betik calistiran tarayicidaki gibi tek bir metin dugumudur: icindeki etiketler oge degildir
    facts = html_extract.extract("<noscript><form><input type=password></form><meta http-equiv=refresh content='0;url=/x'></noscript>")
    assert facts["password_inputs"] == 0 and facts["meta_refresh"] == []
    # Etkisiz <template> icerigi cizilmez: yonlendirmesi izlenmez, formu yine sayilir (birlesim)
    facts = html_extract.extract("<template><meta http-equiv=refresh content='0;url=/x'><input type=password>gizli</template>")
    assert facts["meta_refresh"] == [] and facts["password_inputs"] == 1 and facts["text_visible"] == []


def test_e01_two_views_rule_reports_content_the_tree_does_not_contain(monkeypatch):
    """Iki gorunum kurali: ham metinde parola alani var, ayristirilan belgede yoksa kapsam `partial` olur."""
    url = "https://papatya-e01.com/v7/yorum"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<p>Merhaba</p><!-- " + PW + " -->"))})
    assert coverage(result) == "partial" and "parse_mismatch" in result["ioc_details"]["inspection_gaps"]
    assert result["risk_level"] != "LOW"
    # Karsi ornek: sıradan statik sayfa tam incelenir
    result, _ = run(monkeypatch, url + "2", {url + "2": (200, HTML, doc("<h1>Fırın</h1><p>Taze ekmek.</p>"))})
    assert coverage(result) == "full" and result["risk_level"] == "LOW"


def test_e01_parser_runs_in_a_time_limited_worker(monkeypatch):
    """Agac kurucu derin ic ice ogelerde karesel sure tuketir; isci sure sinirinda sonlandirilir, sayfa
    "incelenemedi" olur ve sonraki belge yeni bir isciyle ayristirilir (hizmet durmaz)."""
    monkeypatch.setattr(parse_pool, "PARSE_TIMEOUT_SECONDS", 1.0)
    hostile = "<div>" * 190_000 + BODY
    started = time.monotonic()
    with pytest.raises(parse_pool.ParseFailed):
        parse_pool.extract(hostile, timeout=1.0)
    assert time.monotonic() - started < 4
    assert parse_pool.extract(doc(BODY))["password_inputs"] == 1
    features, _ = page_probe._inspect_html("x" * 5 + "\ud800" + doc(BODY), "https://x.com/")
    assert features["password_input"]  # tek basina vekil kod noktasi isciyi dusurmez


def test_e01_slow_parse_is_charged_to_the_client_and_the_address(monkeypatch):
    """Ayristiriciyi sure sinirina kadar tutan belge, yavas hedef gibi islenir: istemciye zaman asimi yazilir,
    adres karantinaya alinir; cezali istemcinin ayristirma suresi kisadir (ortak isciler tutulamaz)."""
    from backend.core import netguard

    def timing_out(html, xml=False, timeout=None, **kwargs):
        raise parse_pool.ParseFailed("timeout")

    monkeypatch.setattr(parse_pool, "extract", timing_out)
    ctx = netguard.ProbeContext(client="198.51.100.7")
    token = netguard.set_probe_context(ctx)
    try:
        features, _ = page_probe._inspect_html(doc(BODY), "https://derin-e01.com/kit/a")
    finally:
        netguard.reset_probe_context(token)
    assert features["opaque"] == ["parser"] and ctx.timeouts == ["derin-e01.com"]
    assert netguard.targets.is_slow("derin-e01.com", scope="derin-e01.com/kit")
    assert page_probe._parse_timeout() == parse_pool.PARSE_TIMEOUT_SECONDS
    penalised = netguard.ProbeContext(client="198.51.100.7", page_budget=netguard.PENALTY_BUDGET_SECONDS)
    token = netguard.set_probe_context(penalised)
    try:
        assert page_probe._parse_timeout() <= 0.6
    finally:
        netguard.reset_probe_context(token)


def test_e01_parse_failure_is_never_a_full_inspection(monkeypatch):
    def failing(html, xml=False, timeout=None, **kwargs):
        raise parse_pool.ParseFailed("timeout")

    monkeypatch.setattr(parse_pool, "extract", failing)
    url = "https://papatya-e01.com/v7/sure"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(BODY))})
    assert coverage(result) == "partial" and "parser" in result["ioc_details"]["inspection_gaps"]
    assert result["risk_level"] != "LOW" and "Sayfanın bir bölümü incelenemedi" in names(result["reasons"])


def test_e01_worker_does_not_receive_application_secrets():
    source = (ROOT / "backend/sandbox/pool.py").read_text(encoding="utf-8")
    assert "env=env" in source and "ADMIN" not in source and "DATABASE" not in source
    worker = (ROOT / "backend/sandbox/worker.py").read_text(encoding="utf-8")
    assert "pickle" not in worker.replace("pickle kullanilmaz", "") and "backend.config" not in worker


# --- E-02: taninmayan / durumlu kodlama ---------------------------------------------------------

def _iso2022(meta=""):
    asc = ("<h1>Garanti BBVA &#304;nternet &#350;ubesi</h1><form action='/post' method=post>"
           "<input name=kullanici placeholder='M&#252;&#351;teri numaras&#305;'>"
           "<input type=password name=sifre><button>Giri&#351;</button></form>")
    return (b"<!doctype html><html><head>" + meta.encode() + b"<title>Ho&#351; geldiniz</title></head><body>"
            b"\x1b$B<!--\x1b(B" + asc.encode("ascii") + b"</body></html>")


@pytest.mark.parametrize("variant", ["header", "meta", "sniffed"])
def test_e02_retest_stateful_encoding_is_decoded_or_reported(monkeypatch, variant):
    """Yeniden test: ISO-2022-JP ile etiketlenen sayfa >= 50 almali ya da kapsami `partial` olmali."""
    headers = {"content-type": "text/html; charset=iso-2022-jp" if variant == "header" else "text/html"}
    body = _iso2022("<meta charset='iso-2022-jp'>" if variant == "meta" else "")
    url = f"https://kamelya-e02.com/v7/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, headers, body)})
    assert_caught_or_partial(result)
    assert coverage(result) == "partial" and "charset" in result["ioc_details"]["inspection_gaps"]
    if variant != "sniffed":
        assert_caught(result)  # tarayicinin tablosuyla cozulen belgede form gorunur


def test_e02_unknown_charset_label_lowers_coverage(monkeypatch):
    """Yeniden test: charset=x-bilinmeyen basligiyla sunulan sıradan sayfa da `partial` olmali."""
    url = "https://kamelya-e02.com/v7/bilinmeyen"
    result, _ = run(monkeypatch, url, {url: (200, {"content-type": "text/html; charset=x-bilinmeyen"},
                                             doc("<h1>Fırın</h1><p>Taze ekmek.</p>"))})
    assert coverage(result) == "partial" and result["risk_level"] != "LOW"
    assert "Sayfanın bir bölümü incelenemedi" in names(result["reasons"])
    # Karsi ornek: taninan tek baytli kodlama tam incelemedir
    body = doc("<h1>Fırın</h1><p>Taze ekmek, çörek.</p>").replace("utf-8", "windows-1254").encode("cp1254")
    result, _ = run(monkeypatch, url + "2", {url + "2": (200, {"content-type": "text/html; charset=ISO-8859-9"}, body)})
    assert coverage(result) == "full" and result["risk_level"] == "LOW"


def test_e02_labels_follow_the_whatwg_table():
    plan = page_probe._encoding_plan
    assert plan(b"abc", "latin5").name == "windows-1254" and not plan(b"abc", "latin5").opaque
    assert plan(b"abc", "csiso2022jp").name == "iso-2022-jp" and plan(b"abc", "csiso2022jp").opaque
    for multibyte in ("gbk", "big5", "shift_jis", "euc-kr", "gb18030"):
        assert plan(b"abc", multibyte).opaque, multibyte
    assert plan(b"abc", "rot13").opaque and plan(b"abc", "rot13").name == "utf-8"
    assert plan(b"<p>d\xfcz</p>", None).name == "windows-1254" and not plan(b"<p>d\xfcz</p>", None).opaque
    assert page_probe._codec("undefined") is None and page_probe._codec("base64") is None


def test_e02_late_meta_charset_is_honoured_like_the_browser(monkeypatch):
    """Ilk 1.024 bayttan SONRA gelen <meta charset> agactan okunur; guvenilir kodlama ise belge onunla yeniden
    cozulur, degilse kapsam duser."""
    filler = "<!-- " + "x" * 1500 + " -->"
    body = ("<!doctype html><html><head>" + filler + "<meta charset='windows-1254'><title>İş Bankası İnternet Şubesi"
            "</title></head><body>" + PW + "</body></html>").encode("cp1254")
    url = "https://kamelya-e02.com/v7/gec"
    result, _ = run(monkeypatch, url, {url: (200, {"content-type": "text/html"}, body)})
    assert_caught(result)
    body = ("<!doctype html><html><head>" + filler + "<meta charset='iso-2022-jp'><title>x</title></head>"
            "<body><p>Merhaba</p></body></html>").encode("ascii")
    result, _ = run(monkeypatch, url + "2", {url + "2": (200, {"content-type": "text/html"}, body)})
    assert coverage(result) == "partial"


# --- E-03: adres cozumleme farklari ---------------------------------------------------------------

E03 = {
    "a-base-refresh": ("https://kekik-e03.com/v7/b1/7e", {
        "https://kekik-e03.com/v7/b1/7e": (200, HTML, LOADING % (
            f"<base href='https://{T}/'><meta http-equiv='refresh' content='0; url=giris7'>")),
        "https://kekik-e03.com/v7/b1/giris7": (200, HTML, PLAIN)}),
    "b-base-iframe": ("https://kekik-e03.com/v7/b2/7e", {
        "https://kekik-e03.com/v7/b2/7e": (200, HTML, doc(f"<iframe src='cerceve7' style='{FULL}'></iframe>",
                                                         head=f"<base href='https://{T}/'>")),
        "https://kekik-e03.com/v7/b2/cerceve7": (200, HTML, PLAIN)}),
    "c-backslash-refresh": ("https://ihlamur-e03.com/v7/u1/7e", {
        "https://ihlamur-e03.com/v7/u1/7e": (200, HTML, LOADING % (
            f"<meta http-equiv='refresh' content='0; url=/{BS}{T}/giris7'>")),
        f"https://ihlamur-e03.com/{BS}{T}/giris7": (200, HTML, PLAIN)}),
    "d-backslash-iframe": ("https://ihlamur-e03.com/v7/u2/7e", {
        "https://ihlamur-e03.com/v7/u2/7e": (200, HTML, doc(f"<iframe src='/{BS}{T}/cerceve7' style='{FULL}'></iframe>"))}),
    "e-triple-slash": ("https://ihlamur-e03.com/v7/u3/7e", {
        "https://ihlamur-e03.com/v7/u3/7e": (200, HTML, LOADING % (
            f"<meta http-equiv='refresh' content='0; url=https:///{T}/giris7'>")),
        f"https://ihlamur-e03.com/{T}/giris7": (200, HTML, PLAIN)}),
    "f-location-backslash": ("https://ihlamur-e03.com/v7/u4/7e", {
        "https://ihlamur-e03.com/v7/u4/7e": (302, {"location": f"/{BS}{T}/giris7"}, b"")}),
    "g-location-userinfo": ("https://ihlamur-e03.com/v7/u5/7e", {
        "https://ihlamur-e03.com/v7/u5/7e": (302, {"location": f"https://{T}{BS}@www.garantibbva.com.tr/"}, b""),
        "https://www.garantibbva.com.tr/": (200, HTML, doc("<h1>Garanti BBVA</h1><p>Resmi site.</p>", title="Garanti BBVA"))}),
    # Komsu cesitler
    "tab-in-scheme": ("https://ihlamur-e03.com/v7/u6/7e", {
        "https://ihlamur-e03.com/v7/u6/7e": (200, HTML, LOADING % (
            f"<meta http-equiv='refresh' content='0; url=ht\ttps://{T}/gi\nris7'>"))}),
    "protocol-relative-backslashes": ("https://ihlamur-e03.com/v7/u7/7e", {
        "https://ihlamur-e03.com/v7/u7/7e": (200, HTML, doc(f"<iframe src='{BS}{BS}{T}/cerceve7' style='{FULL}'></iframe>"))}),
    "refresh-header-backslash": ("https://ihlamur-e03.com/v7/u8/7e", {
        "https://ihlamur-e03.com/v7/u8/7e": (200, dict(HTML, refresh=f"0; url=/{BS}{T}/giris7"), PLAIN)}),
}


@pytest.mark.parametrize("variant", sorted(E03))
def test_e03_retest_platform_visits_the_address_the_browser_visits(monkeypatch, variant):
    """Yeniden test: "son adres" ya da cerceve bulgusu hedef alan adini gostermeli ve sonuc >= 50 olmali."""
    url, pages = E03[variant]
    result, calls = run(monkeypatch, url, dict(TARGET_PAGES, **pages))
    assert any(c["host"] == T for c in calls), [c["url"] for c in calls]
    assert_caught(result, 50)
    final = result["ioc_details"]["final_url"] or ""
    assert "www.garantibbva.com.tr" not in urls.parse(final).host if final else True
    if "iframe" not in variant and variant != "protocol-relative-backslashes":
        assert urls.parse(final).host == T, final
    if variant[0] in "cdefg":
        assert "Yönlendirme adresinde gizlenmiş karakter" in names(result["reasons"]), names(result["reasons"])


def test_e03_form_target_honours_base_and_formaction():
    """<base href> ve <button formaction> ile dis adrese gonderilen form bulgu uretir (E-03, E-17)."""
    page = doc("<h1>Üye Girişi</h1><form action='gonder'><input name=tckn placeholder='T.C. Kimlik No'>"
               "<input name=kartno placeholder='Kart numarası'><button>Giriş</button></form>",
               head=f"<base href='https://{T}/'>")
    features, _ = page_probe._inspect_html(page, "https://kekik-e03.com/v7/b3/7e")
    assert features["external_form_hosts"] == [T] and features["base_url"] == f"https://{T}/"
    page = doc("<form action='/yerel'><input name=kartno><button formaction='https://topla-e03.com/t'>Giriş</button></form>")
    features, _ = page_probe._inspect_html(page, "https://kekik-e03.com/v7/b3/7e")
    assert features["external_form_hosts"] == ["topla-e03.com"]
    score, _, reasons, _ = analyze("https://kekik-e03.com/v7/b3/7e", page=dict(features, status="ok"))
    assert "Form başka alan adına gönderiliyor" in names(reasons)
    # Bos action belgenin kendi adresidir (taban adres degil)
    page = doc("<form action=''><input name=kartno></form>", head=f"<base href='https://{T}/'>")
    assert page_probe._inspect_html(page, "https://kekik-e03.com/x")[0]["external_form_hosts"] == []


def test_e03_resolution_matches_the_whatwg_url_standard():
    base = "http://analiz-edilen.com/v7/u1/7e"
    cases = {
        "giris7": "http://analiz-edilen.com/v7/u1/giris7",
        f"/{BS}{T}/giris7": f"http://{T}/giris7",
        f"http:///{T}/giris7": f"http://{T}/giris7",
        f"http://{T}{BS}@www.garantibbva.com.tr/": f"http://{T}/@www.garantibbva.com.tr/",
        f"{BS}{BS}{T}/x": f"http://{T}/x",
        "http:yol": "http://analiz-edilen.com/v7/u1/yol",
        " \t/a\nb ": "http://analiz-edilen.com/ab",
        "//ｅxample.com/": "http://example.com/",
        "?q=1": "http://analiz-edilen.com/v7/u1/7e?q=1",
        "http://0x7f.1/": "http://127.0.0.1/",
    }
    for value, expected in cases.items():
        assert urls.resolve(base, value) == expected, value
    assert urls.resolve(base, "http://a.com:99999/") is None and urls.resolve(base, "\ud800") is None
    assert urls.is_deceptive(base, f"/{BS}{T}/x") and urls.is_deceptive(base, "http://u@a.com/")
    assert not urls.is_deceptive(base, f"images{BS}logo.png") and not urls.is_deceptive(base, "/yol?x=1")


def test_e03_fetch_connects_to_the_host_the_resolver_returned(monkeypatch):
    """Tek ayristirici: denetlenen, baglanilan ve Host basliginda gonderilen ad aynidir (SSRF farki yok)."""
    seen = {}

    def pinned(target, host, ip, port, deadline):
        seen.update(host=host, target=target.target, scheme=target.scheme)
        return page_probe._Response(200, HTML, PLAIN.encode())

    monkeypatch.setattr(page_probe, "_fetch_pinned", pinned)
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "93.184.216.34")
    page_probe._fetch_once(f"http://{T}{BS}@www.garantibbva.com.tr/a?b=1", time.monotonic() + 5)
    assert seen == {"host": T, "target": "/@www.garantibbva.com.tr/a?b=1", "scheme": "http"}


# --- E-04: XML belge ici tanimlar ------------------------------------------------------------

XHTML = {"content-type": "application/xhtml+xml"}
E04 = {
    "x1-attlist-iframe": (XHTML, "<?xml version='1.0' encoding='utf-8'?><!DOCTYPE html [<!ATTLIST iframe src CDATA "
                                 f"'https://{T}/cerceve7' style CDATA '{FULL}'>]><html xmlns='http://www.w3.org/1999/xhtml'>"
                                 "<head><title>Hoş geldiniz</title></head><body><iframe></iframe></body></html>"),
    "x2-attlist-meta": (XHTML, "<?xml version='1.0' encoding='utf-8'?><!DOCTYPE html [<!ATTLIST meta http-equiv CDATA "
                               f"'refresh' content CDATA '0; url=https://{T}/giris7'>]>"
                               "<html xmlns='http://www.w3.org/1999/xhtml'><head><title>Yükleniyor</title><meta/></head>"
                               "<body><p>Lütfen bekleyin…</p></body></html>"),
    "x3-late-xslt": ({"content-type": "application/xml"},
                     "<?xml version='1.0' encoding='utf-8'?><!--" + "x" * 5000 + "--><?xml-stylesheet type='text/xsl' "
                     "href='/v7/x3s/a'?><sayfa><not>Merhaba.</not></sayfa>"),
    # Komsu cesitler
    "css-stylesheet-pi": ({"content-type": "application/xml"},
                          "<?xml version='1.0'?><?xml-stylesheet type='text/css' href='/a.css'?><sayfa><not>Merhaba.</not></sayfa>"),
    "plain-xhtml": (XHTML, "<?xml version='1.0' encoding='utf-8'?><html xmlns='http://www.w3.org/1999/xhtml'><head>"
                           "<title>Hoş geldiniz</title></head><body><p>Merhaba.</p></body></html>"),
    "svg-document": ({"content-type": "image/svg+xml"},
                     "<svg xmlns='http://www.w3.org/2000/svg'><text>Merhaba</text></svg>"),
}


@pytest.mark.parametrize("variant", sorted(E04))
def test_e04_retest_xml_documents_are_never_fully_inspected(monkeypatch, variant):
    """Yeniden test: kapsam `partial` ve en az "Dikkat" (>= 25)."""
    headers, body = E04[variant]
    url = f"https://yasemin-e04.com/v7/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, headers, body)})
    assert coverage(result) == "partial" and result["risk_score"] >= 25, (result["risk_score"], coverage(result))
    assert "Sayfanın bir bölümü incelenemedi" in names(result["reasons"])


def test_e04_xhtml_phishing_page_is_still_found(monkeypatch):
    body = ("<?xml version='1.0' encoding='utf-8'?><html xmlns='http://www.w3.org/1999/xhtml'><head><title>Garanti BBVA"
            "</title></head><body><h1>Garanti BBVA</h1><form action='/p'><input type='password' name='sifre'/>"
            "<input name='kartno'/><div/><p>Devam</p></form></body></html>")
    url = "https://yasemin-e04.com/v7/xhtml"
    result, _ = run(monkeypatch, url, {url: (200, XHTML, body)})
    assert_caught(result)


# --- E-05: kendine yenileyen sayfa + cerez ---------------------------------------------------

def test_e05_retest_self_refresh_with_cookie_is_followed(monkeypatch):
    """Yeniden test: adres >= 50 almali; platformdan cerezli ikinci istek gorulmeli."""
    url = "https://menekse-e05.com/v7/r1/7e"

    def handler(request):
        if "v7=1" in request["cookie"]:
            return 200, HTML, doc(BODY, title="Garanti BBVA İnternet Şubesi"), []
        return 200, HTML, LOADING % f"<meta http-equiv='refresh' content='1; url={request['path']}'>", ["v7=1; Path=/"]

    result, calls = run(monkeypatch, url, handler=handler)
    assert [c["cookie"] for c in calls] == ["", "v7=1"]
    assert_caught(result)
    assert calls[1]["headers"].get("Referer") == url


def test_e05_neighbours_reload_without_url_and_counter_cookie(monkeypatch):
    def reload_handler(request):  # 'content=1': hedefsiz refresh sayfayi yeniden yukler
        if "v=1" in request["cookie"]:
            return 200, HTML, doc(BODY), []
        return 200, HTML, LOADING % "<meta http-equiv='refresh' content='1'>", ["v=1"]

    result, calls = run(monkeypatch, "https://menekse-e05.com/v7/r2", handler=reload_handler)
    assert len(calls) == 2
    assert_caught(result)

    def header_handler(request):  # Refresh yanit basligiyla, iki adimli sayac
        step = int(request["cookie"].rpartition("=")[2] or 0)
        if step >= 2:
            return 200, HTML, doc(BODY), []
        return 200, dict(HTML, refresh=f"0; url={request['url']}"), LOADING % "", [f"n={step + 1}"]

    result, calls = run(monkeypatch, "https://menekse-e05.com/v7/r3", handler=header_handler)
    assert len(calls) == 3
    assert_caught(result)


def test_e05_endless_changing_self_refresh_lowers_coverage(monkeypatch):
    def handler(request):
        n = len(request["cookie"])
        return (200, HTML, f"<html><head><title>Adım {n}</title><meta http-equiv='refresh' content='0'></head>"
                           f"<body><p>bekleyin</p></body></html>", [f"c{n}=1"])

    result, calls = run(monkeypatch, "https://menekse-e05.com/v7/r4", handler=handler)
    assert len(calls) == page_probe.MAX_SELF_REFRESH + 1
    assert coverage(result) == "partial" and "self_refresh" in result["ioc_details"]["inspection_gaps"]


# --- E-06: yoklama basliklari baglama gore uretilir ------------------------------------------

def test_e06_plain_http_request_has_no_client_hints_or_fetch_metadata():
    """Yeniden test: duz HTTP isteginde sec-ch-ua bulunmamali (Chromium yalnizca guvenli baglantida gonderir)."""
    http = dict(page_probe._request_headers("http"))
    assert not [k for k in http if k.lower().startswith(("sec-ch-ua", "sec-fetch"))]
    assert http["Accept-Encoding"] == "gzip, deflate" and http["Connection"] == "keep-alive"
    https = dict(page_probe._request_headers("https"))
    assert https["Sec-Fetch-Site"] == "none" and https["Sec-Fetch-User"] == "?1" and https["Sec-Fetch-Dest"] == "document"
    assert https["Accept-Encoding"] == "gzip, deflate, br, zstd" and "image/jxl" in https["Accept"]
    assert list(https)[:4] == ["Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]


def test_e06_retest_second_hop_and_frame_carry_referer(monkeypatch):
    """Yeniden test: Referer denetimiyle gizlenen ikinci adim ve cerceve >= 50 almali; ikinci adim ve cerceve
    isteginde Referer bulunmali."""
    phish = doc(BODY, title="Garanti BBVA İnternet Şubesi")

    def handler(request):
        path = request["path"]
        if path == "/v7/h1/7e":
            return 200, HTML, LOADING % "<meta http-equiv='refresh' content='0; url=/v7/h1b/7e'>", []
        if path == "/v7/h2/7e":
            return 200, HTML, doc(f"<iframe src='/v7/h2f/7e' style='{FULL}'></iframe>"), []
        return 200, HTML, (phish if request["headers"].get("Referer") else PLAIN), []

    result, calls = run(monkeypatch, "https://orkide-e06.com/v7/h1/7e", handler=handler)
    assert_caught(result)
    hop = calls[1]["headers"]
    assert hop["Referer"] == "https://orkide-e06.com/v7/h1/7e" and hop["Sec-Fetch-Site"] == "same-origin"
    assert "Sec-Fetch-User" not in hop and "Referer" not in calls[0]["headers"]

    result, calls = run(monkeypatch, "https://orkide-e06.com/v7/h2/7e", handler=handler)
    assert_caught(result)
    frame = calls[1]["headers"]
    assert frame["Referer"] == "https://orkide-e06.com/v7/h2/7e" and frame["Sec-Fetch-Dest"] == "iframe"
    assert "Sec-Fetch-User" not in frame


def test_e06_referrer_policy_and_site_are_computed_like_the_browser():
    nav = page_probe._nav
    assert nav("https://a.com/x?y#z", "https://a.com/b") == {
        "referer": "https://a.com/x?y", "site": "same-origin", "dest": "document", "user": False}
    assert nav("https://a.com/x", "https://b.a.com/")["site"] == "same-site"
    assert nav("https://a.com/x", "https://b.a.com/")["referer"] == "https://a.com/"
    assert nav("https://a.com/x", "https://baska.com/")["site"] == "cross-site"
    assert nav("https://a.com/x", "http://baska.com/")["referer"] is None  # https -> http: Referer gonderilmez
    # HTTP yonlendirmesi (3xx) baglami degistirmez: adres cubuguna yazilan istek 'none' kalir (run() ile sinanir)


def test_e06_browser_profile_is_recorded_and_fresh():
    """Baslik kumesi gercek tarayicidan kaydedilir; kayit eskidiginde bu test hatirlatir (rapor 7.6)."""
    profile = json.loads((ROOT / "backend/data/chrome_headers.json").read_text(encoding="utf-8"))
    from backend.config import settings

    assert settings.PROBE_CHROME_MAJOR >= 156 and profile["chrome_major"] >= 156
    assert f"Chrome/{settings.PROBE_CHROME_MAJOR}." in dict(page_probe._request_headers("http"))["User-Agent"]
    age = (date.today() - date.fromisoformat(profile["recorded"])).days
    assert age <= 365, f"chrome_headers.json {age} gun once kaydedildi; guncel Chrome ile yeniden kaydedin"


def test_e06_brotli_and_zstd_bodies_are_decoded_with_a_size_limit():
    import brotli
    import zstandard

    body = doc(BODY).encode("utf-8")
    assert page_probe._decode_body(brotli.compress(body), "br") == body
    assert page_probe._decode_body(zstandard.ZstdCompressor().compress(body), "zstd") == body
    bomb = b"a" * 30_000_000
    assert len(page_probe._decode_body(brotli.compress(bomb), "br")) <= page_probe.MAX_BYTES
    assert len(page_probe._decode_body(zstandard.ZstdCompressor().compress(bomb), "zstd")) <= page_probe.MAX_BYTES
    assert page_probe._decode_body(b"bozuk", "br") == b"" and page_probe._decode_body(b"bozuk", "zstd") == b""


# --- E-07: gorunur kurum adi "gizli" sayiliyor ---------------------------------------------

NAME = "Garanti BBVA İnternet Şubesi"
E07 = {
    "a-custom-property": doc(f"<h1 style='--x:display:none'>{NAME}</h1>" + PW),
    "b-visibility-child": doc(f"<div style='visibility:hidden'><h1 style='visibility:visible'>{NAME}</h1></div>" + PW),
    "c-p-hidden-autoclose": doc(f"<p hidden><h1>{NAME}</h1>" + PW),
    "d-later-declaration": doc(f"<h1 style='display:none;display:block'>{NAME}</h1>" + PW),
    # Komsu cesitler: sezgi "gizli" dese de ad bulunur (birlesim ilkesi)
    "hidden-attr-overridden-by-css": doc(f"<h1 hidden class=g>{NAME}</h1>" + PW, head="<style>.g{display:block}</style>"),
    "opacity-animated": doc(f"<h1 style='opacity:0;animation:g 0s forwards'>{NAME}</h1>" + PW),
    "font-size-reset": doc(f"<div style='font-size:0'><h1 style='font-size:24px'>{NAME}</h1></div>" + PW),
    "display-none-important-class": doc(f"<div style='display:none' class=g><h2>{NAME}</h2></div>" + PW,
                                        head="<style>.g{display:block!important}</style>"),
}


@pytest.mark.parametrize("variant", sorted(E07))
def test_e07_retest_brand_name_in_html_is_found_whatever_the_style_says(monkeypatch, variant):
    """Yeniden test: ad HTML'de varsa sonuc >= 75 olmali."""
    url = f"https://nar-e07.com/v7/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, E07[variant])})
    assert_caught(result)


def test_e07_brand_written_with_css_content_is_found_or_reported(monkeypatch):
    """Yeniden test (e): ad HTML'de yok, ::before ile yaziliyor: en azindan kapsam `partial` olmali."""
    for i, css in enumerate((".b::before{content:'Garanti BBVA İnternet Şubesi'}",
                             ".b::after{content:\"Garanti \" \"BBVA\"}",
                             ".b::before{content:'\\47 aranti BBVA'}")):
        url = f"https://nar-e07.com/v7/c5-{i}"
        result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<h1 class='b'></h1>" + PW, head=f"<style>{css}</style>"))})
        assert_caught(result)
    # Kimlik yalnizca dis stil sayfasinda / gorselde: bulunamaz, ama "tam incelendi, Dusuk risk" de olmaz
    url = "https://nar-e07.com/v7/c6"
    page = doc("<h1 class='b'></h1><img src='/logo.png'>" + PW, head="<link rel=stylesheet href='/s.css'>")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_level"] == "UNKNOWN" and coverage(result) == "partial"
    assert "unverified_form" in result["ioc_details"]["inspection_gaps"]
    assert "Kimliği doğrulanamayan giriş formu" in names(result["reasons"])


def test_e07_hiding_heuristic_still_ignores_hidden_filler_for_thresholds():
    """A-02/A-03 korunur: gizli dolgu metni gorunur metin sayilmaz; ad her iki gorunumde de aranir."""
    page = doc("<h1>Gar<span style='display:none'>xyz</span>anti BBVA</h1><div style='display:none'>" + "dolgu " * 200 + "</div>")
    features, _ = page_probe._inspect_html(page, "https://nar-e07.com/")
    assert features["identity"][-1] == "Garanti BBVA" and len(features["text"]) < 50
    assert "dolgu" in features["text_all"] and "Garxyzanti BBVA" in features["identity_all"]
    decls = html_extract._declarations
    assert decls("--x:display:none") == {} and decls("display:none;display:block") == {"display": "block"}
    assert decls("display:none!important;display:block")["display"] == "none"
    assert decls("background:url(a;b);COLOR:Red")["color"] == "red"


# --- E-08: govdede ikinci bir kurum adi -------------------------------------------------------

LOGO = "<div class='logo'>Garanti BBVA</div><h2>İnternet Şubesi Girişi</h2>"
FOOT = "<p style='font-size:11px;color:#888'>%s</p>"


@pytest.mark.parametrize("footer", [
    "",
    "Akbank, Garanti BBVA ve diğer bankaların kartları geçerlidir.",
    "Akbank, Garanti BBVA, Yapı Kredi ve Ziraat Bankası kartları geçerlidir.",
])
def test_e08_retest_second_brand_in_body_does_not_disable_detection(monkeypatch, footer):
    """Yeniden test: >= 75; ayni sayfada uc banka adi gectiginde de sonuc degismemeli."""
    url = "https://funda-e08.com/v7/m1"
    page = doc(LOGO + PW + (FOOT % footer if footer else ""), title="İnternet Şubesi")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Garanti BBVA"


def test_e08_no_dominant_brand_is_reported_at_attention_level(monkeypatch):
    """Baskin kurum yoksa (odeme sayfalari da boyle gorunur) kesin kanit degil, "Dikkat" duzeyinde bulgu."""
    url = "https://funda-e08.com/v7/m1x"
    card = ("<form action='/post' method=post><input name=adsoyad placeholder='Ad Soyad'>"
            "<input name=kartno placeholder='Kart numarası'><input name=cvv><button>Öde</button></form>")
    page = doc("<h2>Ödeme</h2>" + card + FOOT % "Akbank ve Garanti BBVA kartlarına taksit yapılır.", title="Ödeme")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert 25 <= result["risk_score"] < 75 and result["risk_level"] != "LOW"
    assert "Birden fazla kurum kimliği taşıyan form" in names(result["reasons"])
    # Giris formunda da ayni (adin gectigi yer ayirt etmiyorsa): "Dusuk risk" olamaz
    page = doc("<p>Garanti BBVA</p>" + PW + FOOT % "Akbank kartları da geçerlidir.", title="Giriş")
    result, _ = run(monkeypatch, url + "2", {url + "2": (200, HTML, page)})
    assert 25 <= result["risk_score"] and result["risk_level"] not in ("LOW", "UNKNOWN")
    assert "Birden fazla kurum kimliği taşıyan form" in names(result["reasons"])


def test_e08_multi_brand_page_without_a_sensitive_form_is_not_evidence(monkeypatch):
    """Karsi ornek: cok markali mesru sayfa (karsilastirma, haber) kurum sayisiyla degil sayfa turuyle elenir."""
    url = "https://karsilastir-e08.com/kredi"
    text = "<p>" + "Akbank, Garanti BBVA ve Yapı Kredi konut kredisi faiz oranlarını açıkladı. " * 30 + "</p>"
    page = doc("<h1>Konut kredisi karşılaştırma</h1>" + text + "<form action='/ara'><input name=q></form>", title="Kredi")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_score"] < 25 and result["ioc_details"]["target_brand"] is None


# --- E-09: buyuk harf benzer karakterler -------------------------------------------------------

def test_e09_retest_uppercase_lookalikes_are_normalised():
    """Yeniden test: E-09_ek tablosundaki butun yazimlar beklenen degere indirgenmeli."""
    table = {"AKBANK": "akbank", "AKΒANK": "akbank", "GARANTİ ΒΒVA": "garanti bbva",
             "ΗALKBANK": "halkbank", "ΖİRAAT BANKASI": "ziraat bankasi", "ΜİGROS": "migros",
             "ΕΝPARA": "enpara",
             # Komsu: Kiril buyuk harfler, Yunan Iota, tam genislikli harfler
             "АКВАНК": "akbahk".replace("h", "h"), "GARANTΙ BBVA": "garanti bbva",
             "ＡＫＢＡＮＫ": "akbank", "YΑPI KREDİ": "yapi kredi"}
    for written, expected in table.items():
        assert normalize_text(written) == expected, (written, normalize_text(written))
    # Onceki davranis korunur
    assert normalize_text("İş Bankası") == "is bankasi" and normalize_text("аkbank") == "akbank"
    assert normalize_text("garantibbva.com.tr") == "garantibbva.com.tr"


@pytest.mark.parametrize("name", ["AKΒANK", "ΑKΒΑNK", "АКБANK"])
def test_e09_retest_brand_written_with_lookalikes_is_found(monkeypatch, name):
    """Yeniden test: >= 75. Son cesit tabloda karsiligi olmayan bir harf (Kiril Б) tasir: genel yedek denetim."""
    url = "https://funda-e09.com/v7/m2"
    page = doc(f"<h1>{name} İnternet Şubesi</h1>" + PW, title=f"{name} İnternet Şubesi")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Akbank"
    assert "Kurum adı gizlenerek yazılmış" in names(result["reasons"])


def test_e09_mixed_script_is_not_flagged_for_plain_turkish_text():
    assert not page_probe._mixed_script("Türkiye İş Bankası İnternet Şubesi çığ öğün")
    assert page_probe._mixed_script("AKΒANK") and not page_probe._mixed_script("Αθήνα Athens")


# --- E-10: <label> disindaki alan aciklamalari -------------------------------------------------

E10 = {
    "div-captions": ("<form action='/post' method=post><div>Müşteri / T.C. Kimlik Numarası</div><input type=text name=f1>"
                     "<div>Parola</div><input type=text name=f2 style='-webkit-text-security:disc'><button>Giriş</button></form>"),
    "table-cells": ("<form action='/post'><table><tr><td>Kullanıcı adı</td><td><input name=f1></td></tr>"
                    "<tr><td>Şifre</td><td><input name=f2></td></tr></table><button>Giriş</button></form>"),
    "span-inline": "<form action='/post'><span>Parola:</span> <input name=f2><button>Giriş</button></form>",
    "aria-labelledby": "<form action='/post'><b id='e1'>Şifreniz</b><p>-</p><input name=f2 aria-labelledby='e1'><button>Giriş</button></form>",
    "masked-only": "<form action='/post'><input name=f1><input name=f2 style='-webkit-text-security: disc'><button>Giriş</button></form>",
}


@pytest.mark.parametrize("variant", sorted(E10))
def test_e10_retest_fields_are_recognised_from_surrounding_text(monkeypatch, variant):
    """Yeniden test: >= 75 ve "istenen" alaninda en azindan parola gorunmeli."""
    url = f"https://funda-e10.com/v7/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(LOGO + E10[variant], title="İnternet Şubesi"))})
    assert "Şifre" in result["ioc_details"]["page_fields"], result["ioc_details"]["page_fields"]
    assert_caught(result)


def test_e10_body_brand_is_searched_without_a_recognised_sensitive_field(monkeypatch):
    """Govdedeki kurum adi form tanimadan bagimsiz aranir: taninan hassas alan yalnizca agirligi artirir."""
    url = "https://funda-e10.com/v7/taninmayan"
    form = "<form action='/post'><input name=f1><input name=f2><button>Devam</button></form>"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(LOGO + form, title="İnternet Şubesi"))})
    assert result["ioc_details"]["page_fields"] == [] and result["risk_level"] != "LOW"
    assert "Sayfa Garanti BBVA kimliği taşıyor" in names(result["reasons"])


# --- E-11: sahip muafiyeti yalnizca guvenilen adreslerde ---------------------------------------

@pytest.mark.parametrize("suffix", ["", " - Gmail", " - Google Docs", " | Google Forms"])
def test_e11_retest_owner_product_name_does_not_disable_identity_check(monkeypatch, suffix):
    """Yeniden test: basliga alan sahibinin urun adi eklenen sayfa kontrol sayfasiyla ayni sonucu vermeli."""
    url = "https://docs.google.com/v7/m7/7e"
    body = "<h1>Garanti BBVA Müşteri Doğrulama</h1>" + PW + "<script src='/static/forms.js'></script>"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(body, title="Garanti BBVA Müşteri Doğrulama" + suffix))})
    assert_caught(result, 85)
    assert result["ioc_details"]["target_brand"] == "Garanti BBVA"


def test_e11_owner_exemption_still_applies_on_the_owners_own_site(monkeypatch):
    """Karsi ornek: kurumun kendi (guvenilen) adresinde ortak kurumlarin anilmasi bulgu degildir."""
    url = "https://www.garantibbva.com.tr/kampanyalar"
    page = doc("<h1>Garanti BBVA Bonus ile Trendyol alışverişlerinde indirim</h1><p>Kampanya koşulları.</p>" + PW,
               title="Garanti BBVA - Trendyol kampanyası")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_score"] < 25 and result["risk_level"] == "LOW"


# --- E-12: iki sayfali oltalama kiti ---------------------------------------------------------

LURE = ("<!doctype html><html><head><meta charset='utf-8'><title>Garanti BBVA - Hesap Bildirimi</title></head><body>"
        "<h1>Garanti BBVA</h1><p>Hesabınızda olağan dışı işlem tespit edildi. Kısıtlamayı kaldırmak için "
        "kimliğinizi doğrulayın.</p>%s</body></html>")
E12 = {
    "a-internal-link": "<p><a href='/v7/k/7e'>Kimliğimi doğrula</a></p>",
    "b-area-external": ("<img src='/dugme.png' alt='' usemap='#m' width='300' height='60'><map name='m'>"
                        "<area shape='rect' coords='0,0,300,60' href='https://garanti-dogrulama-merkezi.xyz/giris'></map>"),
    # Komsu cesitler
    "internal-link-without-cta-words": "<p><a href='/v7/k/7e'>Devam etmek için tıklayın</a></p>",
    "area-internal": "<img src='/d.png' usemap='#m'><map name='m'><area href='/v7/k/7e' alt='Devam'></map>",
}


@pytest.mark.parametrize("variant", sorted(E12))
def test_e12_retest_lure_page_is_decisive_and_its_link_is_followed(monkeypatch, variant):
    """Yeniden test: HTTPS uzerinden de >= 50."""
    url = f"https://leylak-e12.com/v7/{variant}"
    pages = {url: (200, HTML, LURE % E12[variant]), "https://leylak-e12.com/v7/k/7e": (200, HTML, doc(BODY))}
    result, calls = run(monkeypatch, url, pages)
    assert_caught(result, 50)
    assert "Sayfa Garanti BBVA kimliği taşıyor" in names(result["reasons"])
    if "internal" in variant:
        assert "https://leylak-e12.com/v7/k/7e" in [c["url"] for c in calls]
        assert "Bağlantının gittiği sayfa: Hassas bilgi toplayan form" in names(result["reasons"])
        assert_caught(result, 85)


def test_e12_news_article_mentioning_a_brand_is_still_a_mention(monkeypatch):
    """Karsi ornek (B-10): uzun metinli, cok baglantili haber sayfasi "yalnizca ad geciyor" indirimini alir."""
    url = "https://haber-e12.com/ekonomi/garanti"
    nav = "".join(f"<a href='/kategori/{i}'>Kategori {i}</a>" for i in range(12))
    page = doc(nav + "<h1>Garanti BBVA yeni faiz oranlarını açıkladı</h1><p>" + "Haber metni devam ediyor. " * 120 + "</p>",
               title="Garanti BBVA yeni faiz oranlarını açıkladı - Haber")
    result, calls = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_score"] < 25 and len(calls) == 1
    assert "Sayfa başlığında Garanti BBVA adı geçiyor" in names(result["reasons"])


# --- E-13: kisitli uzantidaki incelenemeyen sayfa ---------------------------------------------

SCRIPTED = ("<!doctype html><html><head><meta charset='utf-8'><title>Yükleniyor</title></head><body><div id='k'></div>"
            "<script>document.getElementById('k').innerHTML = atob('PGgxPkdhcmFudGk8L2gxPg==')</script></body></html>")


@pytest.mark.parametrize("host", ["okul-z09.k12.tr", "ornek.bel.tr", "bolum.ornek.edu.tr", "kurum.gov.tr"])
def test_e13_retest_uninspectable_page_on_restricted_suffix_is_not_low(monkeypatch, host):
    """Yeniden test: "Karar verilemedi" ya da en az "Dikkat"; "resmi uzanti" guveni verilmemeli."""
    url = f"https://{host}/r6/7e"
    result, _ = run(monkeypatch, url, {url: (200, HTML, SCRIPTED)})
    assert result["risk_level"] in ("UNKNOWN", "MEDIUM", "HIGH", "CRITICAL"), result["risk_level"]
    assert "Kısıtlı resmi uzantı" not in names(result["reasons"])
    assert "Sayfa içeriği betikle üretiliyor; incelenemedi" in names(result["reasons"])
    assert result["risk_score"] >= 25


def test_e13_static_page_on_restricted_suffix_stays_low(monkeypatch):
    """Yeniden test: ayni alan adindaki betiksiz, formsuz sayfa "Dusuk risk" almaya devam etmeli."""
    url = "https://okul-z09.k12.tr/duyurular"
    page = doc("<h1>Okulumuz</h1><p>Veli toplantısı cuma günü yapılacaktır.</p>", title="Okul duyuruları")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_level"] == "LOW" and coverage(result) == "full"
    # Ulasilamayan / indirilemeyen sayfa hakkinda da hukum verilmez
    result, _ = run(monkeypatch, url + "x", handler=lambda r: (_ for _ in ()).throw(page_probe._FetchError("x")))
    assert result["risk_level"] == "UNKNOWN" and "Kısıtlı resmi uzantı" not in names(result["reasons"])


# --- E-14: engel listesi yonlendirme zincirine ve cercevelere uygulanir ----------------------

@pytest.fixture()
def blocked_domain():
    from backend.models.database import SessionLocal, init_db
    from backend.models.list_model import ListModel

    init_db()
    db = SessionLocal()
    rules = [ListModel(list_type="blacklist", entry_type="domain", pattern="sogut-e14.com", description="e14"),
             ListModel(list_type="blacklist", entry_type="url", pattern="kovan-e14.com/kit/giris", description="e14u")]
    for rule in rules:
        db.add(rule)
    db.commit()
    try:
        yield db
    finally:
        for rule in rules:
            db.delete(rule)
        db.commit()
        db.close()


E14 = {
    "a-http-redirect": {"https://sedir-e14.com/v7/a": (302, {"location": "https://sogut-e14.com/v7/z/cerceve7"}, b"")},
    "b-meta-refresh": {"https://sedir-e14.com/v7/b": (200, HTML, LOADING % (
        "<meta http-equiv='refresh' content='0; url=https://sogut-e14.com/v7/z/cerceve7'>"))},
    "c-iframe": {"https://sedir-e14.com/v7/c": (200, HTML, doc(
        f"<iframe src='https://sogut-e14.com/v7/z/cerceve7' style='{FULL}'></iframe>"))},
    # Komsu cesitler
    "subdomain-two-hops": {"https://sedir-e14.com/v7/d": (302, {"location": "https://ara-e14.com/x"}, b""),
                           "https://ara-e14.com/x": (302, {"location": "https://giris.sogut-e14.com/"}, b"")},
    "url-rule-via-refresh": {"https://sedir-e14.com/v7/e": (200, HTML, LOADING % (
        "<meta http-equiv='refresh' content='0; url=https://kovan-e14.com/kit/giris/index.html?x=1'>"))},
    "frame-beyond-limit": {"https://sedir-e14.com/v7/f": (200, HTML, doc(
        "".join(f"<iframe src='/bos{i}'></iframe>" for i in range(4))
        + "<iframe src='https://sogut-e14.com/v7/z/cerceve7'></iframe>"))},
    "lure-link": {"https://sedir-e14.com/v7/g": (200, HTML, LURE % "<a href='https://sogut-e14.com/giris'>Kimliğimi doğrula</a>")},
}


@pytest.mark.parametrize("variant", sorted(E14))
def test_e14_retest_blocked_domain_is_caught_behind_redirects_and_frames(monkeypatch, blocked_domain, variant):
    """Yeniden test: engellenen alan adina goturen adresler "Engel listesi eslesmesi" ile 100 puan almali."""
    url = next(iter(E14[variant]))
    result, _ = run(monkeypatch, url, E14[variant], db=blocked_domain)
    assert result["risk_score"] == 100 and result["risk_level"] == "CRITICAL", (result["risk_score"], names(result["reasons"]))
    assert result["reasons"][0]["rule_name"] == "Engel listesi eşleşmesi"
    assert "yönlendirme zincirindeki ya da çerçevedeki bir adım" in result["reasons"][0]["description"]


def test_e14_unrelated_chain_is_not_blocked(monkeypatch, blocked_domain):
    url = "https://sedir-e14.com/v7/temiz"
    pages = {url: (302, {"location": "https://baska-e14.com/"}, b""),
             "https://baska-e14.com/": (200, HTML, doc("<p>sogut-e14.com hakkında bir yazı.</p>"))}
    result, _ = run(monkeypatch, url, pages, db=blocked_domain)
    assert result["risk_score"] < 100 and "Engel listesi eşleşmesi" not in names(result["reasons"])


# --- E-15: kullanici bilgisinde ASCII disi karakter ---------------------------------------------

@pytest.mark.parametrize("raw", ["http://evil-site.com＼@www.garantibbva.com.tr/",
                                 "http://kullanıcı@www.garantibbva.com.tr/",
                                 "http://\U0001f600:şifre@www.garantibbva.com.tr/x"])
def test_e15_retest_non_ascii_userinfo_is_analysed(monkeypatch, raw):
    """Yeniden test: HTTP 200 ve "URL icinde '@' yonlendirmesi" bulgusu (HTTP 500 degil)."""
    parsed = parse_url_components(raw)
    assert parsed["domain"] == "www.garantibbva.com.tr" and parsed["authority"].isascii() and parsed["userinfo"]
    result, _ = run(monkeypatch, raw, {})
    assert "URL içinde '@' yönlendirmesi" in names(result["reasons"])
    assert result["url"].isascii() and result["risk_level"] != "LOW"


def test_e15_url_parser_only_raises_invalid_target_error():
    """Ozellik testi: rastgele Unicode girdilerde islev ya sonuc dondurur ya InvalidTargetError firlatir."""
    rng = random.Random(7)
    alphabet = ["a", "b", ".", "/", ":", "@", "\\", "?", "#", "%", "[", "]", " ", "\t", "ı", "ş", "＼", "＠", "‮",
                "Β", "\U0001f600", "\ud800", "\x00", "com", "http", "https", "//", "xn--", "%zz", "%41", "0x7f", "１", "。"]
    for _ in range(4000):
        raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
        for candidate in (raw, "http://" + raw, "http://" + raw + "@ornek.com/", "ornek.com/" + raw):
            try:
                result = parse_url_components(candidate)
            except InvalidTargetError:
                continue
            assert result["domain"] and (result["authority"] + result["rest"]).isascii(), candidate


# --- E-16: imaj taramasi ------------------------------------------------------------------------

def test_e16_scan_failure_is_recorded_as_a_dated_risk_acceptance():
    """Yeniden test: tarama, guncelleme ya da gerekceli ve SURELI kabul ile basarili olmali."""
    text = (ROOT / ".trivyignore.yaml").read_text(encoding="utf-8")
    entries = text.split("  - id: ")
    matching = [e for e in entries if e.startswith("CVE-2026-97054")]
    assert len(matching) == 2, "caddy ve gosu icin birer kayit"
    assert any("usr/bin/caddy" in e for e in matching) and any("usr/local/bin/gosu" in e for e in matching)
    for entry in matching:
        assert "statement:" in entry and "expired_at:" in entry
    caddy = next(e for e in matching if "usr/bin/caddy" in e)
    expiry = date.fromisoformat(caddy.split("expired_at:")[1].split()[0])
    assert expiry <= date(2026, 12, 31), "internete acik bilesen icin kabul kisa sureli olmali"
    workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert 'cron: "0 5 * * *"' in workflow, "imaj taramasi her gun calismali"


# --- E-17: ek gozlemler ---------------------------------------------------------------------------

def test_e17_migration_carries_the_level_together_with_the_score(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, text

    from backend.models import database

    engine = create_engine(f"sqlite:///{tmp_path}/eski.db", future=True)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE iocs (id INTEGER PRIMARY KEY, type VARCHAR(50), value TEXT, value_hash VARCHAR(64), "
                          "risk_score INTEGER, risk_level VARCHAR(20))"))
        conn.execute(text("CREATE TABLE analysis_results (id INTEGER PRIMARY KEY, ioc_id INTEGER, risk_score INTEGER)"))
        for table in ("domains", "ip_addresses", "urls"):
            conn.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, ioc_id INTEGER)"))
        for i, score, level in ((1, 15, "LOW"), (2, 86, "CRITICAL"), (3, 40, "MEDIUM")):
            conn.execute(text("INSERT INTO iocs VALUES (:i, 'url', 'http://x/', 'h1', :s, :l)"), {"i": i, "s": score, "l": level})
    monkeypatch.setattr(database, "engine", engine)
    database.migrate_ioc_unique()
    with engine.begin() as conn:
        assert conn.execute(text("SELECT id, risk_score, risk_level FROM iocs")).fetchall() == [(1, 86, "CRITICAL")]


def test_e17_area_links_count_as_links_and_dead_code_is_gone():
    page = doc("<p>kısa</p><map name=m><area href='https://dis-e17.com/giris' alt='Giriş yap'></map>")
    features, _ = page_probe._inspect_html(page, "https://x-e17.com/")
    assert features["external_links"] == ["dis-e17.com"] and features["prominent_external_link"]
    source = (ROOT / "backend/core/page_probe.py").read_text(encoding="utf-8")
    assert "def encoding(self)" not in source and "urljoin" not in source
