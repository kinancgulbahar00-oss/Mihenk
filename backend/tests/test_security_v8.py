"""Guvenlik zafiyet raporu (8) — G-01..G-13 icin regresyon testleri. Ag erisimi gerektirmez.

Her bulgu icin raporun "Yeniden test" olcutu ve komsu cesitler, laboratuvar yerine sahte ag katmaniyla sinanir. Test
sayfalari rapordaki kanit sayfalarinin (rapor/kanitlar_v8/araclar/r8.py) aynisidir. Analizler gecerli TLS ile
calistirilir (rapordaki "Sifresiz baglanti" katkisi yoktur).

Uc genel kural (rapor 7.1, 7.3):
  * Olumlu kanit olmadan "Dusuk risk" yok: kimligi belirlenemeyen hassas form en az "Karar verilemedi"dir.
  * Gomulu belge ve yenileme icin tek kural: `src`/`srcdoc`, <meta>/baslik ayni yoldan gecer.
  * Birlesim ilkesi: kurum adi butun gorunumlerde (oznitelik, ayracsiz, benzer harf, ters, harf harf) aranir.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import html as html_lib
import json
import threading
import time
from pathlib import Path

import pytest

from backend.core import netguard, page_probe, urls
from backend.sandbox import html_extract
from backend.sandbox import pool as parse_pool
from backend.tests.test_security_v6 import _page_fetch, names  # noqa: F401  (_page_fetch: autouse fixture)
from backend.tests.test_security_v7 import (BODY, CARD, FULL, HTML, LOADING, PLAIN, PW, T, assert_caught, coverage, doc, run)

ROOT = Path(__file__).resolve().parents[2]
NAME = "Garanti BBVA İnternet Şubesi"
TARGET = {f"https://{T}/giris8": (200, HTML, doc(CARD, title=NAME))}


def not_low(result):
    assert result["risk_level"] != "LOW", (result["risk_score"], coverage(result), names(result["reasons"]))


def srcdoc(inner, attrs=f"style='{FULL}'"):
    return doc(f"<iframe srcdoc=\"{html_lib.escape(inner, quote=True)}\" {attrs}></iframe>")


# --- G-01: srcdoc cercevesinin icindeki gezinme ------------------------------------------------

G01 = {
    "a-meta-refresh": srcdoc(f"<meta http-equiv='refresh' content='0; url=https://{T}/giris8'>"),
    "base-and-relative-refresh": srcdoc(f"<base href='https://{T}/'><meta http-equiv='refresh' content='0; url=giris8'>"),
    "nested-iframe": srcdoc(f"<iframe src='https://{T}/giris8' style='{FULL}'></iframe>"),
    "delayed-refresh": srcdoc(f"<p>Yükleniyor</p><meta http-equiv='refresh' content='5; url=https://{T}/giris8'>"),
}


@pytest.mark.parametrize("variant", sorted(G01))
def test_g01_retest_navigation_inside_srcdoc_frame_is_followed(monkeypatch, variant):
    """Yeniden test: srcdoc belgesinin yonlendirmesi ve cercevesi `src` cercevesiyle ayni kurala baglidir (>= 50)."""
    url = f"https://papatya-g01.com/v8/{variant}"
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, G01[variant])}))
    assert f"https://{T}/giris8" in [c["url"] for c in calls]
    assert_caught(result, 50)
    assert any(n.startswith("Çerçevedeki sayfa:") for n in names(result["reasons"]))


def test_g01_unfollowable_srcdoc_navigation_is_never_a_full_inspection(monkeypatch):
    for i, inner in enumerate(("<meta http-equiv='refresh' content='0; url=javascript:x'>",
                               "<meta http-equiv='refresh' content='0; url=https://yok-g01.com/x'>")):
        url = f"https://papatya-g01.com/v8/x{i}"
        result, _ = run(monkeypatch, url, {url: (200, HTML, srcdoc(inner)),
                                           "https://yok-g01.com/x": (200, {"content-type": "application/pdf"}, b"%PDF")})
        assert coverage(result) == "partial" and result["risk_level"] != "LOW"
    # Karsi ornek: icinde gezinme olmayan srcdoc cercevesi tam incelenir
    url = "https://papatya-g01.com/v8/duz"
    result, calls = run(monkeypatch, url, {url: (200, HTML, srcdoc("<p>Merhaba</p>"))})
    assert coverage(result) == "full" and len(calls) == 1


# --- G-02: kendine yenileme ---------------------------------------------------------------------

def test_g02_retest_refresh_header_without_url_reloads_the_document(monkeypatch):
    """Yeniden test (a): 'Refresh: 1' (adres yok) sayfayi yeniden yukler; cerezli ikinci istek gorulmeli."""
    def handler(request):
        if "v8=1" in request["cookie"]:
            return 200, HTML, doc(BODY, title=NAME), []
        return 200, dict(HTML, refresh="1"), LOADING % "", ["v8=1; Path=/"]

    result, calls = run(monkeypatch, "https://menekse-g02.com/v8/r2/x", handler=handler)
    assert [c["cookie"] for c in calls] == ["", "v8=1"]
    assert_caught(result)


def test_g02_retest_server_side_counter_is_outlasted(monkeypatch):
    """Yeniden test (b): cerez yok; sunucu ilk iki istege ayni "Yukleniyor" sayfasini, ucuncuye asil sayfayi verir."""
    seen = []

    def handler(request):
        seen.append(request["url"])
        if len(seen) >= 3:
            return 200, HTML, doc(BODY, title=NAME), []
        return 200, HTML, LOADING % f"<meta http-equiv='refresh' content='0; url={request['path']}'>", []

    result, calls = run(monkeypatch, "https://menekse-g02.com/v8/r1/x", handler=handler)
    assert len(calls) == 3
    assert_caught(result)


def test_g02_quick_self_refresh_that_never_changes_is_not_a_full_inspection(monkeypatch):
    """Kisa gecikmeli, hic degismeyen kendine yenileme (sure ya da daha uzun sayac): "tam incelendi" sayilmaz."""
    def handler(request):
        return 200, HTML, LOADING % "<meta http-equiv='refresh' content='0'>", []

    result, calls = run(monkeypatch, "https://menekse-g02.com/v8/r9/x", handler=handler)
    assert len(calls) == page_probe.MAX_SELF_REFRESH + 1
    assert coverage(result) == "partial" and "self_refresh" in result["ioc_details"]["inspection_gaps"]
    not_low(result)

    # Uzun gecikmeli kendini yenileme bir kez sinanir; gecikme BEKLENMEDIGI icin "tam incelendi" sayilmaz (9. tur)
    def news(request):
        return 200, HTML, doc("<h1>Canlı yayın</h1><p>" + "Haber metni. " * 60 + "</p>",
                              head="<meta http-equiv='refresh' content='60'>"), []

    result, calls = run(monkeypatch, "https://haber-g02.com/canli", handler=news)
    assert len(calls) == 2 and coverage(result) == "partial" and result["risk_level"] != "LOW"


def test_g02_meta_and_header_refresh_share_one_rule():
    assert page_probe._first_refresh(["1"]) == (1, "", False)
    assert page_probe._first_refresh(["0; url=/x"]) == (0, "/x", False)
    assert page_probe._first_refresh(["600; url=/x"]) == (0, None, True)
    assert page_probe._first_refresh(["abc", "2;/y"]) == (2, "/y", False)


# --- G-03: cerez ve yonlendiren kurallari -------------------------------------------------------

def test_g03_retest_domain_cookie_is_carried_to_the_subdomain(monkeypatch):
    """Yeniden test (a): Domain=ust alan adi ile verilen cerez alt alan adina tasinir."""
    def handler(request):
        if request["host"] == "zeytin-g03.com":
            return 302, {"location": "https://giris.zeytin-g03.com/v8/c1b/x"}, b"", ["v8=1; Domain=zeytin-g03.com; Path=/"]
        return 200, HTML, (doc(BODY, title=NAME) if "v8=1" in request["cookie"] else PLAIN), []

    result, calls = run(monkeypatch, "https://zeytin-g03.com/v8/c1/x", handler=handler)
    assert calls[1]["cookie"] == "v8=1"
    assert_caught(result)


def test_g03_retest_cookie_with_other_path_is_not_sent(monkeypatch):
    """Yeniden test (b): Path'i uymayan cerez gonderilmez (tarayici gibi)."""
    def handler(request):
        if "v8=1" not in request["cookie"]:
            return (200, HTML, LOADING % f"<meta http-equiv='refresh' content='1; url={request['path']}'>",
                    ["v8=1; Path=/", "tuzak=1; Path=/baska-yol"])
        return 200, HTML, (PLAIN if "tuzak=1" in request["cookie"] else doc(BODY, title=NAME)), []

    result, calls = run(monkeypatch, "https://zeytin-g03.com/v8/c2/x", handler=handler)
    assert calls[1]["cookie"] == "v8=1"
    assert_caught(result)


def test_g03_cookie_jar_follows_browser_rules():
    state = {"cookies": []}
    token = page_probe._probe_state.set(state)
    try:
        store, header = page_probe._store_cookies, page_probe._cookie_header
        store("a.ornek-g03.com", ["s=1", "d=2; Domain=ornek-g03.com", "p=3; Path=/hesap", "sec=4; Secure",
                                  "x=5; Domain=baska-g03.com", "t=6; Domain=com", "e=7; Max-Age=0"], "/giris/form", False)
        assert header("a.ornek-g03.com", "/giris/x") == "s=1; d=2"          # varsayilan yol: /giris
        assert header("a.ornek-g03.com", "/baska") is None                     # varsayilan yol uymuyor
        assert header("b.ornek-g03.com", "/giris/y") == "d=2"                  # Domain cerezi alt alan adina gider
        assert header("a.ornek-g03.com", "/hesap/1") == "p=3"
        assert header("ornek-g03.com.tr", "/") is None
        # Secure cerez duz HTTP uzerinden kabul edilmez; HTTPS'te kabul edilir ve yalnizca HTTPS'e gonderilir
        store("a.ornek-g03.com", ["sec=4; Secure; Path=/"], "/", True)
        assert "sec=4" in header("a.ornek-g03.com", "/", True) and "sec=4" not in (header("a.ornek-g03.com", "/", False) or "")
        # Max-Age=0 mevcut cerezi siler; ayni adli cerez gunceller
        store("a.ornek-g03.com", ["d=9; Domain=ornek-g03.com", "s=; Max-Age=0; Path=/giris"], "/giris/form", False)
        assert header("a.ornek-g03.com", "/giris/x") == "d=9"
        # Paylasimli sonek ("public suffix") icin cerez kabul edilmez
        store("kurban.blogspot.com", ["z=1; Domain=blogspot.com"], "/", False)
        assert header("baska.blogspot.com", "/") is None
    finally:
        page_probe._probe_state.reset(token)


@pytest.mark.parametrize("how", ["header", "meta"])
def test_g03_retest_referrer_policy_is_honoured(monkeypatch, how):
    """Yeniden test (c): 'no-referrer' ilkesi altinda ikinci istekte Referer gonderilmez."""
    def handler(request):
        if request["path"].endswith("/p1"):
            head = "<meta http-equiv='refresh' content='0; url=/v8/p1b'>"
            if how == "meta":
                return 200, HTML, LOADING % ("<meta name='referrer' content='no-referrer'>" + head), []
            return 200, {**HTML, "referrer-policy": "no-referrer"}, LOADING % head, []
        return 200, HTML, (PLAIN if request["headers"].get("Referer") else doc(BODY, title=NAME)), []

    result, calls = run(monkeypatch, "https://orkide-g03.com/v8/p1", handler=handler)
    assert "Referer" not in calls[1]["headers"]
    assert_caught(result)


def test_g03_referrer_policies_and_client_hint_value():
    ref = page_probe._referer
    a, same, cross, down = "https://a.com/x?y#z", "https://a.com/b", "https://b.com/", "http://b.com/"
    assert ref(a, same) == "https://a.com/x?y" and ref(a, cross) == "https://a.com/" and ref(a, down) is None
    assert ref(a, same, "no-referrer") is None and ref(a, cross, "unsafe-url") == "https://a.com/x?y"
    assert ref(a, same, "origin") == "https://a.com/" and ref(a, cross, "same-origin") is None
    assert ref(a, down, "strict-origin") is None and ref(a, cross, "strict-origin") == "https://a.com/"
    assert ref(a, down, "no-referrer-when-downgrade") is None and ref(a, cross, "origin-when-cross-origin") == "https://a.com/"
    assert page_probe._referrer_policy("bilinmeyen, no-referrer, origin") == "origin"
    assert page_probe._referrer_policy("bilinmeyen") is None
    # sec-ch-ua: Chromium 156'nin gonderdigi deger (GREASE markasinin metni, surumu ve SIRASI)
    value = dict(page_probe._request_headers("https"))["sec-ch-ua"]
    assert value == '"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"'
    assert "Not_A Brand" not in json.dumps(page_probe.CHROME_PROFILE)


# --- G-04: yon degistirme -----------------------------------------------------------------------

G04 = {
    "a-bdo": "<h1><bdo dir='rtl'>" + NAME[::-1] + "</bdo></h1>" + PW,
    "b-unicode-bidi": "<h1 style='unicode-bidi:bidi-override;direction:rtl;text-align:left'>" + NAME[::-1] + "</h1>" + PW,
    "c-float-right": "<div style='float:left'>" + "".join(
        f"<span style='float:right'>{ch if ch != ' ' else '&nbsp;'}</span>" for ch in "Garanti BBVA"[::-1]) + "</div><br clear=all>" + PW,
    # Komsu cesitler
    "dir-rtl-attribute": "<p dir='rtl'><bdo>" + "Garanti BBVA"[::-1] + "</bdo></p>" + PW,
    "bdo-in-body-only": "<div><bdo dir='rtl'>" + "Garanti BBVA"[::-1] + "</bdo></div>" + PW,
    "flex-row-reverse": "<div style='display:flex;flex-direction:row-reverse'>" + "".join(
        f"<span>{ch if ch != ' ' else '&nbsp;'}</span>" for ch in "Garanti BBVA"[::-1]) + "</div>" + PW,
}


@pytest.mark.parametrize("variant", sorted(G04))
def test_g04_retest_reversed_brand_name_is_found(monkeypatch, variant):
    """Yeniden test: >= 50 ya da kapsam `partial`; ters yazilan ad "gizlenerek yazilmis" bulgusunu da uretir."""
    url = f"https://nar-g04.com/v8/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(G04[variant]))})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Garanti BBVA"
    assert "Kurum adı gizlenerek yazılmış" in names(result["reasons"])


# --- G-05: ayrac ve ASCII benzer harf ------------------------------------------------------------

@pytest.mark.parametrize("written", [
    "Garanti-BBVA", "Garanti.BBVA", "Garanti/BBVA", "Garanti·BBVA", "Garanti_BBVA", "Garanti B.B.V.A.", "Garanti‑BBVA",
    "GARANTl BBVA", "Garant1 BBVA", "Gar\x01anti BB\x01VA", "Gar\x81anti BB\x81VA", "Gar\x7fanti BB\x7fVA",
    "G.a.r.a.n.t.i BBVA"])
def test_g05_retest_separators_and_ascii_lookalikes(monkeypatch, written):
    """Yeniden test: ayracli ve benzer harfli yazimlarin tamami taninmali (>= 75)."""
    url = "https://nar-g05.com/v8/g"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(f"<h1>{written} İnternet Şubesi</h1>" + PW))})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Garanti BBVA"


def test_g05_split_single_word_brand_and_no_false_join(monkeypatch):
    url = "https://nar-g05.com/v8/ak"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<h1>Ak bank İnternet Şubesi</h1>" + PW))})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Akbank"
    # Karsi ornek: sozcuk sinirlarini asan rastlantisal birlesim kurum adi sayilmaz
    result, _ = run(monkeypatch, url + "2", {url + "2": (200, HTML, doc("<h1>Kazak bankosu ve tezgah</h1><p>Ürünler.</p>"))})
    assert result["ioc_details"]["target_brand"] is None and result["risk_score"] < 25


# --- G-06: ad metin dugumu olarak yok -------------------------------------------------------------

G06 = {
    "a-input-value": f"<input readonly size=40 value='{NAME}'><br>" + PW,
    "b-placeholder-and-submit": ("<form action='/post' method=post><input name=kullanici placeholder='Garanti BBVA müşteri numarası'>"
                                 f"<input type=password name=sifre><input type=submit value='{NAME} Giriş'></form>"),
    "c-table-cells": "<table cellspacing=0 cellpadding=0><tr>" + "".join(
        f"<td>{ch if ch != ' ' else '&nbsp;'}</td>" for ch in "Garanti BBVA") + "</tr></table>" + PW,
    "d-inline-divs": "<div style='font-size:2em'>" + "".join(
        f"<div style='display:inline'>{ch if ch != ' ' else '&nbsp;'}</div>" for ch in "Garanti BBVA") + "</div>" + PW,
    # Komsu cesitler
    "aria-label": "<div role='img' aria-label='Garanti BBVA İnternet Şubesi' style='height:40px'></div>" + PW,
    "svg-tspans": "<svg width=400 height=40><text y=30>" + "".join(f"<tspan>{c}</tspan>" for c in "GarantiBBVA") + "</text></svg>" + PW,
    "list-items": "<ul>" + "".join(f"<li style='display:inline'>{c}</li>" for c in "GarantiBBVA") + "</ul>" + PW,
    "option-label": "<select><option label='Garanti BBVA İnternet Şubesi'></option></select>" + PW,
}


@pytest.mark.parametrize("variant", sorted(G06))
def test_g06_retest_brand_outside_text_nodes_is_found(monkeypatch, variant):
    """Yeniden test: >= 50 ya da kapsam `partial`."""
    url = f"https://nar-g06.com/v8/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(G06[variant]))})
    assert_caught(result)
    assert result["ioc_details"]["target_brand"] == "Garanti BBVA"


def test_g06_password_value_is_never_read_as_text():
    facts = html_extract.extract("<input type=password value='Garanti BBVA'><input type=hidden value='Akbank'><input value='görünen'>")
    assert facts["attr_text"] == ["görünen"]


# --- G-07: kimligi belirlenemeyen hassas form ---------------------------------------------------

PLAIN_FORM = doc("<h2>İnternet Şubesi Girişi</h2>" + PW, title="İnternet Şubesi")
LOGO_FORM = doc("<img src='/logo.png' alt='' width=200 height=40><h2>İnternet Şubesi Girişi</h2>" + PW, title="İnternet Şubesi")


@pytest.mark.parametrize("host,page", [
    ("akasya-g07.com", PLAIN_FORM),          # (a) stil ve gorsel yok
    ("okul-z09.k12.tr", LOGO_FORM),          # (c) kisitli uzanti
    ("okul-z09.k12.tr", PLAIN_FORM),
    ("ornek.bel.tr", PLAIN_FORM),
    ("docs.google.com", PLAIN_FORM),         # sahibi bilinen ama guvenilmeyen (kullanici icerigi) alan
    ("93.184.216.34", PLAIN_FORM),
])
def test_g07_retest_identity_less_sensitive_form_is_never_low(monkeypatch, host, page):
    """Yeniden test: "Karar verilemedi" ya da en az "Dikkat"; "Kisitli resmi uzanti" indirimi gorunmemeli."""
    url = f"https://{host}/v8/g0"
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    not_low(result)
    assert "Kısıtlı resmi uzantı" not in names(result["reasons"])
    assert "Kimliği doğrulanamayan giriş formu" in names(result["reasons"])
    assert "unverified_form" in result["ioc_details"]["inspection_gaps"]


def test_g07_form_inside_a_frame_counts_too(monkeypatch):
    url = "https://akasya-g07.com/v8/cerceve"
    pages = {url: (200, HTML, doc("<iframe src='/form'></iframe>")), "https://akasya-g07.com/form": (200, HTML, PLAIN_FORM)}
    result, _ = run(monkeypatch, url, pages)
    not_low(result)
    assert "unverified_form" in result["ioc_details"]["inspection_gaps"]


def test_g07_trusted_owner_and_pages_without_sensitive_fields_are_unaffected(monkeypatch):
    """Karsi ornekler: katalogdaki guvenilen adresin kendi giris sayfasi ve bilgi istemeyen sayfa."""
    url = "https://www.garantibbva.com.tr/giris"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<h1>Garanti BBVA İnternet Şubesi</h1>" + PW, title="Garanti BBVA"))})
    assert result["risk_level"] == "LOW" and "Kimliği doğrulanamayan giriş formu" not in names(result["reasons"])
    url = "https://okul-z09.k12.tr/duyurular"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<h1>Okulumuz</h1><p>Veli toplantısı.</p><form action='/ara'><input name=q></form>"
                                                           "<a href='/a'>Duyurular</a> <a href='/b'>Kadro</a> <a href='/c'>İletişim</a>"))})
    assert result["risk_level"] == "LOW" and "Kısıtlı resmi uzantı" in names(result["reasons"])


# --- G-08: ayristirma iscileri ------------------------------------------------------------------

def test_g08_parse_time_is_budgeted_per_analysis(monkeypatch):
    """Tek bir analiz istegi isciyi toplamda PARSE_BUDGET_PER_PROBE'dan uzun tutamaz; ilk zaman asimindan sonra
    kalan belgeler kisa sureyle ve dusuk oncelikle islenir."""
    seen = []

    def slow(html, xml=False, timeout=None, low_priority=False):
        seen.append((round(timeout, 2), low_priority))
        time.sleep(min(timeout, 0.05))
        raise parse_pool.ParseFailed("timeout")

    monkeypatch.setattr(parse_pool, "extract", slow)
    state = {"cookies": [], "parse_spent": 0.0, "parse_strikes": 0}
    token = page_probe._probe_state.set(state)
    try:
        for _ in range(4):
            page_probe._inspect_html(doc(BODY), "https://derin-g08.com/a")
    finally:
        page_probe._probe_state.reset(token)
    assert seen[0] == (parse_pool.PARSE_TIMEOUT_SECONDS, False)
    assert all(t == (page_probe.PARSE_TIMEOUT_AFTER_STRIKE, True) for t in seen[1:])
    state = {"cookies": [], "parse_spent": page_probe.PARSE_BUDGET_PER_PROBE, "parse_strikes": 0}
    token = page_probe._probe_state.set(state)
    try:
        before = len(seen)
        features, _ = page_probe._inspect_html(doc(BODY), "https://derin-g08.com/b")
    finally:
        page_probe._probe_state.reset(token)
    assert len(seen) == before and features["opaque"] == ["parser"]  # butce bitti: isciye gidilmedi


def test_g08_deeply_nested_document_is_rejected_before_parsing(monkeypatch):
    called = []
    monkeypatch.setattr(parse_pool, "extract", lambda *a, **k: called.append(1) or {})
    started = time.monotonic()
    features, _ = page_probe._inspect_html("<div>" * 190_000 + BODY, "https://derin-g08.com/c")
    assert not called and features["opaque"] == ["parser"] and time.monotonic() - started < 1.0


def test_g08_client_with_a_recent_parse_timeout_is_low_priority(monkeypatch):
    seen = []

    def fake(html, xml=False, timeout=None, low_priority=False):
        seen.append(low_priority)
        if len(seen) == 1:
            raise parse_pool.ParseFailed("timeout")
        return html_extract.extract(html, xml)

    monkeypatch.setattr(parse_pool, "extract", fake)
    monkeypatch.setattr(page_probe, "_parse_strikes", {})
    for client in ("198.51.100.8", "198.51.100.8", "198.51.100.9"):
        token = netguard.set_probe_context(netguard.ProbeContext(client=client))
        try:
            page_probe._inspect_html(doc(BODY), "https://derin-g08.com/d")
        finally:
            netguard.reset_probe_context(token)
    assert seen == [False, True, False]


def test_g08_low_priority_calls_cannot_take_the_reserved_worker():
    pool = parse_pool.ParsePool(size=3)
    release = threading.Event()
    started = []

    def hold(html, xml, timeout):
        started.append(1)
        release.wait(5)
        return {}

    pool._run = hold
    threads = [threading.Thread(target=pool.run, args=("x",), kwargs={"low_priority": True}) for _ in range(2)]
    for t in threads:
        t.start()
    while len(started) < 2:
        time.sleep(0.01)
    try:
        with pytest.raises(parse_pool.ParseFailed):
            pool.run("x", low_priority=True)       # ucuncu dusuk oncelikli cagri son isciyi alamaz, beklemez
        pool._run = lambda html, xml, timeout: {"ok": 1}
        assert pool.run("x") == {"ok": 1}            # olagan cagri ayrilan isciyi kullanir
    finally:
        release.set()
        for t in threads:
            t.join()
    assert pool._busy == 0


def test_g08_waiting_call_takes_over_the_slot_of_a_killed_worker():
    """Zaman asimiyla sonlandirilan iscinin yeri, bekleyen cagriya HEMEN gecer (bekleyen "busy" almaz)."""
    pool = parse_pool.ParsePool(size=1)
    slow = "<div>" * 19_000 + ("<div>" * 19_000 + "</div>" * 19_000) * 3
    outcome = {}

    def hog():
        try:
            pool.run(slow * 4, timeout=0.6)
        except parse_pool.ParseFailed as exc:
            outcome["hog"] = str(exc)

    thread = threading.Thread(target=hog)
    thread.start()
    time.sleep(0.2)
    started = time.monotonic()
    try:
        facts = pool.run("<input type=password>")
    finally:
        thread.join()
        pool.shutdown()
    assert facts["password_inputs"] == 1 and time.monotonic() - started < 3.0
    assert outcome.get("hog") in ("timeout", None)
    assert pool._busy == 0 and pool._count == 0


def test_g08_contended_pool_shortens_the_parse_timeout():
    pool = parse_pool.ParsePool(size=3)
    seen = []
    release = threading.Event()

    def hold(html, xml, timeout):
        seen.append(timeout)
        release.wait(5)
        return {}

    pool._run = hold
    threads = [threading.Thread(target=pool.run, args=("x",)) for _ in range(3)]
    for t in threads:
        t.start()
        while len(seen) < threads.index(t) + 1:
            time.sleep(0.01)
    release.set()
    for t in threads:
        t.join()
    assert seen == [parse_pool.PARSE_TIMEOUT_SECONDS, parse_pool.PARSE_TIMEOUT_SECONDS, parse_pool.CONTENDED_TIMEOUT_SECONDS]


def test_g08_worker_memory_limits_fit_the_container():
    worker = (ROOT / "backend/sandbox/worker.py").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "limit = 640 * 1024 * 1024" in worker and "mem_limit: 1g" in compose
    assert parse_pool.POOL_SIZE == 3 and parse_pool.RESERVED_WORKERS >= 1


# --- G-09 / G-12: yem sayfasi ve baglanti izleme -------------------------------------------------

LURE = ("<!doctype html><html><head><meta charset='utf-8'><title>Garanti BBVA - Hesap Bildirimi</title></head><body>%s"
        "<h1>Garanti BBVA</h1><p>%s</p><p><a href='/v8/k/x'>%s</a></p>%s</body></html>")
ALERT = "Hesabınızda olağan dışı işlem tespit edildi. Kısıtlamayı kaldırmak için kimliğinizi doğrulayın."
NAV = "".join(f"<a href='/v8/y0/s{i}'>Sayfa {i}</a> " for i in range(5))
PAD = "<p style='color:#999;font-size:10px'>" + "Bu ileti bilgilendirme amaçlıdır. Yasal uyarı metni ve kullanım koşulları geçerlidir. " * 20 + "</p>"
G09 = {
    "a-nav-links": LURE % (NAV, ALERT, "Devam", ""),
    "b-padding": LURE % ("", ALERT, "Devam", PAD),
    # Komsu cesitler: tuzak ifadesi de yok; yalnizca baglantinin gittigi sayfadaki form belirleyici
    "neutral-text-nav-and-padding": LURE % (NAV, "İşleminize devam etmek için aşağıdaki bağlantıyı kullanın.", "Devam", PAD),
    "get-form-button": ("<!doctype html><html><head><meta charset='utf-8'><title>Garanti BBVA - Bildirim</title></head><body>"
                        "<h1>Garanti BBVA</h1><p>İşleminize devam edin.</p><form action='/v8/k/x'><button>Devam</button></form>"
                        + PAD + "</body></html>"),
}


@pytest.mark.parametrize("variant", sorted(G09))
def test_g09_retest_lure_page_is_decisive_whatever_its_shape(monkeypatch, variant):
    """Yeniden test: HTTPS uzerinden >= 50; baglantinin gittigi sayfa izlenir."""
    url = f"https://leylak-g09.com/v8/{variant}"
    pages = {url: (200, HTML, G09[variant]), "https://leylak-g09.com/v8/k/x": (200, HTML, doc(BODY))}
    result, calls = run(monkeypatch, url, pages)
    assert "https://leylak-g09.com/v8/k/x" in [c["url"] for c in calls]
    assert_caught(result)
    assert "Sayfa Garanti BBVA kimliği taşıyor" in names(result["reasons"])
    assert "Bağlantının gittiği sayfa: Hassas bilgi toplayan form" in names(result["reasons"])


def test_g09_bait_text_alone_makes_the_lure_decisive():
    features, _ = page_probe._inspect_html(LURE % (NAV, ALERT, "Devam", PAD), "https://leylak-g09.com/x")
    assert features["bait_text"] and features["follow_links"][0] == "https://leylak-g09.com/v8/k/x"
    assert not page_probe._inspect_html(doc("<h1>Fırın</h1><p>Taze ekmek.</p>"), "https://x.com/")[0]["bait_text"]


def test_g12_retest_one_time_links_are_not_consumed(monkeypatch):
    """Yeniden test: kimlik tasimayan sayfadaki "Onayla" baglantisina dokunulmaz."""
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>E-posta doğrulama</title></head><body>"
            "<p>Hesabınızı silme isteğinizi onaylamak için bağlantıya tıklayın.</p>"
            "<p><a href='/v8/t1hit/x?token=abc123'>Onayla</a></p></body></html>")
    url = "https://leylak-g12.com/v8/t1"
    result, calls = run(monkeypatch, url, {url: (200, HTML, page)})
    assert [c["url"] for c in calls] == [url]
    # Kimlik tasiyan sayfada da belirtec tasiyan baglanti izlenmez; belirtecsiz olan izlenir
    lure = LURE % ("<a href='/onay?token=abc123'>Onayla</a> <a href='/iptal?k=0123456789abcdef0123'>İptal</a> ", ALERT, "Devam", "")
    result, calls = run(monkeypatch, url + "2", {url + "2": (200, HTML, lure)})
    fetched = [c["url"] for c in calls]
    assert "https://leylak-g12.com/v8/k/x" in fetched and not [u for u in fetched if "token=" in u or "?k=" in u]


def test_g12_embedded_requests_are_capped(monkeypatch):
    assert page_probe._state_changing_link("https://a.com/x?session=1") and not page_probe._state_changing_link("https://a.com/x?sayfa=2")
    state = {"cookies": [], "embedded_requests": page_probe.MAX_EMBEDDED_REQUESTS, "visited": [], "tricks": []}
    token = page_probe._probe_state.set(state)
    try:
        assert page_probe._fetch_embedded("https://a-g12.com/x", time.monotonic() + 5, None) == (None, "https://a-g12.com/x")
    finally:
        page_probe._probe_state.reset(token)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "bağlantıları da ziyaret eder" in readme


# --- G-10: govde kimligi ---------------------------------------------------------------------------

LOGO = "<div class='logo'>Garanti BBVA</div><h2>İnternet Şubesi Girişi</h2>"
FOOT = "<p style='font-size:11px;color:#888'>%s</p>"


@pytest.mark.parametrize("body,brand", [
    (LOGO + PW + FOOT % "Akbank kartları da geçerlidir.", "Garanti BBVA"),                 # (a) esitlik: logo ogesi kazanir
    ("<h2>Garanti BBVA</h2>" + PW + FOOT % "Akbank ve Yapı Kredi kartları da geçerlidir.", "Garanti BBVA"),
    ("<div class='logo'>ING</div><h2>İnternet Şubesi Girişi</h2>" + PW, "ING"),            # (b) kisa adli kurum
    ("<div id='brand'>PTT</div>" + PW, "PTT"),
])
def test_g10_retest_prominent_brand_wins_and_short_names_count(monkeypatch, body, brand):
    """Yeniden test: (a) >= 75, (b) >= 50. Kisaltma zayif kanittir (9. tur: 'UPS Sistemleri' yanlis pozitifi)."""
    url = "https://funda-g10.com/v8/m"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(body, title="İnternet Şubesi"))})
    assert_caught(result, 50 if len(brand) <= 3 else 75)
    assert brand in (result["ioc_details"]["target_brand"] or "")


def test_g10_short_name_outside_a_prominent_element_is_not_a_brand(monkeypatch):
    """Karsi ornek: govde metninde gecen kisa sozcuk (logo / baslik disinda) kurum sayilmaz; form yine "Dusuk risk" olmaz."""
    url = "https://funda-g10.com/v8/kisa"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc("<h2>Şifreniz yok mu? Shopping and ing endings</h2><p>ptt.</p>" + PW, title="Login"))})
    assert result["ioc_details"]["target_brand"] is None and result["risk_level"] == "UNKNOWN"


# --- G-11: engel listesi gorulen her adrese ---------------------------------------------------------

@pytest.fixture()
def blocked():
    from backend.models.database import SessionLocal, init_db
    from backend.models.list_model import ListModel

    init_db()
    db = SessionLocal()
    rule = ListModel(list_type="blacklist", entry_type="domain", pattern="sogut-g11.com", description="g11")
    db.add(rule)
    db.commit()
    try:
        yield db
    finally:
        db.delete(rule)
        db.commit()
        db.close()


B = "https://sogut-g11.com/v8/z/x"
G11 = {
    "a-script-redirect": (LOADING % "").replace("</body>", f"<script>location.href='{B}'</script></body>"),
    "b-frame-inside-srcdoc": srcdoc(f"<iframe src='{B}' style='{FULL}'></iframe>"),
    # Komsu cesitler
    "refresh-inside-srcdoc": srcdoc(f"<meta http-equiv='refresh' content='0; url={B}'>"),
    "form-target": doc(f"<form action='{B}' method=post><input name=q><button>Gönder</button></form>"),
    "call-to-action-link": doc(f"<p>Devam etmek için <a href='{B}'>giriş yap</a>.</p>" + "<p>metin</p>" * 400),
    "frame-inside-frame": doc("<iframe src='/ic'></iframe>"),
    "location-replace": (LOADING % "").replace("</body>", f"<script>window.location.replace(\"{B}\")</script></body>"),
}


@pytest.mark.parametrize("variant", sorted(G11))
def test_g11_retest_blocklist_covers_every_address_the_probe_sees(monkeypatch, blocked, variant):
    """Yeniden test: "Engel listesi eslesmesi" ile 100 puan."""
    url = f"https://sedir-g11.com/v8/{variant}"
    pages = {url: (200, HTML, G11[variant]), B: (200, HTML, doc(BODY)),
             "https://sedir-g11.com/ic": (200, HTML, doc(f"<iframe src='{B}'></iframe>"))}
    result, _ = run(monkeypatch, url, pages, db=blocked)
    assert result["risk_score"] == 100 and result["reasons"][0]["rule_name"] == "Engel listesi eşleşmesi", names(result["reasons"])


def test_g11_rules_are_read_once_per_analysis(monkeypatch, blocked):
    import backend.core.analyzer_interface as ai

    counted = []
    original = ai.check_list_match

    def counting(db, domain, raw_url, list_type, parsed=None, entries=None):
        counted.append(entries is not None)
        return original(db, domain, raw_url, list_type, parsed=parsed, entries=entries)

    monkeypatch.setattr(ai, "check_list_match", counting)
    url = "https://sedir-g11.com/v8/zincir"
    pages = {url: (302, {"location": "https://a-g11.com/1"}, b""), "https://a-g11.com/1": (302, {"location": "https://b-g11.com/2"}, b""),
             "https://b-g11.com/2": (200, HTML, doc("<p>merhaba</p>"))}
    run(monkeypatch, url, pages, db=blocked)
    assert counted.count(True) >= 2 and counted.count(False) <= 2  # zincir adimlari onceden okunan kurallari kullanir


# --- G-13: ek gozlemler ------------------------------------------------------------------------------

def test_g13_http_equiv_is_compared_without_trimming(monkeypatch):
    """Tarayici ' refresh ' degerini yonlendirme saymaz; platform da izlemez ve "son adres" sayfanin kendisidir."""
    url = "https://papatya-g13.com/v8/q1"
    page = doc(BODY, head="<meta http-equiv=' refresh ' content='0; url=https://www.garantibbva.com.tr/'>")
    result, calls = run(monkeypatch, url, {url: (200, HTML, page)})
    assert [c["url"] for c in calls] == [url] and result["ioc_details"]["final_url"] is None
    assert_caught(result)
    assert html_extract.extract("<meta http-equiv='REFRESH' content='0;url=/x'>")["meta_refresh"] == ["0;url=/x"]


def test_g13_worker_reply_is_bounded():
    big = "<p>" + "ş" * 300_000 + "</p>"
    facts = html_extract.extract(doc(big * 4 + BODY))
    assert sum(len(c) for c in facts["text"]) + sum(len(c) for c in facts["text_visible"]) <= html_extract.MAX_TEXT_CHARS + 600_000
    assert facts["truncated_tree"] and facts["password_inputs"] == 1
    features, _ = page_probe._inspect_html(doc(big * 4 + BODY), "https://x-g13.com/")
    assert "truncated" in features["opaque"] and features["password_input"]


def test_g13_control_characters_are_stripped_and_reported():
    from backend.core.brands import normalize_text

    assert normalize_text("Gar\x01anti BB\x81VA\x7f") == "garanti bbva"
    assert normalize_text("satır\tsonu\nkorunur") == "satir\tsonu\nkorunur"
    features, _ = page_probe._inspect_html(doc("<h1>Gar\x01anti BBVA</h1>" + PW), "https://x-g13.com/")
    assert features["hidden_chars"]


def test_urls_helper_still_used_for_every_in_page_address():
    source = (ROOT / "backend/core/page_probe.py").read_text(encoding="utf-8")
    assert "urljoin" not in source and urls.resolve("https://a.com/x", "/y") == "https://a.com/y"
