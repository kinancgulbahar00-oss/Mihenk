"""9. tur gerileme testleri (H-01 … H-12): 8. rapor duzeltmelerinin ardindan yapilan incelemede bulunan bosluklar.

Olcut her testte aynidir: taninan bir kurum kimligi + veri toplayan form "Zararli/Supheli" olur; platformun
okuyamadigi her durum en az "Karar verilemedi"dir; "tam incelendi, Dusuk risk" yalnizca olumlu kanitla verilir."""

import pytest

from backend.core import page_probe
from backend.tests.test_security_v6 import _page_fetch, names  # noqa: F401  (_page_fetch: autouse fixture)
from backend.tests.test_security_v7 import (BODY, CARD, FULL, HTML, LOADING, PLAIN, PW, T, assert_caught, coverage, doc, run)

NAME = "Garanti BBVA İnternet Şubesi"
TARGET_URL = f"https://{T}/giris8"
TARGET = {TARGET_URL: (200, HTML, doc(CARD, title=NAME))}
MASK = "<style>.m{-webkit-text-security:disc}</style>"
LOGO = "<img src='/logo.png'>"


def form(inner):
    return f"<form action='/post' method=post>{inner}<button>Devam</button></form>"


# --- H-01: alan tanima -------------------------------------------------------------------------------

H01 = {
    "css-mask-image-labels": MASK + LOGO + form("<img src='/a.png'><input name=f1><img src='/b.png'><input name=f2 class=m>"),
    "homoglyph-label": LOGO + form("Kullanıcı<input name=f1>Şіfre<input name=f2>"),
    "css-content-label": "<style>.l::before{content:'Şifre'}</style>" + LOGO + form("<input name=f1><span class=l></span><input name=f2>"),
    "unknown-word": LOGO + form("Müşteri numarası<input name=f1>Erişim anahtarınız<input name=f2>"),
    "no-labels-at-all": LOGO + form("<input name=f1><input name=f2>"),
}


@pytest.mark.parametrize("variant", sorted(H01))
@pytest.mark.parametrize("host", ["akasya-h01.com", "okul-h01.k12.tr"])
def test_h01_unrecognised_fields_are_never_a_clean_page(monkeypatch, variant, host):
    """Alan turu taninmasa da metin girdisini POST eden, kimligi belirlenemeyen form "Dusuk risk" olamaz."""
    url = f"https://{host}/v9/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(H01[variant], title="İnternet Şubesi"))})
    assert result["risk_level"] != "LOW", (result["risk_score"], names(result["reasons"]))
    assert coverage(result) == "partial" and "Kısıtlı resmi uzantı" not in names(result["reasons"])


def test_h01_recognised_variants_and_counter_example(monkeypatch):
    features, _ = page_probe._inspect_html(doc(MASK + form("<input name=f1><input name=f2 class=m>")), "https://x-h01.com/")
    assert features["password_input"] and features["collects_input"]
    features, _ = page_probe._inspect_html(doc(form("Vatandaşlık Numarası<input name=a>")), "https://x-h01.com/")
    assert features["tckn_input"]
    # Karsi ornek: GET ile calisan arama kutusu veri toplayan form degildir; sayfa tam incelenir
    url = "https://kumsal-h01.com/"
    page = doc("<h1>Kumsal Atölye</h1><form action='/ara'><input name=q><button>Ara</button></form><p>Merhaba.</p>"
               "<a href='/kurslar'>Kurslar</a> <a href='/galeri'>Galeri</a> <a href='/iletisim'>İletişim</a>")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert coverage(result) == "full" and result["risk_level"] == "LOW"


def test_h01_brand_plus_unrecognised_fields_is_caught(monkeypatch):
    url = "https://akasya-h01.com/v9/b"
    page = doc(MASK + "<h2>" + NAME + "</h2>" + form("<input name=f1><input name=f2 class=m>"))
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert_caught(result)


# --- H-02: yem sayfasi, kurum adi govdede ------------------------------------------------------------

H02 = {
    "paragraph": "<p><b>Garanti BBVA</b> hesabınız kısıtlandı. Kimliğinizi doğrulayın.</p>",
    "h2": "<h2>Garanti BBVA</h2><p>Hesabınız kısıtlandı.</p>",
    "img-alt": "<img src='/l.png' alt='Garanti BBVA'><p>Hesabınız kısıtlandı.</p>",
}


@pytest.mark.parametrize("variant", sorted(H02))
def test_h02_lure_page_with_brand_only_in_body(monkeypatch, variant):
    url = f"https://leylak-h02.com/v9/{variant}"
    page = doc(H02[variant] + f"<a href='{TARGET_URL}'>Devam et</a>", title="Bilgilendirme")
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, page)}))
    assert TARGET_URL in [c["url"] for c in calls]
    assert_caught(result, 50)


def test_h02_padded_lure_page_follows_the_external_link(monkeypatch):
    """G-09 kalani: baslikta kurum + 1.500 karakterden uzun dolgu + 12 site ici baglanti + listede olmayan ifade."""
    url = "https://leylak-h02.com/v9/dolgu"
    nav = "".join(f"<a href='/s{i}'>Bölüm {i}</a> " for i in range(12))
    fill = "".join(f"<p>Yasal uyarı metni {i}: hizmet koşulları ve gizlilik bildirimi geçerlidir, ayrıntılar için sözleşmeye bakınız.</p>"
                   for i in range(20))
    page = doc(f"<h1>{NAME}</h1><p>Hesabınıza erişim geçici olarak durdurulmuştur.</p><a href='{TARGET_URL}'>Devam</a>" + nav + fill)
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, page)}))
    assert [c["url"] for c in calls] == [url, TARGET_URL]
    assert_caught(result, 50)


# --- H-03: zincir ve cerceve sinirlari ---------------------------------------------------------------

def test_h03_fifth_document_in_a_refresh_chain_is_scored(monkeypatch):
    base = "https://papatya-h03.com/v9/c"
    pages = {f"{base}/{i}": (200, HTML, LOADING % f"<meta http-equiv='refresh' content='0; url={base}/{i + 1}'>") for i in range(1, 6)}
    pages[f"{base}/6"] = (200, HTML, doc(BODY, head=f"<meta http-equiv='refresh' content='1; url={base}/son'>"))
    pages[f"{base}/son"] = (200, HTML, PLAIN)
    result, calls = run(monkeypatch, f"{base}/1", pages)
    assert len(calls) == 7
    assert_caught(result)


def test_h03_fifth_frame_is_scored(monkeypatch):
    url = "https://papatya-h03.com/v9/fr"
    page = doc("<iframe srcdoc='' width=0 height=0></iframe>" * 3 + "<iframe src='/v9/bos' width=0 height=0></iframe>"
               + f"<iframe src='{TARGET_URL}' style='{FULL}'></iframe>")
    result, _ = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, page), "https://papatya-h03.com/v9/bos": (200, HTML, PLAIN)}))
    assert_caught(result, 50)
    assert any(n.startswith("Çerçevedeki sayfa:") for n in names(result["reasons"]))


# --- H-04: yenileme zamanlamasi, cerez kabi ----------------------------------------------------------

def test_h04_unwaited_refresh_delay_is_not_a_full_inspection(monkeypatch):
    slept = []
    monkeypatch.setattr(page_probe.time, "sleep", lambda s: slept.append(s))
    a, b = "https://menekse-h04.com/v9/t1", "https://menekse-h04.com/v9/t2"
    result, _ = run(monkeypatch, a, {a: (200, HTML, LOADING % f"<meta http-equiv='refresh' content='9; url={b}'>"), b: (200, HTML, PLAIN)})
    assert slept and max(slept) <= page_probe.REFRESH_WAIT_SECONDS
    assert coverage(result) == "partial" and "delayed_refresh" in result["ioc_details"]["inspection_gaps"]
    assert result["risk_level"] != "LOW"
    # Karsi ornek: kisa gecikme beklenir ve sayfa tam incelenir
    a2 = a + "k"
    result, _ = run(monkeypatch, a2, {a2: (200, HTML, LOADING % f"<meta http-equiv='refresh' content='1; url={b}'>"), b: (200, HTML, PLAIN)})
    assert coverage(result) == "full" and 1 in slept


def test_h04_cookie_jar_keeps_twenty_fifth_cookie_and_long_values(monkeypatch):
    a, b = "https://menekse-h04.com/v9/ck", "https://menekse-h04.com/v9/ck2"

    def handler(request):
        if request["url"] == a:
            cookies = [f"c{i}=1; Path=/" for i in range(1, 26)] + ["uzun=" + "x" * 3000 + "; Path=/"]
            return 200, HTML, LOADING % f"<meta http-equiv='refresh' content='0; url={b}'>", cookies
        ok = "c25=1" in request["cookie"] and "uzun=xxx" in request["cookie"]
        return 200, HTML, doc(BODY) if ok else PLAIN, []

    result, _ = run(monkeypatch, a, handler=handler)
    assert_caught(result)


def test_h04_conflicting_refresh_tags_are_not_a_full_inspection(monkeypatch):
    url = "https://menekse-h04.com/v9/m2"
    head = f"<meta http-equiv='refresh' content='5; url=/v9/iyi'><meta http-equiv='refresh' content='0; url={TARGET_URL}'>"
    features, _ = page_probe._inspect_html(LOADING % head, url)
    assert "refresh_conflict" in features["opaque"]
    features, _ = page_probe._inspect_html(LOADING % "<meta http-equiv='refresh' content='0; url=/a'><meta http-equiv='refresh' content='3; url=/a'>", url)
    assert "refresh_conflict" not in features["opaque"]


# --- H-05: engel listesi icin gorulen adresler -------------------------------------------------------

def test_h05_form_targets_cannot_crowd_out_frames_and_hops():
    state = {"visited": []}
    token = page_probe._probe_state.set(state)
    try:
        for i in range(120):
            page_probe._note_visit(f"https://dolgu{i}.example/", soft=True)
        page_probe._note_visit("https://engelli-h05.com/cerceve")
    finally:
        page_probe._probe_state.reset(token)
    assert len(state["visited"]) == page_probe.MAX_SOFT_VISITS + 1 and state["visited"][-1] == "https://engelli-h05.com/cerceve"


def test_h05_page_with_sixty_form_targets_still_reports_its_frame(monkeypatch):
    url = "https://sedir-h05.com/v9/b1"
    forms = "".join(f"<form hidden action='https://d{i}.example/'></form>" for i in range(70))
    page = doc(forms + "<iframe src='https://engelli-h05.com/x'></iframe>")
    seen = {}
    import backend.core.analyzer_interface as ai

    real = ai.collect_signals
    monkeypatch.setattr(ai, "collect_signals", lambda parsed, intel: seen.update(page=intel["page"]) or real(parsed, intel))
    run(monkeypatch, url, {url: (200, HTML, page), "https://engelli-h05.com/x": (200, HTML, PLAIN)})
    assert "https://engelli-h05.com/x" in seen["page"]["visited"]


# --- H-06: kisitli uzantida govde / logo kimligi -----------------------------------------------------

@pytest.mark.parametrize("host", ["okul-h06.k12.tr", "ornek-h06.bel.tr", "bolum.ornek.edu.tr"])
@pytest.mark.parametrize("identity", ["<h2>" + NAME + "</h2>", "<img src='/l.png' alt='Garanti BBVA'>"])
def test_h06_body_brand_with_sensitive_form_on_restricted_suffix(monkeypatch, host, identity):
    url = f"https://{host}/v9/k"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(identity + PW))})
    assert_caught(result)


def test_h06_restricted_site_mentioning_a_brand_without_a_form_stays_clean(monkeypatch):
    url = "https://okul-h06.k12.tr/duyuru"
    page = doc("<h2>Duyurular</h2><p>Okul aile birliği ödemeleri Garanti BBVA şubelerinden yapılabilir.</p><a href='/iletisim'>İletişim</a>")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_level"] == "LOW" and result["ioc_details"]["target_brand"] is None


# --- H-07: ayristirilamayan belge --------------------------------------------------------------------

@pytest.mark.parametrize("padding", ["<br>" * 20_001, "<img src=x>" * 20_001, "<!--" + "<a" * 20_001 + "-->",
                                     "<ul>" + "<li>madde" * 20_001 + "</ul>"], ids=["br", "img", "comment", "li"])
def test_h07_void_and_auto_closing_elements_are_not_nesting(monkeypatch, padding):
    url = "https://yildiz-h07.com/v9/br"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(BODY + "<div hidden>" + padding + "</div>"))})
    assert_caught(result)
    assert coverage(result) == "full"


def test_h07_unparsable_document_keeps_raw_evidence(monkeypatch):
    assert page_probe._nesting_estimate("<div>" * 25_000) > page_probe.MAX_NESTING_ESTIMATE
    url = "https://yildiz-h07.com/v9/derin"
    page = doc(BODY, title=NAME).replace("</body>", "<div>" * 25_000 + "</body>")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert coverage(result) == "partial" and "parser" in result["ioc_details"]["inspection_gaps"]
    assert_caught(result, 50)
    # Karsi ornek: ayristirilamayan, kimlik tasimayan belge "Karar verilemedi" duzeyinde kalir
    url2 = url + "2"
    result, _ = run(monkeypatch, url2, {url2: (200, HTML, PLAIN.replace("</body>", "<div>" * 25_000 + "</body>"))})
    assert result["risk_level"] != "LOW" and result["risk_score"] < 50


def test_h07_redirect_status_without_location_is_a_page(monkeypatch):
    url = "https://yildiz-h07.com/v9/nl"
    result, _ = run(monkeypatch, url, {url: (302, HTML, doc(BODY))})
    assert_caught(result)


# --- H-08: tarayicinin cizdigi, platformun okumadigi metin -------------------------------------------

H08 = {
    "object-fallback": "<object><h1>" + NAME + "</h1>" + PW + "</object>",
    "object-broken-data": "<object data='/yok.png' type='image/png'><h1>" + NAME + "</h1></object>" + PW,
    "css-attr": "<style>.b::before{content:attr(data-n)}</style><div class=b data-n='" + NAME + "'></div>" + PW,
}


@pytest.mark.parametrize("variant", sorted(H08))
def test_h08_rendered_text_outside_text_nodes(monkeypatch, variant):
    url = f"https://nar-h08.com/v9/{variant}"
    pages = {url: (200, HTML, doc(H08[variant])), "https://nar-h08.com/yok.png": (404, HTML, "yok")}
    result, _ = run(monkeypatch, url, pages)
    assert_caught(result, 50)


# --- H-09: yanlis pozitifler -------------------------------------------------------------------------

@pytest.mark.parametrize("title", ["En Para Kazandıran Uygulamalar - Üye Girişi", "Yemek Sepeti Hazırlama Kursu - Giriş"])
def test_h09_ordinary_phrases_are_not_joined_into_a_brand(monkeypatch, title):
    url = "https://kurs-h09.com/uye"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(PW, title=title))})
    assert result["ioc_details"]["target_brand"] is None and result["risk_level"] == "UNKNOWN", names(result["reasons"])


@pytest.mark.parametrize("heading", ["UPS Sistemleri Bayi Girişi", "BIM Yönetim Paneli"])
def test_h09_three_letter_acronym_is_weak_evidence(monkeypatch, heading):
    url = "https://bayi-h09.com/giris"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(f"<h2>{heading}</h2>" + PW, title="Panel"))})
    assert result["risk_level"] != "CRITICAL" and result["risk_score"] < 75, (result["risk_score"], names(result["reasons"]))
    assert not any(n.startswith("Sayfa ") and n.endswith("kimliği taşıyor") for n in names(result["reasons"]))


def test_h09_split_single_word_brand_is_still_caught(monkeypatch):
    url = "https://kurs-h09.com/ak"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(PW, title="Ak bank İnternet Şubesi"))})
    assert_caught(result)


# --- H-10: uzun gecikmeli kendine yenileme -----------------------------------------------------------

def test_h10_slow_self_refresh_is_not_a_full_inspection(monkeypatch):
    url = "https://menekse-h10.com/v9/t3"
    result, calls = run(monkeypatch, url, {url: (200, HTML, LOADING % "<meta http-equiv='refresh' content='12'>")})
    assert len(calls) == 2 and coverage(result) == "partial" and result["risk_level"] != "LOW"


# --- 10. tur: 9. tur duzeltmelerine karsi denemeler --------------------------------------------------

J01 = {
    "get-two-fields": "<form action='/p'><input name=a><input name=b><button>Devam</button></form>",
    "get-one-unlabelled-field": "<form action='/p'><input name=a><button>Devam</button></form>",
    "unknown-input-type": "<form method=post action='/p'><input type=metin name=a><input type=x name=b><button>Devam</button></form>",
    "date-like-types": "<form method=post action='/p'><input type=month name=a><input type=datetime-local name=b><button>Devam</button></form>",
}


@pytest.mark.parametrize("variant", sorted(J01))
def test_j01_every_form_that_sends_typed_text_counts(monkeypatch, variant):
    url = f"https://akasya-j01.com/v10/{variant}"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(LOGO + J01[variant], title="İnternet Şubesi"))})
    assert result["risk_level"] != "LOW" and coverage(result) == "partial", names(result["reasons"])


LURE_LINK = f"<a href='{TARGET_URL}'>Devam et</a>"


@pytest.mark.parametrize("body", [
    "<h2>Garanti BBVA</h2><p>Tebrikler, ödül kazandınız.</p>" + LURE_LINK,          # tuzak ifadesi listede yok
    "<img src='/l.png' alt='Garanti BBVA'><p>İşleminize devam edin.</p>" + LURE_LINK,
])
def test_j02_body_brand_lure_without_listed_phrase_is_followed(monkeypatch, body):
    url = "https://leylak-j02.com/v10/y"
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, doc(body, title="Kampanya"))}))
    assert TARGET_URL in [c["url"] for c in calls]
    assert_caught(result, 50)


def test_j02_image_only_lure_with_bait_phrase(monkeypatch):
    """Kurum adi gorselde: tuzak ifadesi + bilgi isteyen hedef sayfa en az "Dikkat"tir."""
    url = "https://leylak-j02.com/v10/g"
    page = doc(LOGO + "<p>Hesabınız kısıtlandı.</p>" + LURE_LINK, title="Bilgi")
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, page)}))
    assert TARGET_URL in [c["url"] for c in calls]
    assert result["risk_level"] not in ("LOW", "UNKNOWN"), (result["risk_score"], names(result["reasons"]))


def test_j02_unfollowable_link_is_not_a_full_inspection(monkeypatch):
    url = "https://leylak-j02.com/v10/t"
    token = "https://hedef-j02.com/x?token=abcdefghijklmnop1234"
    page = doc("<h2>Garanti BBVA</h2><p>İşleminize devam edin.</p>" + f"<a href='{token}'>Devam et</a>", title="Bilgi")
    result, calls = run(monkeypatch, url, {url: (200, HTML, page)})
    assert len(calls) == 1                                    # belirtecli baglantiya dokunulmaz (G-12)
    assert result["risk_level"] != "LOW" and "unfollowed_link" in result["ioc_details"]["inspection_gaps"]
    # Hedef indirilemiyorsa da ayni
    url2 = url + "2"
    page = doc("<h2>Garanti BBVA</h2><p>İşleminize devam edin.</p><a href='https://yok-j02.com/x'>Devam et</a>", title="Bilgi")
    result, _ = run(monkeypatch, url2, {url2: (200, HTML, page), "https://yok-j02.com/x": (200, {"content-type": "application/pdf"}, b"%PDF")})
    assert result["risk_level"] != "LOW"


def test_j02_plain_page_with_links_is_untouched(monkeypatch):
    """Karsi ornek: kurum adi ve tuzak ifadesi tasimayan sayfanin baglantilarina dokunulmaz."""
    url = "https://kumsal-j02.com/"
    page = doc("<h1>Kumsal Atölye</h1><p>Seramik kursları başladı.</p><a href='/kurslar'>Kurslar</a> <a href='/iletisim'>İletişim</a>")
    result, calls = run(monkeypatch, url, {url: (200, HTML, page)})
    assert len(calls) == 1 and coverage(result) == "full" and result["risk_level"] == "LOW"


# --- 11. tur: kalan bulgular ----------------------------------------------------------------------

def test_k01_brand_written_by_external_stylesheet(monkeypatch):
    url, css = "https://nar-k01.com/v11/s", "https://nar-k01.com/s.css"
    page = doc("<div class=b></div>" + PW, head="<link rel=stylesheet href='/s.css'>")
    pages = {url: (200, HTML, page), css: (200, {"content-type": "text/css"}, ".b::before{content:'" + NAME + "'}")}
    result, calls = run(monkeypatch, url, pages)
    sheet = [c for c in calls if c["url"] == css]
    assert sheet and sheet[0]["headers"]["Accept"].startswith("text/css") and sheet[0]["headers"]["Sec-Fetch-Dest"] == "style"
    assert_caught(result)


def test_k01_password_mask_in_external_stylesheet_and_html_in_css_is_inert(monkeypatch):
    url, css = "https://nar-k01.com/v11/m", "https://nar-k01.com/m.css"
    page = doc(LOGO + "<form action='/ara'><input name=q class=m></form>", head="<link rel=stylesheet href='/m.css'>")
    pages = {url: (200, HTML, page),
             css: (200, {"content-type": "text/css"}, ".m{-webkit-text-security:disc}</style><h1>" + NAME + "</h1>")}
    result, _ = run(monkeypatch, url, pages)
    assert "Şifre" in (result["ioc_details"].get("page_fields") or [])
    assert result["ioc_details"]["target_brand"] is None and result["risk_level"] == "UNKNOWN"


def test_k02_interstitial_requests_its_image_before_following(monkeypatch):
    a, b, px = "https://menekse-k02.com/v11/t4", "https://menekse-k02.com/v11/t5", "https://menekse-k02.com/px.gif"
    seen = []

    def handler(request):
        seen.append(request["url"])
        if request["url"] == a:
            return 200, HTML, LOADING % f"<meta http-equiv='refresh' content='0; url={b}'>".replace("</head>", "") \
                + "", []
        if request["url"] == px:
            return 200, {"content-type": "image/gif"}, b"GIF89a", []
        return 200, HTML, doc(BODY) if px in seen else PLAIN, []

    page_a = (LOADING % f"<meta http-equiv='refresh' content='0; url={b}'>").replace("</body>", "<img src='/px.gif'></body>")

    def handler2(request):
        seen.append(request["url"])
        if request["url"] == a:
            return 200, HTML, page_a, []
        if request["url"] == px:
            return 200, {"content-type": "image/gif"}, b"GIF89a", []
        return 200, HTML, doc(BODY) if px in seen else PLAIN, []

    result, calls = run(monkeypatch, a, handler=handler2)
    assert [c["url"] for c in calls] == [a, px, b]
    assert calls[1]["headers"]["Accept"].startswith("image/")
    assert_caught(result)


def test_k03_image_and_link_only_page_is_not_a_full_inspection(monkeypatch):
    url = "https://leylak-k03.com/v11/g"
    page = doc(LOGO + f"<a href='{TARGET_URL}'><img src='/devam.png'></a>", title="Bilgi")
    result, calls = run(monkeypatch, url, dict(TARGET, **{url: (200, HTML, page)}))
    assert len(calls) == 1                                    # kimlik yok: baglantiya dokunulmaz (G-12)
    assert result["risk_level"] != "LOW" and "visual_only" in result["ioc_details"]["inspection_gaps"]


def test_k04_select_only_get_form_is_not_a_data_collecting_form(monkeypatch):
    url = "https://kumsal-k04.com/"
    page = doc("<h1>Kumsal Atölye</h1><form action='/dil'><select name=l><option>TR</option><option>EN</option></select>"
               "<button>Git</button></form><p>Merhaba.</p>")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert coverage(result) == "full" and result["risk_level"] == "LOW"


@pytest.mark.parametrize("heading,expected", [
    ("UPS Sistemleri Bayi Girişi", None), ("BIM Yönetim Paneli", None), ("SGK Evrak Takip", None),
    ("ING", "ING"), ("ING Bank", "ING"), ("PTT Kargo Takip", "PTT"),
])
def test_k05_acronym_needs_brand_context(monkeypatch, heading, expected):
    url = "https://bayi-k05.com/uye"
    result, _ = run(monkeypatch, url, {url: (200, HTML, doc(f"<h2>{heading}</h2>" + PW, title="Panel"))})
    target = result["ioc_details"]["target_brand"]
    if expected is None:
        assert target is None and result["risk_level"] == "UNKNOWN", (target, result["risk_score"])
    else:
        assert expected in (target or "") and result["risk_score"] >= 50


def test_k06_padded_lure_with_same_site_action_link_is_followed(monkeypatch):
    url, nxt = "https://leylak-k06.com/v11/dolgu", "https://leylak-k06.com/v11/adim2"
    nav = "".join(f"<a href='/s{i}'>Bölüm {i}</a> " for i in range(12))
    fill = "".join(f"<p>Yasal uyarı metni {i}: hizmet koşulları ve gizlilik bildirimi geçerlidir, ayrıntılar için sözleşmeye bakınız.</p>"
                   for i in range(20))
    page = doc(f"<h1>{NAME}</h1><p>Hesabınıza erişim geçici olarak durdurulmuştur.</p><a href='/v11/adim2'>Devam et</a>" + nav + fill)
    result, calls = run(monkeypatch, url, {url: (200, HTML, page), nxt: (200, HTML, doc(CARD, title=NAME))})
    assert nxt in [c["url"] for c in calls]
    assert_caught(result, 50)


def test_k07_later_refresh_tag_with_shorter_or_equal_delay_wins_like_chromium(monkeypatch):
    """Chromium 156 olcumu: '5; url=/A' + '0; url=/B' -> /B ve '0; url=/A' + '0; url=/B' -> /B."""
    for first in ("5", "0"):
        url = f"https://menekse-k07.com/v11/m{first}"
        head = f"<meta http-equiv='refresh' content='{first}; url=/v11/iyi'><meta http-equiv='refresh' content='0; url={TARGET_URL}'>"
        pages = dict(TARGET, **{url: (200, HTML, LOADING % head), "https://menekse-k07.com/v11/iyi": (200, HTML, PLAIN)})
        result, calls = run(monkeypatch, url, pages)
        assert [c["url"] for c in calls][-1] == TARGET_URL
        assert_caught(result, 50)
    # Sonraki etiketin gecikmesi daha UZUNSA ilk etiket gecerlidir
    assert page_probe._first_refresh(["0; url=/a", "5; url=/b"])[:2] == (0, "/a")


# --- 12. tur: alt kaynak yukleyicisi ve arama kutusu ayrimi -------------------------------------------

def test_l01_redirected_stylesheet_is_followed_and_lure_pages_load_stylesheets(monkeypatch):
    url = "https://nar-l01.com/v12/y"
    css1, css2 = "https://nar-l01.com/s.css", "https://cdn-l01.com/gercek.css"
    page = doc("<div class=b></div><p>Tebrikler, ödül kazandınız.</p>" + LURE_LINK, title="Kampanya",
               head="<link rel=stylesheet href='/s.css'>")
    pages = dict(TARGET, **{url: (200, HTML, page), css1: (302, {"location": css2}, ""),
                            css2: (200, {"content-type": "text/css"}, ".b::before{content:'Garanti BBVA'}")})
    result, calls = run(monkeypatch, url, pages)
    assert [c["url"] for c in calls][:3] == [url, css1, css2] and TARGET_URL in [c["url"] for c in calls]
    assert_caught(result, 50)


def test_l01_subresource_gets_a_short_deadline_and_no_client_penalty(monkeypatch):
    url, css = "https://nar-l01.com/v12/yavas", "https://nar-l01.com/yavas.css"
    import backend.core.analyzer_interface as ai

    seen = {}

    def fetch(target, deadline, pinned=None):
        seen[target] = deadline - page_probe.time.monotonic()
        if target == css:
            raise page_probe._FetchError("budget exhausted")
        return page_probe._Response(200, HTML, doc(BODY, head="<link rel=stylesheet href='/yavas.css'>").encode("utf-8"))

    monkeypatch.setattr(page_probe, "_fetch_once", fetch)
    page_probe._cache.clear()
    monkeypatch.setattr(ai, "resolve_ip", lambda d: "93.184.216.34")
    monkeypatch.setattr(ai, "resolve_all_public", lambda d: ["93.184.216.34"])
    monkeypatch.setattr(ai, "lookup_domain_registration", lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "valid")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation", lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    result = ai.analyze_url_pipeline(url)
    assert seen[css] <= page_probe.SUBRESOURCE_SECONDS + 0.01 < seen[url]
    assert_caught(result)                                      # takilan stil sayfasi sayfanin bulgularini silmez


def test_l02_single_field_named_like_a_search_box_on_a_bare_page(monkeypatch):
    url = "https://akasya-l02.com/v12/q"
    page = doc(LOGO + "<form action='/p'><input name=q><button>Devam</button></form>", title="İnternet Şubesi")
    result, _ = run(monkeypatch, url, {url: (200, HTML, page)})
    assert result["risk_level"] != "LOW" and coverage(result) == "partial"
