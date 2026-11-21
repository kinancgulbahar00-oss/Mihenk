"""Aciklanabilir risk skorlama motoru.

Model
-----
Her sinyal, tek basina gozlendiginde gostergenin zararli olma olasiligini temsil
eden bir agirlik ``p`` (0-1) tasir. Sinyaller "noisy-OR" ile birlesir:

    risk = 1 - prod(1 - p_i) = 1 - exp(-sum(lambda_i)),   lambda_i = -ln(1 - p_i)

Bu sayede:
  * skor hicbir zaman 100'u asmaz ve her yeni sinyal azalan getiriyle eklenir,
  * sinyallerin sirasi sonucu degistirmez,
  * log-uzayinda katkilar toplanabilir oldugu icin her bulgunun skora kac puan
    kattigi tam olarak (lambda payi ile) hesaplanabilir.

Guven artiran sinyaller (eski alan adi, temiz VirusTotal sonucu) carpan olarak
uygulanir ve yalnizca kesin kanit (VirusTotal tespiti, marka taklidi) yoksa
devreye girer. Kesin kanitlar icin alt sinirlar (floor) tanimlidir.
"""

import ipaddress
import math
import re

from urllib.parse import parse_qs, unquote, urlsplit

from backend.core.brands import (
    ascii_host, detect_brand, detect_brand_in_content, detect_fake_suffix, detect_unlisted_gov,
    homograph_of, is_restricted, is_user_content_path, lure_words, official_brand, owner_brand, registered_domain,
    sector_label, user_content_boundary,
)
from backend.core.hostnames import to_unicode
from backend.core.suffixes import SHORTENERS as _SHORTENERS

# ---------------------------------------------------------------------------
# Bilgi tabanlari
# ---------------------------------------------------------------------------

# Kimlik avi sayfalarinin URL'lerinde sik gecen ifadeler (Turkce ve Ingilizce)
BAIT_WORDS = (
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security",
    "update", "account", "banking", "wallet", "password", "auth", "confirm", "unlock",
    "support", "billing", "invoice", "refund",
    "giris", "dogrula", "dogrulama", "guvenlik", "guvenli", "hesap", "sifre", "odeme",
    "iade", "musteri", "basvuru", "aidat", "ceza", "takip",
)

# Kotuye kullanim oranlari yuksek ust seviye alan adlari
RISKY_TLDS = (
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "icu", "cyou", "buzz",
    "rest", "click", "online", "site", "live", "shop", "support", "monster", "sbs", "cfd",
)

SHORTENERS = tuple(sorted(_SHORTENERS))

# Seviye esikleri
LEVELS = ((75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW"))


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------

def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def level_for(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "LOW"


# ---------------------------------------------------------------------------
# Sinyal toplama
# ---------------------------------------------------------------------------

def _signal(key, rule_name, description, severity, p):
    return {"key": key, "rule_name": rule_name, "description": description, "severity": severity, "p": p}


BRAND_KINDS = {
    "label": ("Marka taklidi", "critical", 0.80),
    "glyph": ("Görsel benzer karakterle marka taklidi", "critical", 0.80),
    "typo": ("Yazım benzeri marka taklidi", "critical", 0.70),
    "subdomain": ("Alt alan adında marka kullanımı", "high", 0.60),
    "path": ("Adres yolunda marka adı", "medium", 0.35),
}

# Bu sinyallerden biri varsa guven artiranlar (eski alan adi, temiz VT) uygulanmaz
HARD_EVIDENCE = {"vt", "brand", "content_brand", "exfil", "fake_suffix", "gov_unlisted", "homograph", "official_young"}

# Katalogdaki resmi adres bu kadar gunden yeni kayitliysa resmi adres guveni verilmez (B-07): suresi
# dolan ya da katalogda yanlis yazilan bir ad baskasi tarafindan kaydedilmis olabilir
OFFICIAL_MIN_AGE_DAYS = 90

# Sayfa yoklamasi yalnizca bu portlara yapilir (Y-09); digerleri sinyal olarak raporlanir
STANDARD_PORTS = (None, 80, 443)

# Sayfa indirilemedi/ayristirilamadi: analiz edilemeyen adres guvenli gibi gorunmemeli (Z-02)
UNINSPECTED_PAGE_STATUSES = {
    "error": "Sayfa indirilemedi veya ayrıştırılamadı.",
    "blocked": "Sayfa indirilemedi.",
    "too_many_redirects": "Sayfa çok sayıda yönlendirme yaptığı için indirilemedi.",
    "target_busy": "Aynı sunucuya yönelik başka bir yoklama sürdüğü için sayfa indirilmedi.",
    "slow_target": "Sunucu yakın zamanda süre sınırını aştığı için sayfa yeniden indirilmedi.",
    # Indirme basarili, icerik HTML olarak islenemedi (B-01): bu durum "incelendi" sayilmaz
    "not_html": "Sunucunun yanıtı HTML olarak işlenemedi (içerik türü veya kodlama tanınmadı).",
    "empty": "Sunucu boş bir sayfa döndürdü.",
    # Yonlendirme zinciri standart disi bir porta gitti; hedef indirilmedi (A-14)
    "port_not_allowed": "Adres standart dışı bir porta yönlendirdiği için hedef sayfa indirilmedi.",
}
# Statik ayristiricinin goremedigi yapilar (A-01). 'script' burada yoktur: betik yalnizca kapsami dusurur,
# gorunur icerigi olmayan betikli sayfa ayrica "betikle uretiliyor" bulgusunu alir.
OPAQUE_REASONS = {
    "frame": "incelenemeyen gömülü belge (iframe/frame/object/embed)",
    "truncated": "yanıt boyut sınırında kesildi; devamı okunmadı",
    "xml_dtd": "XML belge içi tanımları (DTD varlığı, varsayılan öznitelik ya da XSLT/CSS bildirimi) işlenmedi",
    "delayed_refresh": "uzun gecikmeli ya da çözümlenemeyen yönlendirme izlenmedi",
    # E-01..E-05: tarayicinin baska bir belge gorebilecegi durumlar
    "xml": "belge XML türünde (XHTML/SVG); tarayıcı XML ayrıştırıcısıyla işler",
    "charset": "karakter kodlaması tanınmadı ya da güvenilir biçimde çözülemedi; tarayıcı farklı bir metin görebilir",
    "parser": "belge süre sınırı içinde ayrıştırılamadı",
    "parse_mismatch": "sayfa kaynağında form, parola alanı ya da çerçeve var ancak ayrıştırılan belgede yok",
    "self_refresh": "sayfa kendini yeniliyor; yenileme sonrasındaki hali izlenemedi",
    "refresh_conflict": "sayfada farklı hedefler gösteren birden fazla yönlendirme etiketi var",
    "unfollowed_link": "sayfanın yönlendirdiği bağlantı izlenemedi",
    "visual_only": "sayfa neredeyse yalnızca görsel ve bağlantıdan oluşuyor; görseldeki metin okunamadı",
}
# Tek tek yonetilen kisitli uzantilar (okul, belediye, universite, avukat ve hekim siteleri): merkezi kurum
# adlarina (gov.tr, tsk.tr ...) gore daha zayif bir guven sinyalidir (E-13)
INDIVIDUALLY_MANAGED_SUFFIXES = ("k12.tr", "bel.tr", "edu.tr", "av.tr", "dr.tr")
# "Incelenemedi" bulgulari guven artiran sinyallerle azaltilmaz (A-13): koklu alan adi, icerigi gorulemeyen
# sayfa hakkinda bilgi vermez
UNINSPECTED_KEYS = ("page_uninspected", "script_content", "page_opaque")
# Sayfaya ulasildi (yonlendirme zinciri ve son adres biliniyor)
REACHED_PAGE_STATUSES = {"ok", "not_html", "empty", "download"}

# Bilinen acik yonlendirme yollari (B-06): hedef adres ayiklanip ayrica degerlendirilir
OPEN_REDIRECTS = (
    (("google.com", "google.com.tr"), "/url", ("q", "url")),
    (("youtube.com",), "/redirect", ("q",)),
    (("facebook.com",), "/l.php", ("u",)),
    (("linkedin.com",), "/redir/redirect", ("url",)),
    (("vk.com",), "/away.php", ("to",)),
)


def _brand_signal(match, age):
    brand = match["brand"]
    gov = bool(brand.get("gov"))
    title, severity, p = BRAND_KINDS[match["kind"]]
    if gov and match["kind"] in ("label", "glyph", "typo"):
        title, p = "Kamu kurumu taklidi", max(p, 0.85)
    official = ", ".join(brand["domains"][:3]) or "katalogda doğrulanmış resmi adres yok"
    where = {
        "label": f"Alan adı '{match['token']}' ifadesiyle {brand['name']} kurumunu çağrıştırıyor",
        "glyph": f"Alan adındaki '{match['detail']}' ifadesi rakam ya da benzer harflerle '{match['token']}' yazımını taklit ediyor",
        "typo": f"Alan adındaki '{match['detail']}' ifadesi '{match['token']}' ({brand['name']}) yazımına çok yakın",
        "subdomain": f"'{match['token']}' ({brand['name']}) alt alan adı olarak kullanılmış; kayıtlı alan adı kuruma ait değil",
        "path": f"Adres yolunda '{match['token']}' ({brand['name']}) geçiyor; alan adı kuruma ait değil",
    }[match["kind"]]
    suffix = " veya .gov.tr uzantıları" if gov else ""
    desc = f"{where}. Resmi adres: {official}{suffix}."

    # Koklu alan adlari: marka adi gecse de genellikle mesrudur (bayi, servis, haber sitesi)
    if age is not None and age >= 1095 and match["kind"] in ("label", "glyph", "typo", "path"):
        return _signal("brand_aged", f"{brand['name']} adı geçiyor (köklü alan adı)",
                       f"{where}; ancak alan adı yaklaşık {age // 365} yıldır kayıtlı. Bayi, servis ya da içerik sitesi olabilir.",
                       "medium", 0.20)
    key = "brand" if match["kind"] != "path" else "brand_path"
    return _signal(key, f"{title}: {brand['name']}", desc, severity, p)


def page_fully_inspected(page):
    """Sayfa icerigi indirildi ve statik incelemenin goremedigi bir yapi yok (bkz. inspection_coverage)."""
    page = page or {}
    return page.get("status") == "ok" and not (
        page.get("script_rendered") or page.get("opaque") or page.get("truncated"))


def _merge_signals(signals, extra):
    """Ayni anahtarli sinyal iki kez sayilmaz (noisy-OR'da cift sayim olurdu): agirligi yuksek olan kalir."""
    for sig in extra:
        existing = next((i for i, s in enumerate(signals) if s["key"] == sig["key"]), None)
        if existing is None:
            signals.append(sig)
        elif sig["p"] > signals[existing]["p"]:
            signals[existing] = sig


def _content_signals(page, doc_host, trusted_doc, restricted, context, set_target, signals, prefix="",
                     redirecting=False):
    """Tek bir belgenin icerik bulgulari: kurum kimligi, hassas form, veri sizdirma kodu, dis form.
    Son belge ve yonlendirmeden onceki her belge icin ayri ayri cagrilir (D-01). Doner: (content, harvest)."""
    content = detect_brand_in_content(dict(page, final_host=doc_host))
    sensitive = [f for f in page.get("fields", []) if f != "Telefon"]
    harvest = False
    ambiguous = False
    if content and content.get("ambiguous"):
        # Sayfa hassas bilgi istiyor ve govdesinde birden fazla kurum, hicbiri baskin olmadan geciyor (E-08).
        # Odeme sayfalari da boyle gorunebilir; bu nedenle kesin kanit degil, dusuk agirlikli bir bulgudur.
        ambiguous = True
        signals.append(_signal("content_multi", f"{prefix}Birden fazla kurum kimliği taşıyan form",
                               f"Sayfa ({doc_host}) hassas bilgi istiyor ve metninde birden fazla kurumun adı geçiyor: "
                               f"{', '.join(content.get('brands', [])[:4])}. Hangi kurumun taklit edildiği "
                               f"belirlenemedi; sayfa bu kurumların hiçbirine ait değil.",
                               "medium", 0.25))
        content = None
    if content and (page.get("hidden_chars") or content.get("obfuscated")):
        signals.append(_signal("hidden_chars", f"{prefix}Kurum adı gizlenerek yazılmış",
                               f"Sayfanın başlığında '{content['brand']['name']}' adı ekranda görünmeyen ya da yön "
                               f"değiştiren karakterlerle, ya da harfleri ayrılarak yazılmış; içerik denetimini "
                               f"atlatmak için kullanılır.",
                               "high", 0.40))
    if content and content["zone"] == "identity":
        # Kurum adi yalnizca baslikta geciyorsa (haber, blog, bayi sayfasi) tek basina kesin kanit
        # degildir (B-10): sayfa bilgi istemiyor, belirgin bir dis baglanti tasimiyor, dosya indirmiyor,
        # yonlendirmiyor ve icerigi betikle uretilmiyorsa dusuk agirlikli bir not olur.
        # Belirleyici isaretler (A-04): taninan hassas alan olmasa da form/dugme/metin girdisi tasiyan kisa
        # sayfa, dis adrese giden form ve gizlenmis ad "yalnizca ad geciyor" sayilmaz.
        decisive = (sensitive or page.get("prominent_external_link") or page.get("exfil") or page.get("download")
                    or page.get("script_rendered") or page.get("script_redirect") or page.get("hidden_chars")
                    or page.get("interactive") or page.get("external_form_hosts") or content.get("obfuscated")
                    # G-09: sayfa metnindeki tuzak ifadeleri ("hesabiniz kisitlandi", "kimliginizi dogrulayin") ve
                    # baglantinin gittigi sayfadaki hassas form, yem sayfasini uzunlugundan ve baglanti sayisindan
                    # bagimsiz olarak belirleyici kilar. G-04: sirasi degistirilmis metin haber sayfasinda gorulmez.
                    or page.get("bait_text") or page.get("linked_sensitive") or page.get("reordered")
                    or redirecting)
        if not decisive:
            b = content["brand"]
            signals.append(_signal("content_brand_mention", f"{prefix}Sayfa başlığında {b['name']} adı geçiyor",
                                   f"Sayfanın başlık veya site adı alanında '{content['term']}' geçiyor; sayfa {doc_host} "
                                   f"üzerinde; form, düğme ya da belirgin bir dış bağlantı içermiyor. Haber, blog veya "
                                   f"bayi sayfası olabilir.",
                                   "medium", 0.15))
            content = None
    weak = bool(content and content.get("weak"))
    if weak:
        # Zayif kanit: logo / baslik ogesindeki uc-bes harfli kisaltma ('ING', 'PTT'; ama 'UPS Sistemleri' de). Baska
        # anlamlar da tasir; tek basina "taklit" hukmu vermez, "Dikkat/Şüpheli" duzeyinde bir bulgudur.
        b = content["brand"]
        signals.append(_signal("content_brand_weak", f"{prefix}Sayfada {b['name']} adına benzeyen ifade",
                               f"Sayfada ({doc_host}) '{content['term']}' ifadesi geçiyor; {b['name']} kurumunu "
                               f"çağrıştırıyor olabilir, ancak ifade başka anlamlar da taşır. Kurumun resmi adresi "
                               f"{', '.join(b['domains'][:2]) or 'katalogda doğrulanmamış'}.",
                               "medium", 0.35))
        set_target(b)
        content = None
    if content:
        b = content["brand"]
        zone = {"identity": "başlık veya site adı", "logo": "logo görselleri", "body": "sayfa metni"}[content["zone"]]
        signals.append(_signal("content_brand", f"{prefix}Sayfa {b['name']} kimliği taşıyor",
                               f"Sayfanın {zone} alanında '{content['term']}' geçiyor ancak sayfa {doc_host} "
                               f"üzerinde; kurumun resmi adresi {', '.join(b['domains'][:2]) or 'katalogda doğrulanmamış'}.",
                               "critical" if content["zone"] != "body" else "high",
                               {"identity": 0.70, "logo": 0.60, "body": 0.45}[content["zone"]]))
        set_target(b)

    # Son adres resmi adres degilse (yonlendirme, kisa baglanti) resmi adres muafiyeti yoktur
    if sensitive and (not trusted_doc or content):
        impersonating = bool(content or context["target_brand"])
        card_or_id = page.get("card_input") or page.get("tckn_input")
        if restricted and not content:
            # Kamu siteleri T.C. kimlik no isteyebilir; kart bilgisi isteyen .gov.tr/.k12.tr
            # sayfasi ise ele gecirilmis site belirtisidir
            card_or_id = page.get("card_input")
        if impersonating or card_or_id or ambiguous:
            p = 0.45 if impersonating else 0.30
            harvest = True
            signals.append(_signal("harvest", f"{prefix}Hassas bilgi toplayan form",
                                   f"Sayfa ({doc_host}) şu bilgileri istiyor: {', '.join(sensitive)}.",
                                   "high", p))

    if page.get("exfil"):
        signals.append(_signal("exfil", f"{prefix}Veri sızdırma kodu",
                               f"Sayfa kaynağında {page['exfil']} adresi var; oltalama kitleri girilen bilgileri "
                               f"bu yolla saldırgana iletir.",
                               "critical", 0.85))

    if sensitive and page.get("external_form_hosts"):
        signals.append(_signal("form_external", f"{prefix}Form başka alan adına gönderiliyor",
                               f"Hassas alanlar içeren form verileri {', '.join(page['external_form_hosts'][:3])} "
                               f"adresine gönderiliyor.",
                               "medium", 0.25))
    return content, harvest


def collect_signals(parsed, intel):
    """parsed: url/host/path; intel: harici kaynak ve sayfa yoklamasi sonuclari.
    Doner: (sinyaller, guven artiranlar, baglam)."""
    # Alan adi hattin basinda kanonik ASCII (Punycode) bicime getirilmistir
    host = ascii_host(parsed["domain"])
    # Kanonik adreste yol yuzde kodludur (Z-02); tespit, tarayicinin gosterdigi metin uzerinden
    # yapilir. '%67iris' gibi kodlamalarla ifade gizlenemez.
    url_lower = unquote(parsed["url"]).lower()
    path = unquote(parsed.get("rest", "") or parsed.get("path", ""))
    # Kullanici icerigi sunan adreste (x.blogspot.com, kova.s3.amazonaws.com) kayit yasi platforma
    # aittir; icerigi yayimlayan kisi hakkinda bilgi vermez ve guven sinyali olarak kullanilmaz (Z-01)
    platform_hosted = not _is_ip(host) and bool(user_content_boundary(host))
    age = None if platform_hosted else intel.get("age_days")
    page = intel.get("page") or {}
    signals = []
    mitigations = []
    context = {"target_brand": None, "target_sector": None, "unverified_form": False}

    def set_target(brand):
        if not context["target_brand"]:
            context["target_brand"] = brand["name"]
            context["target_sector"] = sector_label(brand["sector"])

    # --- Resmi adres -----------------------------------------------------------
    ip_host = _is_ip(host)
    # '@' iceren adreslerde 'resmi alan adi' indirimi uygulanmaz
    has_userinfo = "@" in parsed.get("authority", "")
    # Resmi adres: kurumun KENDI icerigini sundugu alan. Herkesin icerik yayimlayabildigi
    # alanlar (blogspot.com alt alan adlari, S3 kovalari, kisa baglantilar) burada None doner (Z-01).
    own = None if ip_host or has_userinfo else official_brand(host)
    # Adresin sahibi (resmi ya da kullanici icerigi alani): sahibin adi taklit sayilmaz
    owner = None if ip_host or has_userinfo else owner_brand(host)

    # Katalogdaki resmi adres yakin zamanda kaydedilmis (B-07): resmi adres guveni verilmez
    if own and age is not None and age < OFFICIAL_MIN_AGE_DAYS:
        signals.append(_signal("official_young", f"{own['name']} resmi adresi yakın zamanda kaydedilmiş",
                               f"{host} katalogda {own['name']} kurumunun resmi adresi olarak kayıtlı, ancak alan adı "
                               f"{age} gün önce kaydedilmiş. Süresi dolan ya da yanlış yazılan bir ad başkası tarafından "
                               f"kaydedilmiş olabilir; resmi adres güveni uygulanmadı.",
                               "high", 0.50))
        set_target(own)
        own = None
    # Guvenilen adin altindaki bilinen kullanici icerigi yolu (A-06): sahibi bilinir, guven verilmez
    if own and is_user_content_path(host, parsed.get("path") or ""):
        own = None
    restricted = not ip_host and not own and is_restricted(host)

    # Bilinen acik yonlendirme (B-06): resmi adresin guveni hedefe tasinmaz, hedef ayrica degerlendirilir
    redirect_target = None if ip_host else _open_redirect_target(host, parsed)
    if redirect_target:
        signals.append(_signal("open_redirect", "Bilinen açık yönlendirme",
                               f"Adres {registered_domain(host)} üzerindeki bir yönlendirme yolu; kullanıcıyı "
                               f"{redirect_target['url'][:120]} adresine gönderir. Hedef adres ayrıca analiz edilmeli.",
                               "medium", 0.25))
        target_match = detect_brand(redirect_target["host"], "") if not official_brand(redirect_target["host"]) else None
        if target_match:
            sig = _brand_signal(target_match, None)
            sig["description"] = f"Yönlendirme hedefinde: {sig['description']}"
            signals.append(sig)
            set_target(target_match["brand"])

    # Sayfa baska bir alan adina yonlendirdiyse resmi adres guveni son adrese tasinmaz
    # (resmi sitedeki acik yonlendirme, kisa baglanti)
    final_owner_differs = bool(redirect_target)
    if page.get("status") in REACHED_PAGE_STATUSES and page.get("final_host"):
        final_ascii = ascii_host(page["final_host"])
        if registered_domain(final_ascii) != registered_domain(host):
            final_official = official_brand(final_ascii)
            final_owner_differs = final_owner_differs or not (own and final_official and final_official["id"] == own["id"])

    # --- Kurum taklidi (URL) -----------------------------------------------
    if ip_host:
        signals.append(_signal("ip_host", "Alan adı yerine IP adresi",
                               "Bağlantı bir alan adı yerine doğrudan IP adresine gidiyor; meşru hizmetlerde nadirdir.",
                               "high", 0.45))

    fake = None if ip_host else detect_fake_suffix(host)
    if fake:
        signals.append(_signal("fake_suffix", "Sahte resmi uzantı",
                               f"Alan adı '{fake}' ifadesini taşıyor ancak gerçek uzantısı {registered_domain(host)}; "
                               f"resmi kurum adresi izlenimi vermek için kullanılır.",
                               "critical", 0.75))

    # --- Benzer harfle resmi adres taklidi (Y-01) ---------------------------
    # Gorunusu resmi adresle ayni, ASCII bicimi farkli: en guclu taklit sinyali
    homograph = None if ip_host or own else homograph_of(host)
    if homograph:
        hb = homograph["brand"]
        who = hb["name"] if hb else "Kamu kurumu"
        shown = to_unicode(host)
        signals.append(_signal("homograph", f"Benzer harfle resmi adres taklidi: {who}",
                               f"'{shown}' adresi görünüşte {homograph['official']} ile aynı, ancak gerçek alan adı "
                               f"{host}; kuruma ait değil. Türkçe, aksanlı ya da Kiril/Yunan harf eklenerek resmi "
                               f"adres taklit ediliyor.",
                               "critical", 0.90))
        if hb:
            set_target(hb)
        else:
            context["target_brand"] = "Kamu kurumu (resmi uzantı taklidi)"
            context["target_sector"] = sector_label("government")

    match = None if ip_host or own or owner or homograph else detect_brand(host, path)
    if match:
        sig = _brand_signal(match, age)
        signals.append(sig)
        if sig["key"] != "brand_aged":
            set_target(match["brand"])
    elif not ip_host and not own and not owner and not homograph:
        entity = detect_unlisted_gov(host, path)
        if entity:
            signals.append(_signal("gov_unlisted", "Kamu kurumu izlenimi",
                                   f"Adres '{entity}' ifadesini kamu hizmeti tuzak kelimeleriyle birlikte kullanıyor; "
                                   f"resmi kurumlar .gov.tr veya .bel.tr uzantılarını kullanır.",
                                   "high", 0.55))
            context["target_brand"] = "Kamu kurumu (katalog dışı)"
            context["target_sector"] = sector_label("government")

    # --- Sayfa icerigi --------------------------------------------------------
    # Icerik denetimleri hicbir guven sinyaliyle kapatilmaz (Z-01): resmi adres veya kisitli
    # uzanti uzerinde BASKA bir kurumun kimligini tasiyan ya da hassas bilgi isteyen sayfa,
    # guven indirimini de devre disi birakir.
    content = None
    harvest = False
    if page.get("status") in REACHED_PAGE_STATUSES:
        final_host = ascii_host(page.get("final_host") or host)
        final_reg = registered_domain(final_host)
        if final_reg != registered_domain(host):
            note = ""
            if page.get("steps") and official_brand(final_host):
                note = (f" Son sayfanın içeriği {final_host} resmi sitesinden alındı; ilk adresin içeriği ayrıca "
                        f"incelendi ve bulguları aşağıda.")
            signals.append(_signal("redirect", "Başka alan adına yönlendirme",
                                   f"Adres ziyaret edildiğinde {final_host} alan adına yönlendiriyor.{note}",
                                   "low", 0.08))
            if not match:
                final_match = detect_brand(final_host, "")
                if final_match:
                    sig = _brand_signal(final_match, None)
                    sig["description"] = f"Yönlendirilen alan adında: {sig['description']}"
                    signals.append(sig)
                    set_target(final_match["brand"])

    if page.get("status") == "ok":
        final_host = ascii_host(page.get("final_host") or host)
        trusted_final = own and not final_owner_differs
        content, harvest = _content_signals(page, final_host, trusted_final, restricted, context, set_target, signals)
        if page.get("url_tricks"):
            # Yonlendirme / cerceve adresi, inceleme araclarinin ve tarayicinin FARKLI sitelere cozdugu bicimde
            # yazilmis (E-03): ters egik cizgi, fazladan egik cizgi, kullanici bilgisi. Mesru sitelerde gorulmez.
            trick = page["url_tricks"][0]
            signals.append(_signal("redirect_obfuscation", "Yönlendirme adresinde gizlenmiş karakter",
                                   f"Sayfanın yönlendirme ya da çerçeve adresi ('{trick.get('value', '')[:80]}') ters eğik "
                                   f"çizgi, fazladan eğik çizgi ya da '@' içeriyor; tarayıcı bu adresi "
                                   f"{trick.get('target', '')[:120]} olarak açar. Bağlantının analiz araçlarında başka "
                                   f"bir siteye gidiyor görünmesi için kullanılır.",
                                   "high", 0.35))
        if page.get("script_rendered") and not page.get("script_redirect"):
            # Icerik betikle uretiliyor (B-02): JavaScript calistirilmadigi icin tarayicinin gosterecegi
            # sayfa incelenemedi. Bu durum "Dusuk risk" sayilmaz.
            signals.append(_signal("script_content", "Sayfa içeriği betikle üretiliyor; incelenemedi",
                                   "Sayfanın görünür metni ve formu yok; içerik tarayıcıda JavaScript ile oluşturuluyor. "
                                   "Mihenk betik çalıştırmadığı için kimlik avı içeriği, form ve yönlendirme hedefi "
                                   "denetlenemedi. Oltalama kitleri içeriği bu yolla gizler; bağlantıyı açmadan önce "
                                   "doğrulayın.",
                                   "medium", 0.30))
        # Statik ayristiricinin goremedigi yapilar (A-01): gomulu belge, kesilen govde, XML tanimlari,
        # uzun gecikmeli yonlendirme. Sayfa "tam incelendi" sayilmaz ve bu durum bulgu olarak bildirilir.
        hidden_parts = [OPAQUE_REASONS[r] for r in page.get("opaque", []) if r in OPAQUE_REASONS]
        if hidden_parts:
            signals.append(_signal("page_opaque", "Sayfanın bir bölümü incelenemedi",
                                   f"Sayfada Mihenk'in göremediği içerik var: {'; '.join(hidden_parts)}. Tarayıcı bu "
                                   f"içeriği sayfanın parçası olarak gösterir; kimlik avı formu burada gizlenmiş "
                                   f"olabilir. Bağlantıyı açmadan önce doğrulayın.",
                                   "medium", 0.25))
        if (page.get("redirect_delay") or 0) > 10:
            signals.append(_signal("delayed_redirect", "Gecikmeli yönlendirme",
                                   f"Adres yaklaşık {int(page['redirect_delay'])} saniye bekledikten sonra başka bir "
                                   f"sayfaya yönlendiriyor; asıl sayfayı otomatik incelemeden gizlemek için kullanılır.",
                                   "medium", 0.20))
        script_target = page.get("script_redirect")
        if script_target:
            # Yalnizca HTTP ve <meta refresh> yonlendirmeleri izlenir; betikle yapilan yonlendirmenin
            # hedefi incelenmedi, bu durum briefingde belirtilir (Z-09)
            signals.append(_signal("script_redirect", "İzlenemeyen yönlendirme",
                                   f"Sayfa betikle {script_target[:120]} adresine yönlendiriyor; hedef sayfa "
                                   f"incelenmedi. Ara sayfa, asıl içeriği analizden gizlemek için kullanılabilir.",
                                   "medium", 0.25))
            target_host = page.get("script_redirect_host")
            if target_host and not match:
                target_match = detect_brand(target_host, "")
                if target_match:
                    sig = _brand_signal(target_match, None)
                    sig["description"] = f"Betikle yönlendirilen alan adında: {sig['description']}"
                    signals.append(sig)
                    set_target(target_match["brand"])

    if page.get("status") == "download":
        dl = page.get("download") or {}
        what = dl.get("kind") or "Dosya"
        name = f" ({dl['filename']})" if dl.get("filename") else ""
        digest = f" SHA-256: {dl['sha256']}." if dl.get("sha256") else ""
        signals.append(_signal("download", f"Adres doğrudan dosya indiriyor: {what}",
                               f"Bağlantı bir sayfa yerine dosya indiriyor{name}. SMS ve e-posta dolandırıcılıklarında "
                               f"zararlı uygulamalar bu yolla dağıtılır; dosyayı açmayın ve kurmayın.{digest}",
                               "high" if dl.get("risk") == "high" else "medium",
                               0.50 if dl.get("risk") == "high" else 0.30))
    elif page.get("status") in UNINSPECTED_PAGE_STATUSES and not (
            page.get("status") == "port_not_allowed" and parsed.get("port") not in STANDARD_PORTS):
        # (girilen adresin kendisi standart disi porttaysa "Standart disi port" bulgusu ayrica uretilir)
        # Saldirgan sayfayi incelenemez kilabilir; bu durum guvenli sayilmaz (Z-02). Kullanici
        # icerigi sunan adreste (sites.google.com, x.blogspot.com) karar neredeyse tumuyle icerige
        # dayanir; incelenemeyen sayfa orada "Dikkat" duzeyinde bildirilir (D-02).
        if platform_hosted:
            signals.append(_signal("page_uninspected", "Sayfa içeriği incelenemedi (kullanıcı içeriği)",
                                   UNINSPECTED_PAGE_STATUSES[page["status"]] +
                                   " Adres, herkesin içerik yayımlayabildiği bir platformda; bu adreslerde karar "
                                   "sayfa içeriğine dayanır. Kimlik avı içeriği ve form denetlenemedi; bağlantıyı "
                                   "açmadan önce doğrulayın.",
                                   "high", 0.35))
        else:
            signals.append(_signal("page_uninspected", "Sayfa içeriği incelenemedi",
                                   UNINSPECTED_PAGE_STATUSES[page["status"]] +
                                   " Kimlik avı içeriği, form ve veri sızdırma kodu denetlenemedi; "
                                   "sonuç yalnızca adres ve kayıt bilgilerine dayanıyor.",
                                   "medium", 0.15))

    # --- Yonlendirmeden onceki belgeler (D-01) -----------------------------------------
    # Yonlendiren ara sayfanin (meta refresh) formu, kurum kimligi ve veri sizdirma kodu sonucta
    # kalir. Sayfa ilk adreste hassas bilgi isteyip ayni anda baska adrese "yonlendiriyorsa"
    # (orn. bankanin gercek sitesine) bu kendi basina guclu bir aldatma belirtisidir.
    # Sinir yoklamanin urettigi en uzun listeden kisa olamaz: besinci adim / cerceve puanlanmadan kalmamali
    for step in (page.get("steps") or [])[:16]:
        step_host = ascii_host(step.get("final_host") or step.get("host") or host)
        step_trusted = bool(own) and registered_domain(step_host) == registered_domain(host)
        step_restricted = restricted and registered_domain(step_host) == registered_domain(host)
        step_signals = []
        step_content, step_harvest = _content_signals(step, step_host, step_trusted, step_restricted, context,
                                                      set_target, step_signals, prefix="Yönlendirmeden önceki sayfa: ",
                                                      redirecting=True)
        _merge_signals(signals, step_signals)
        content = content or step_content
        harvest = harvest or step_harvest
        sensitive = [f for f in step.get("fields", []) if f != "Telefon"]
        if (sensitive or step_content) and not step_trusted:
            final = page.get("final_host") or (page.get("redirects") or [""])[-1]
            _merge_signals(signals, [_signal(
                "decoy_redirect", "Bilgi isteyen sayfa başka adrese yönlendiriyor",
                f"{step_host} adresindeki sayfa "
                f"{'şu bilgileri istiyor: ' + ', '.join(sensitive) if sensitive else 'başka bir kurumun kimliğini taşıyor'}"
                f" ve aynı anda {str(final)[:120]} adresine yönlendirme etiketi içeriyor. İçerik incelemesini "
                f"başka bir siteye yöneltmek için kullanılan bir yöntemdir.",
                "high", 0.40)])

    # --- Gomulu belgeler (A-01) --------------------------------------------------------
    # Cerceve (iframe/frame/object/embed) ve srcdoc icindeki belge sayfanin parcasidir: formu, kurum
    # kimligi ve veri sizdirma kodu sonuca girer.
    for frame in (page.get("frames") or [])[:16]:
        frame_host = ascii_host(frame.get("final_host") or frame.get("host") or host)
        frame_trusted = bool(own) and registered_domain(frame_host) == registered_domain(host)
        frame_restricted = restricted and registered_domain(frame_host) == registered_domain(host)
        frame_signals = []
        frame_content, frame_harvest = _content_signals(frame, frame_host, frame_trusted, frame_restricted, context,
                                                        set_target, frame_signals, prefix="Çerçevedeki sayfa: ")
        _merge_signals(signals, frame_signals)
        content = content or frame_content
        harvest = harvest or frame_harvest

    # --- Kimligi belirlenemeyen hassas form (E-07, G-07) --------------------------------------
    # Olumlu kanit olmadan "Dusuk risk" yoktur: sayfa (ya da gosterdigi cerceve) parola, kart ya da T.C. kimlik
    # numarasi istiyor ve kimin oldugu belirlenemiyorsa karar en az "Karar verilemedi" olur. Kosul YOKTUR: sayfanin
    # stil ya da gorsel icermesi, adresin kisitli uzantida (k12.tr, bel.tr ...) ya da sahibi bilinen ama
    # guvenilmeyen bir alanda olmasi fark etmez. Kurum adini platformun okuyamayacagi her yazim (ters sira,
    # gorsel, oznitelik, yeni bir ayrac) bu taban karara iner; yalnizca katalogdaki GUVENILEN adres muaftir.
    # Alan TURU taninmasa da kural gecerlidir: alan tanima bir sozcuk listesidir ve etiket gorselle / baska bir
    # sozcukle yazilarak atlatilabilir. Metin girdisini POST ile (ya da baska bir alan adina) gonderen form
    # "veri toplayan form"dur (`collects_input`).
    sensitive_docs = []
    if page.get("status") == "ok":
        sensitive_docs = [d for d in [page] + list((page.get("frames") or [])[:16])
                          if [f for f in d.get("fields", []) if f != "Telefon"] or d.get("collects_input")]
    any_sensitive = bool(sensitive_docs)
    if (any_sensitive and not content and not harvest and not (own and not final_owner_differs)
            and not any(s["key"] in ("content_multi", "content_brand_weak") for s in signals)):
        wanted = sorted({f for d in sensitive_docs for f in d.get("fields", []) if f != "Telefon"}) \
            or ["serbest metin (alan türü tanınmadı)"]
        where = ascii_host(page.get("final_host") or host)
        context["unverified_form"] = True
        signals.append(_signal("unverified_form", "Kimliği doğrulanamayan giriş formu",
                               f"Sayfa ({where}) şu bilgileri istiyor: {', '.join(wanted)}. Sayfanın hangi kuruma ait "
                               f"olduğu belirlenemedi: kurum adı görselle, stil sayfasıyla ya da platformun "
                               f"okuyamadığı bir biçimde verilmiş olabilir. Statik inceleme bu sayfanın zararsız "
                               f"olduğunu söyleyemez; bilgi girmeden önce adresi doğrulayın.",
                               "low", 0.10))

    # --- Yem sayfasinin baglandigi sayfalar (E-12) ------------------------------------------
    # Iki sayfali oltalama kitinde SMS'teki baglanti bildirim sayfasini acar; form, "Kimligimi dogrula"
    # baglantisinin gittigi ikinci sayfadadir. O sayfanin formu ve kurum kimligi sonuca girer.
    for linked in (page.get("linked") or [])[:4]:
        linked_host = ascii_host(linked.get("final_host") or linked.get("host") or host)
        linked_official = official_brand(linked_host)
        linked_trusted = bool(linked_official) and not is_user_content_path(
            linked_host, urlsplit(linked.get("url") or "").path if linked.get("url") else "")
        linked_signals = []
        linked_content, linked_harvest = _content_signals(
            linked, linked_host, linked_trusted, is_restricted(linked_host) and not linked_official, context,
            set_target, linked_signals, prefix="Bağlantının gittiği sayfa: ")
        _merge_signals(signals, linked_signals)
        content = content or linked_content
        harvest = harvest or linked_harvest

    # Kurum adi tasimayan (gorselle verilmis olabilir) yem sayfasi: tuzak ifadesi + bilgi isteyen hedef sayfa
    if (not content and not harvest and page.get("bait_text") and page.get("linked_sensitive")
            and not (own and not final_owner_differs)):
        signals.append(_signal("bait_lure", "Tuzak ifadesiyle bilgi isteyen sayfaya yönlendirme",
                               f"Sayfa ({ascii_host(page.get('final_host') or host)}) hesap kısıtlama / doğrulama türünde bir "
                               f"ifade taşıyor ve bağlantısı bilgi isteyen bir sayfaya gidiyor. Kurum adı metin olarak "
                               f"bulunamadı; görselle verilmiş olabilir.",
                               "medium", 0.40))

    # --- Guven artiranlar ---------------------------------------------------------
    if own and not content and not final_owner_differs:
        mitigations.append(_signal("official", f"{own['name']} resmi alan adı",
                                   f"{host} katalogda {own['name']} kurumunun resmi adresi olarak kayıtlı.",
                                   "low", 0.10))
    elif restricted and not content and not harvest and not any_sensitive and page_fully_inspected(page):
        # Kisitli uzanti, sayfa INCELENEBILDIGINDE ve hassas bilgi ISTEMEDIGINDE bir guven sinyalidir (E-13, G-07):
        # bu uzantilar on binlerce bagimsiz yonetilen siteyi kapsar ve ele gecirilmis okul/belediye siteleri
        # oltalama sayfalarinin en sik barindirildigi yerlerdendir.
        individually = any(host == s or host.endswith("." + s) for s in INDIVIDUALLY_MANAGED_SUFFIXES)
        mitigations.append(_signal("restricted", "Kısıtlı resmi uzantı",
                                   f"{registered_domain(host)} uzantısı yalnızca yetkili kurumlara tahsis edilir"
                                   f"{'; site kurumun kendisi tarafından yönetilir' if individually else ''}.",
                                   "low", 0.50 if individually else 0.20))

    reg = registered_domain(host)
    if host.startswith("xn--") or ".xn--" in host:
        signals.append(_signal("punycode", "Punycode (IDN) alan adı",
                               "Alan adı Punycode kodlu; görsel olarak başka bir alan adını taklit ediyor olabilir.",
                               "high", 0.35))

    port = parsed.get("port")
    if port not in STANDARD_PORTS:
        signals.append(_signal("port", "Standart dışı port",
                               f"Bağlantı {port} portunu kullanıyor; meşru web siteleri 80/443 dışında nadiren yayın yapar. "
                               f"Sayfa içeriği bu nedenle indirilmedi.",
                               "medium", 0.20))

    if parsed.get("stripped_whitespace"):
        signals.append(_signal("url_obfuscation", "Adreste gizlenmiş karakter",
                               "Adres sekme veya satır sonu karakteri içeriyor; tarayıcı bu karakterleri yok sayar. "
                               "Bağlantının analiz araçlarında farklı görünmesi için kullanılır.",
                               "medium", 0.25))

    if "@" in parsed.get("authority", ""):
        signals.append(_signal("userinfo", "URL içinde '@' yönlendirmesi",
                               "Adresin '@' öncesi kısmı tarayıcıda yok sayılır; kullanıcıyı yanıltmak için kullanılır.",
                               "high", 0.45))

    depth = host.count(".") - reg.count(".")
    if depth >= 3:
        signals.append(_signal("deep_sub", "Aşırı alt alan adı derinliği",
                               f"Alan adında {depth} seviye alt alan adı var; gerçek alan adını gizlemek için kullanılır.",
                               "medium", 0.20))

    # Punycode oneki ('xn--') tire sayilmaz (Z-09): sayim gorunen (Unicode) etiket uzerinde yapilir
    hyphens = to_unicode(reg.split(".")[0]).count("-")
    if hyphens >= 2:
        signals.append(_signal("hyphens", "Çok sayıda tire",
                               f"Kayıtlı alan adında {hyphens} tire var; oltalama alan adlarında yaygın bir kalıptır.",
                               "medium", 0.15))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        signals.append(_signal("tld", "Riskli üst seviye alan adı",
                               f"'.{tld}' uzantısı kötüye kullanım oranı yüksek uzantılar arasında.",
                               "medium", 0.25))

    if reg in SHORTENERS:
        signals.append(_signal("shortener", "URL kısaltıcı",
                               "Kısaltılmış bağlantı gerçek hedefi gizliyor; hedef ayrıca analiz edilmeli.",
                               "medium", 0.20))

    # --- Icerik ifadeleri ----------------------------------------------------
    found = []
    for word in BAIT_WORDS:
        if re.search(rf"(?<![a-z]){re.escape(word)}", url_lower) and word not in found:
            found.append(word)
    for word in lure_words(host, path):
        if word not in found and len(word) >= 4:
            found.append(word)
    if found:
        # Her ek kelime azalan getiriyle: 1 kelime 0.20, 2 kelime ~0.34, 3+ ~0.45
        p = 1 - (1 - 0.20) * (1 - 0.18) ** min(len(found) - 1, 2)
        signals.append(_signal("bait", "Kimlik avı ifadeleri",
                               f"Adreste kimlik avıyla ilişkilendirilen ifadeler geçiyor: {', '.join(found[:6])}.",
                               "high" if len(found) >= 2 else "medium", round(p, 3)))

    # --- Baglanti guvenligi --------------------------------------------------
    tls = intel.get("tls")
    if tls == "none":
        signals.append(_signal("no_https", "Şifresiz bağlantı (HTTP)",
                               "Sunucu HTTPS sunmuyor; girilen bilgiler şifresiz iletilir.",
                               "medium", 0.15))
    elif tls == "http_link":
        signals.append(_signal("no_https", "Şifresiz bağlantı (HTTP)",
                               "Bağlantı açıkça http:// ile veriliyor; girilen bilgiler şifresiz iletilir.",
                               "medium", 0.15))
    elif tls == "invalid":
        signals.append(_signal("bad_tls", "Geçersiz TLS sertifikası",
                               "Sunucu HTTPS sunuyor ancak sertifika doğrulanamadı (süresi dolmuş, kendinden imzalı veya alan adıyla uyuşmuyor).",
                               "high", 0.30))

    # --- Kayit yasi ------------------------------------------------------------
    age = None if platform_hosted else intel.get("age_days")
    if age is not None:
        if age < 7:
            signals.append(_signal("age", "Çok yeni alan adı",
                                   f"Alan adı {age} gün önce kaydedilmiş. Oltalama altyapısı genellikle kullanımdan hemen önce kurulur.",
                                   "critical", 0.55))
        elif age < 30:
            signals.append(_signal("age", "Yeni alan adı",
                                   f"Alan adı {age} gün önce kaydedilmiş.",
                                   "high", 0.40))
        elif age < 180:
            signals.append(_signal("age", "Genç alan adı",
                                   f"Alan adı {age} gün önce kaydedilmiş.",
                                   "medium", 0.15))
        elif age >= 3650:
            mitigations.append(_signal("age_old", "Köklü alan adı",
                                       f"Alan adı yaklaşık {age // 365} yıldır kayıtlı.", "low", 0.55))
        elif age >= 1095:
            mitigations.append(_signal("age_old", "Eski alan adı",
                                       f"Alan adı yaklaşık {age // 365} yıldır kayıtlı.", "low", 0.75))

    # --- Itibar ----------------------------------------------------------------
    vt_pos, vt_total = intel.get("vt_positives"), intel.get("vt_total")
    if vt_pos is not None:
        if vt_pos >= 5:
            signals.append(_signal("vt", "VirusTotal tespiti",
                                   f"{vt_total} motordan {vt_pos} tanesi adresi zararlı veya şüpheli olarak işaretledi.",
                                   "critical", 0.95))
        # 1-4 tespit kesin kanit sayilmaz: VirusTotal'da buyuk sitelerin bile birkac motor
        # tarafindan yanlis isaretlenmesi yaygindir (google.com 2/93 gibi). Resmi veya koklu
        # alan adi guven sinyalleri bu durumda skoru dusurebilir.
        elif vt_pos >= 2:
            signals.append(_signal("vt_low", "Az sayıda VirusTotal tespiti",
                                   f"{vt_total} motordan {vt_pos} tanesi adresi zararlı veya şüpheli olarak işaretledi. "
                                   f"Az sayıdaki tespitler büyük sitelerde de görülebilir; diğer bulgularla birlikte değerlendirin.",
                                   "high", 0.45))
        elif vt_pos == 1:
            signals.append(_signal("vt_low", "Tekil VirusTotal tespiti",
                                   f"{vt_total} motordan 1 tanesi adresi işaretledi; tekil tespitler yanlış pozitif olabilir.",
                                   "medium", 0.20))
        elif vt_total and vt_total >= 50:
            mitigations.append(_signal("vt_clean", "VirusTotal temiz",
                                       f"{vt_total} motorun hiçbiri adresi işaretlemedi.", "low", 0.85))

    abuse = intel.get("abuse_score")
    if abuse is not None:
        if abuse >= 75:
            signals.append(_signal("abuse", "Kötü IP itibarı",
                                   f"Barındırma IP adresinin AbuseIPDB güven skoru %{abuse}.", "high", 0.45))
        elif abuse >= 25:
            signals.append(_signal("abuse", "Şüpheli IP itibarı",
                                   f"Barındırma IP adresinin AbuseIPDB güven skoru %{abuse}.", "medium", 0.20))

    if intel.get("resolved") is False and not _is_ip(host):
        signals.append(_signal("nxdomain", "Alan adı çözümlenmiyor",
                               "Alan adı şu anda bir IP adresine çözümlenmiyor; kapatılmış veya henüz yayına alınmamış olabilir.",
                               "low", 0.05))

    return signals, mitigations, context


def _open_redirect_target(host, parsed):
    """Bilinen acik yonlendirme yolundaki hedef adres: {"url", "host"} ya da None (B-06)."""
    reg = registered_domain(host)
    path = parsed.get("path") or ""
    for domains, prefix, params in OPEN_REDIRECTS:
        if reg not in domains or path.rstrip("/") != prefix:
            continue
        query = parse_qs(parsed.get("query") or "")
        for name in params:
            for value in query.get(name, []):
                return _redirect_target(value)
    # google.com/amp/s/<hedef>
    if reg in ("google.com", "google.com.tr") and path.startswith("/amp/"):
        rest = unquote(path[len("/amp/"):])
        rest = ("https://" + rest[2:]) if rest.startswith("s/") else ("http://" + rest)
        return _redirect_target(rest)
    return None


def _redirect_target(value):
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value[:12]:
        value = "http://" + value.lstrip("/")
    try:
        parts = urlsplit(value)
        target = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not target:
        return None
    return {"url": value, "host": ascii_host(target)}


# ---------------------------------------------------------------------------
# Birlestirme ve katki dagitimi
# ---------------------------------------------------------------------------

def _apportion(total, weights):
    """Toplami agirliklara gore tam sayilara boler (en buyuk kalan yontemi)."""
    s = sum(weights)
    if total <= 0 or s <= 0:
        return [0] * len(weights)
    raw = [total * w / s for w in weights]
    out = [math.floor(r) for r in raw]
    remainder = total - sum(out)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - out[i], reverse=True)
    for i in order[:remainder]:
        out[i] += 1
    return out


def score_signals(signals, mitigations):
    lambdas = [-math.log(1 - min(s["p"], 0.99)) for s in signals]
    raw = 100 * (1 - math.exp(-sum(lambdas)))

    keys = {s["key"] for s in signals}
    hard_evidence = bool(keys & HARD_EVIDENCE)

    # Guven artiranlar yalnizca kesin kanit yokken uygulanir
    applied = [] if hard_evidence else mitigations
    factor = 1.0
    for m in applied:
        factor *= m["p"]
    adjusted = raw * factor

    # Kesin kanit icin alt sinirlar
    floor = 0
    vt = next((s for s in signals if s["key"] == "vt"), None)
    if vt and vt["p"] >= 0.95:
        floor = max(floor, 85)
    young = any(s["key"] == "age" and s["p"] >= 0.40 for s in signals)
    impersonation = keys & {"brand", "content_brand", "fake_suffix", "gov_unlisted"}
    if impersonation and young:
        floor = max(floor, 80)
    if "content_brand" in keys and "harvest" in keys:
        floor = max(floor, 85)
    if "brand" in keys and "harvest" in keys:
        floor = max(floor, 85)
    if "exfil" in keys:
        floor = max(floor, 85)
    # "Incelenemedi" bulgulari guven artiran sinyallerle (koklu alan adi, temiz itibar) azaltilmaz (A-13).
    # Istisna: adres katalogdaki bir kurumun resmi adresiyse karar adresin sahipligine dayanir; icerigi
    # betikle gelen resmi site "Dikkat" duzeyine cikmaz. Kisitli uzantilar (k12.tr, bel.tr ...) bu istisnaya
    # girmez (E-13).
    if not any(m["key"] == "official" for m in applied):
        for s in signals:
            if s["key"] in UNINSPECTED_KEYS:
                floor = max(floor, int(round(100 * s["p"])))
    # Benzer harfle resmi adres taklidi: en az Kritik (Y-01)
    if "homograph" in keys:
        floor = max(floor, 80)
        if keys & {"harvest", "content_brand"}:
            floor = max(floor, 90)

    score = max(0, min(int(round(max(adjusted, floor))), 100))

    # Katki: sinyaller lambda payiyla bolusur; guven artiranlar eksi katki olarak gosterilir.
    # Alt sinir uygulandiysa fark kesin kanit sinyallerine dagitilmis olur.
    positive_total = max(int(round(max(raw, floor))), score)
    contributions = _apportion(positive_total, lambdas)
    reduction = positive_total - score
    neg_weights = [-math.log(m["p"]) for m in applied]
    reductions = _apportion(reduction, neg_weights)

    reasons = []
    for s, c in zip(signals, contributions):
        reasons.append({"rule_name": s["rule_name"], "description": s["description"],
                        "severity": s["severity"], "contribution": c})
    for m, r in zip(applied, reductions):
        reasons.append({"rule_name": m["rule_name"], "description": m["description"],
                        "severity": "low", "contribution": -r})

    reasons.sort(key=lambda r: -abs(r["contribution"]))
    return score, level_for(score), reasons
