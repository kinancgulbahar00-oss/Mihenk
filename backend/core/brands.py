"""Turkiye pazari marka ve kurum taklidi tespiti.

Katalog: backend/data/tr_brands.json. Tespit sirasi en guclu kanittan zayifa:

  1. Sahte resmi uzanti      : turkiye-gov-tr.com, edevlet.gov.tr.giris.xyz
  2. Kayitli alan adinda marka: garantibbva-bonus.com, kucoins-signin.com
  3. Yazim benzeri taklit    : garamtibbva.com, akbnak.com, g4ranti...
  4. Alt alan adinda marka   : ziraat.hesap-dogrula.xyz
  5. Yolda marka             : site.com/garanti/giris
  6. Katalog disi kamu taklidi: "belediye", "valilik", "bakanligi" + kamu tuzagi,
                                .gov.tr / .bel.tr disinda

Normalizasyon: IDN (punycode) cozumu, Kiril/Yunan sahte harfler, Turkce karakterler
ve rakam homoglifleri ASCII'ye indirgenir.

ONEMLI (Y-01): Bu sadelestirme yalnizca BENZERLIK tespiti icindir. "Bu adres kuruma ait"
karari (official_brand, is_restricted) her zaman alan adinin kanonik ASCII (Punycode)
bicimi uzerinde, birebir eslesmeyle verilir. Sadelestirilmis bicimi resmi adrese esit
ama ASCII bicimi farkli olan alan adi (işbank.com, аkbank.com) en guclu taklit sinyalidir
(homograph_of).
"""

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from backend.core.hostnames import to_ascii_or_none, to_unicode
from backend.core.suffixes import registrable_domain, shared_suffix

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "tr_brands.json"

# Geriye donuk uyumluluk icin tutulur; kayitli alan adi karari artik Public Suffix List ile
# verilir (backend/core/suffixes.py).
SECOND_LEVEL_SUFFIXES = {
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "k12.tr", "gen.tr", "biz.tr", "web.tr",
    "info.tr", "tv.tr", "av.tr", "dr.tr", "pol.tr", "tsk.tr", "mil.tr", "kep.tr", "name.tr", "tel.tr",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.in", "com.de",
}

# Latin harflere gorsel olarak benzeyen harfler (Unicode "confusables" verisinin alan
# adlarinda kullanilabilen, Latin kucuk harflere benzeyen alt kumesi; Z-09). Aksanli Latin
# harfler (á, ơ...) NFKD ile zaten sadelesir; bu tablo ayrisamayan harfler icindir.
# Tabloda olmayan harfler icin homograph_of() ayrica "yalnizca ASCII disi harflerde fark"
# karsilastirmasi yapar.
CONFUSABLES = str.maketrans({
    # Kiril
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k", "м": "m",
    "т": "t", "н": "h", "в": "b", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "һ": "h", "ӏ": "l", "ү": "y", "ѡ": "w", "ӧ": "o", "ӓ": "a", "ӱ": "y", "ԍ": "g", "ь": "b", "ъ": "b",
    "п": "n", "г": "r", "ɩ": "i", "ԑ": "e", "ҽ": "e", "ѵ": "v", "ʏ": "y",
    # Yunan
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
    "χ": "x", "ϲ": "c", "ϳ": "j", "ω": "w", "η": "n", "γ": "y", "ϐ": "b", "ϱ": "p", "ϰ": "k",
    "ά": "a", "έ": "e", "ί": "i", "ό": "o", "ύ": "u", "ή": "n", "ώ": "w",
    # Ermeni
    "ո": "n", "ս": "u", "օ": "o", "հ": "h", "ց": "g", "զ": "q", "ք": "p", "ա": "w", "լ": "l",
    "ռ": "n", "ւ": "l", "ճ": "a", "ի": "h", "յ": "j", "ɑ": "a",
    # Latin genisletilmis ve kucuk buyuk harfler
    "ƅ": "b", "ɓ": "b", "ƀ": "b", "ƈ": "c", "ɗ": "d", "ɖ": "d", "đ": "d", "ð": "d", "ɛ": "e", "ɇ": "e",
    "ƒ": "f", "ɠ": "g", "ɡ": "g", "ɢ": "g", "ɦ": "h", "ħ": "h", "ʜ": "h", "ɨ": "i", "ɪ": "i", "ʝ": "j",
    "ȷ": "j", "ƙ": "k", "ɭ": "l", "ł": "l", "ŀ": "l", "ƚ": "l", "ɫ": "l", "ɬ": "l", "ʟ": "l", "ⅼ": "l",
    "ɱ": "m", "ᴍ": "m", "ɲ": "n", "ɳ": "n", "ɴ": "n", "ɵ": "o", "ø": "o", "ᴏ": "o", "ƥ": "p", "þ": "p",
    "ᴘ": "p", "ʠ": "q", "ɋ": "q", "ɽ": "r", "ɍ": "r", "ʀ": "r", "ʂ": "s", "ꜱ": "s", "ƭ": "t", "ŧ": "t",
    "ᴛ": "t", "ʋ": "v", "ᴠ": "v", "ⱳ": "w", "ᴡ": "w", "ƴ": "y", "ɏ": "y", "ȥ": "z", "ƶ": "z", "ᴢ": "z",
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴊ": "j", "ᴋ": "k", "ᴜ": "u",
    # Tarayicida korunur, IDNA 2003'te 'ss' olurdu (Y-06): benzerlik icin 'ss' sayilir
    "ß": "ss", "ς": "s",
})
CONFUSABLES_PATH = Path(__file__).resolve().parent.parent / "data" / "confusables.txt"


def _load_unicode_confusables():
    """Unicode Konsorsiyumu'nun UTS #39 `confusables.txt` verisinden Latin harf/rakam karsiliklari (E-09).

    Elle tutulan tablo yalnizca kucuk harfleri kapsiyordu; metin once kucuk harfe cevrildigi icin buyuk hali
    Latin harfe benzeyen harfler kaciyordu ('AKΒANK': Yunan buyuk Beta kucultulunce 'β' olur). Bu tablo
    kucuk harfe cevirmeden ONCE uygulanir ve buyuk harf bicimlerini ayri ayri esler (Β→B, Η→H, Ν→N).

    Yalnizca ASCII disi tek kod noktasindan ASCII harf/rakam dizisine giden eslemeler alinir; hedefteki
    birlesen isaretler atilir. Elle tutulan tablodaki harfler burada yoktur (o tablo onceliklidir). Buyuk
    harfin 'l' karsiligi 'I' sayilir: buyuk I ile kucuk L ayni gorunur, buyuk harfli yazimda kastedilen I'dir."""
    table = {}
    hand = set(CONFUSABLES.keys())
    try:
        lines = CONFUSABLES_PATH.read_text(encoding="utf-8-sig").splitlines()
    except OSError:  # pragma: no cover
        return {}
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if len(fields) < 2:
            continue
        try:
            source = [int(x, 16) for x in fields[0].split()]
            target = "".join(chr(int(x, 16)) for x in fields[1].split())
        except ValueError:
            continue
        if len(source) != 1 or source[0] < 0x80 or source[0] in hand:
            continue
        target = "".join(ch for ch in unicodedata.normalize("NFD", target) if not unicodedata.combining(ch))
        if not target or not target.isascii() or not target.isalnum() or len(target) > 3:
            continue
        ch = chr(source[0])
        if target == "l" and unicodedata.category(ch) == "Lu":
            target = "I"
        table[source[0]] = target
    return table


TURKISH = str.maketrans({"ı": "i", "İ": "i", "ş": "s", "Ş": "s", "ğ": "g", "Ğ": "g",
                         "ü": "u", "Ü": "u", "ö": "o", "Ö": "o", "ç": "c", "Ç": "c", "â": "a", "î": "i", "û": "u"})
UNICODE_CONFUSABLES = _load_unicode_confusables()
DIGIT_GLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"))

# Katalog disindaki kamu kurumlarini yakalamak icin kurum turu kelimeleri
GOV_ENTITY_WORDS = ("belediye", "buyuksehir", "valilik", "valiligi", "kaymakamlik", "bakanlik", "bakanligi",
                    "mudurlugu", "baskanligi", "cumhurbaskanligi", "tccb", "devlet", "resmi", "hukumet", "tbmm",
                    "universitesi", "universite")
FAKE_SUFFIX_RE = re.compile(r"(?:^|[.-])(gov|edu|bel|pol|tsk|k12)[.-]?tr(?:[.-]|$)")


# ---------------------------------------------------------------------------
# Katalog
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def catalog():
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    brands = []
    for b in data["brands"]:
        brands.append({
            **b,
            "aliases": [normalize_text(a).replace(" ", "") for a in b.get("aliases", [])],
            "weak_aliases": [normalize_text(a).replace(" ", "") for a in b.get("weak_aliases", [])],
            "terms": [normalize_text(t) for t in b.get("terms", []) if t],
            # Resmi adresler kanonik ASCII bicimde tutulur; sahiplik karari bu bicimle verilir
            "domains": [to_ascii_or_none(d) or d.lower() for d in b.get("domains", [])],
            # Kuruma ait ama icerigi kullanicilarin yayimladigi alanlar: sahiplik bilinir,
            # guven verilmez (Z-01)
            "user_content_domains": [to_ascii_or_none(d) or d.lower() for d in b.get("user_content_domains", [])],
            # Kullanici icerigi barindiran buyuk platformlar (B-06): 'resmi alan adi' guveni YALNIZCA
            # bu adlara verilir; alan adinin geri kalani "sahibi bilinir, guven verilmez" sinifindadir.
            # Anahtar yoksa (None) tum resmi alan adlari guvenilir; bos liste hicbir adin guvenilmedigi
            # anlamina gelir. '*.ornek.com' alt alan adlarini kapsar.
            "trusted_hosts": (None if b.get("trusted_hosts") is None else
                              [_ascii_pattern(t) for t in b.get("trusted_hosts", [])]),
            # Guvenilen adin ALTINDAKI kullanici icerigi yollari (A-06): 'www.google.com/maps/d/',
            # 'www.paypal.com/paypalme/'. Bu yollarda resmi alan adi guveni verilmez.
            "user_content_paths": [p.strip().lower() for p in b.get("user_content_paths", []) if p.strip()],
            "lures": set(data["sectors"][b["sector"]]["lures"]),
        })
    return {
        "brands": brands,
        "sectors": data["sectors"],
        "restricted": tuple(data["restricted_suffixes"]),
        "all_lures": {w for s in data["sectors"].values() for w in s["lures"]},
    }


def _ascii_pattern(value):
    value = (value or "").strip().lower()
    if value.startswith("*."):
        return "*." + (to_ascii_or_none(value[2:]) or value[2:])
    return to_ascii_or_none(value) or value


def _trusted_host(host, brand):
    """Resmi alan adi guveni bu adres icin gecerli mi? (B-06)"""
    trusted = brand.get("trusted_hosts")
    if trusted is None:
        return True
    for t in trusted:
        if t.startswith("*."):
            if host == t[2:] or host.endswith(t[1:]):
                return True
        elif host == t:
            return True
    return False


def is_user_content_path(host, path):
    """Adres, guvenilen bir adin altindaki bilinen kullanici icerigi yolunda mi? (A-06)"""
    host = ascii_host(host)
    target = host + "/" + (path or "/").lstrip("/").lower()
    for brand in catalog()["brands"]:
        for prefix in brand["user_content_paths"]:
            if target.startswith(prefix):
                return True
    return False


def sector_label(sector):
    return catalog()["sectors"].get(sector, {}).get("label", sector)


def catalog_summary():
    cat = catalog()
    return [
        {"id": b["id"], "name": b["name"], "sector": b["sector"], "sector_label": sector_label(b["sector"]),
         "domains": b["domains"]}
        for b in cat["brands"]
    ]


# ---------------------------------------------------------------------------
# Normalizasyon
# ---------------------------------------------------------------------------

def decode_idn(host):
    """Benzerlik tespiti icin Punycode etiketlerini Unicode'a cevirir (UTS-46; 'ß' korunur)."""
    return to_unicode(host)


def ascii_host(host):
    """Sahiplik ve uzanti kararlari icin kanonik ASCII bicim. Cevrilemeyen girdi icin
    kucuk harfli ham deger doner; boyle bir deger hicbir resmi adresle birebir eslesemez."""
    host = (host or "").strip().rstrip(".")
    return to_ascii_or_none(host) or host.lower()


def skeleton(host):
    """Gorsel benzerlik iskeleti: Unicode'a cevir, Turkce/aksanli/Kiril/Yunan harfleri sadelestir."""
    return normalize_text(decode_idn((host or "").lower()))


# Gorunmez bicim karakterleri (Unicode "Cf": U+200B-U+200F, U+2060, U+FEFF, U+00AD...). Ekranda
# hicbir sey gostermezler; kurum adini bolerek terim aramasini atlatmak icin kullanilirlar (B-01).
_FORMAT_CHARS_RE = re.compile(r"[­͏؜ᅟᅠ឴឵᠋-᠏​-‏"
                              r"‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]")


# Kontrol karakterleri (C0, DEL, C1): metinde yer kaplamaz ya da kucuk bir kutu olarak cizilir; kurum adini
# bolmek icin kullanilir (G-05). Bosluk karakterleri (sekme, satir sonu) korunur.
_CONTROL_CHARS_RE = re.compile("[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]")


def strip_invisible(text):
    """Gorunmez bicim karakterlerini ve kontrol karakterlerini atar."""
    text = _CONTROL_CHARS_RE.sub("", text or "")
    text = _FORMAT_CHARS_RE.sub("", text)
    if text.isascii():
        return text
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def normalize_text(text):
    """Kucuk harf, Turkce ve gorsel taklit harfleri ASCII'ye, aksanlari sil. Gorunmez bicim
    karakterleri eslestirmeden ONCE atilir (B-01): 'Gar​anti' 'garanti' olarak eslesir."""
    text = strip_invisible(text)
    if not text.isascii():
        # Buyuk harf benzer karakterler kucuk harfe cevrilmeden ONCE eslenir (E-09)
        text = text.translate(UNICODE_CONFUSABLES)
    text = text.replace("İ", "i").replace("I", "ı").lower()
    text = text.translate(TURKISH).translate(CONFUSABLES)
    text = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in text if not unicodedata.combining(ch))


def deglyph(text):
    out = text
    for fake, real in DIGIT_GLYPHS:
        out = out.replace(fake, real)
    return out


def registered_domain(host):
    """Kayitli alan adi (Public Suffix List). Paylasimli barindirma soneki altindaki ad
    (garantibbva-giris.blogspot.com) kendi basina kayitli alan adi sayilir (Z-01)."""
    return registrable_domain(host)


def _under(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def _suffix_of(reg):
    return reg.split(".", 1)[1] if "." in reg else ""


def is_restricted(host, restricted=None):
    """Kisitli resmi uzanti (gov.tr, edu.tr...). Karar ASCII bicimde birebir verilir."""
    restricted = restricted or catalog()["restricted"]
    host = ascii_host(host)
    return any(host == s or host.endswith("." + s) for s in restricted)


def is_official(host, brand):
    host = ascii_host(host)
    if _user_content(host):
        return False
    if _under(host, brand["domains"]):
        return _trusted_host(host, brand)
    return bool(brand.get("gov")) and is_restricted(host)


def damerau(a, b, limit=2):
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


# ---------------------------------------------------------------------------
# URL ayristirma
# ---------------------------------------------------------------------------

def url_parts(host, path=""):
    """Tespit icin normallestirilmis parcalar."""
    uhost = skeleton(host)
    reg = registered_domain(uhost)
    label = reg.split(".")[0]
    sub = uhost[: -len(reg)].rstrip(".") if uhost.endswith(reg) and uhost != reg else ""
    npath = normalize_text(path or "")
    return {
        "host": uhost,
        "reg": reg,
        "label": label,
        "plain": label.replace("-", ""),
        "label_tokens": [t for t in re.split(r"[-_]", label) if t],
        "sub_tokens": [t for t in re.split(r"[-_.]", sub) if t],
        "path_tokens": [t for t in re.split(r"[^a-z0-9]+", npath) if t],
        "words": set(re.split(r"[^a-z0-9]+", uhost + " " + npath)) - {""},
        "blob": re.sub(r"[^a-z0-9]", "", uhost + npath),
    }


def _has_lure(parts, lures):
    if parts["words"] & lures:
        return True
    # Turkce eklemeli yapi: "subesi", "faturaniz", "cezasi" kok uzerinden eslesir
    if any(w.startswith(l) for w in parts["words"] for l in lures if len(l) >= 4):
        return True
    return any(lure in parts["blob"] for lure in lures if len(lure) >= 5)


def _short_hit(alias, token, lures):
    """Kisa ifadeler (<=4) yalnizca tam parca ya da 'ptt' + 'kargo' gibi tuzak kelimeyle birlesik."""
    if token == alias:
        return True
    if token.startswith(alias) and (token[len(alias):] in lures or token[len(alias):].isdigit()):
        return True
    if token.endswith(alias) and token[: -len(alias)] in lures:
        return True
    return False


def _long_hit(alias, token):
    return token.startswith(alias) or (len(alias) >= 6 and alias in token)


# ---------------------------------------------------------------------------
# Tespit
# ---------------------------------------------------------------------------

def _match(brand, kind, token, detail):
    return {"brand": brand, "kind": kind, "token": token, "detail": detail}


def _owner(host, domains_of):
    """Adresi kapsayan kurum. Birden fazla kurum eslesirse once EN OZEL (en uzun) kayit,
    esitlikte kaydi birincil (listede once) tasiyan kurum secilir (D-06): 'sites.google.com'
    Google'in kullanici icerigi kaydidir; 'google.com'u ikincil olarak listeleyen bir kardes
    marka sahip sayilmaz."""
    owners = []
    for order, brand in enumerate(catalog()["brands"]):
        best = None
        for rank, d in enumerate(domains_of(brand)):
            if host == d or host.endswith("." + d):
                if best is None or len(d) > len(best[2]):
                    best = (rank, brand, d)
        if best:
            owners.append((-len(best[2]), best[0], order, best[1], best[2]))
    if not owners:
        return None
    _, rank, _, brand, d = min(owners, key=lambda o: o[:3])
    return (rank, brand, d)


def _longest_match(host, domains):
    """host'u kapsayan en uzun (en ozel) alan adinin uzunlugu; yoksa 0."""
    return max((len(d) for d in domains if host == d or host.endswith("." + d)), default=0)


@lru_cache(maxsize=8192)
def _user_content(host):
    """Alan adi kullanici icerigi sunuyor mu? Paylasimli sonek altindaki ad her zaman; bir
    kurumun user_content_domains listesindeki ad ise resmi listede daha ozel bir kayit yoksa
    (windows.net kullanici icerigi, login.windows.net resmi)."""
    if shared_suffix(host):
        return True
    ugc = max((_longest_match(host, b["user_content_domains"]) for b in catalog()["brands"]), default=0)
    if not ugc:
        return False
    official = max((_longest_match(host, b["domains"]) for b in catalog()["brands"]), default=0)
    return ugc >= official


@lru_cache(maxsize=8192)
def official_brand(host):
    """Alan adi katalogdaki bir kurumun resmi adresiyse o kurumu dondurur.
    Karar YALNIZCA kanonik ASCII (Punycode) bicimde birebir eslesmeyle verilir; Turkce harf,
    aksan veya Kiril/Yunan harf eklenmis bir alan adi hicbir zaman resmi sayilmaz (Y-01).
    Herkesin icerik yayimlayabildigi adresler (blogspot.com alt alan adlari, S3 kovalari,
    docs.google.com, kisa baglantilar) hicbir zaman resmi sayilmaz (Z-01).
    Birden fazla kurum ayni adresi listeliyorsa adresi birincil olarak tasiyan secilir.
    Kullanici icerigi barindiran buyuk platformlarda (Google, Microsoft, Meta...) guven yalnizca
    katalogda acikca listelenen adlara verilir (trusted_hosts; B-06): lookerstudio.google.com,
    www.facebook.com/notes/..., paypal.me/... resmi sayilmaz, sahipleri yine bilinir (owner_brand)."""
    host = ascii_host(host)
    if _user_content(host):
        return None
    owner = _owner(host, lambda b: b["domains"])
    if not owner or not _trusted_host(host, owner[1]):
        return None
    return owner[1]


def user_content_boundary(host):
    """Kullanici icerigi sunan adreste icerigi yayimlayan kisinin siniri; degilse None.
    'sirket.blogspot.com' -> 'sirket.blogspot.com', 'sites.google.com' -> 'sites.google.com'.
    Bu sinirin ustundeki bir izin kurali (google.com) sinirin icindeki icerige guven veremez."""
    host = ascii_host(host)
    if not host or not _user_content(host):
        return None
    if shared_suffix(host):
        return registered_domain(host)
    matches = [d for b in catalog()["brands"] for d in b["user_content_domains"]
               if host == d or host.endswith("." + d)]
    return max(matches, key=len) if matches else None


def user_content_domains():
    """Katalogdaki tum kullanici icerigi alanlari (liste kurali dogrulamasi icin)."""
    return {d for b in catalog()["brands"] for d in b["user_content_domains"]}


@lru_cache(maxsize=8192)
def owner_brand(host):
    """Alan adinin SAHIBI olan kurum (resmi adres ya da kurumun kullanici icerigi alani).
    Sahibin adi alan adinda veya sayfada gecmesi taklit sayilmaz; ancak sahiplik guven
    anlamina gelmez (bkz. official_brand). Paylasimli sonek altindaki adin sahibi bilinmez."""
    host = ascii_host(host)
    if shared_suffix(host):
        return None
    # Resmi adresler once: kaydi birincil olarak tasiyan kurum sahiptir (D-06). Daha ozel kullanici
    # icerigi kaydi (sites.google.com) en uzun eslesme kuraliyla yine one gecer.
    owner = _owner(host, lambda b: b["domains"] + b["user_content_domains"])
    return owner[1] if owner else None


def _non_ascii_lookalike(host_skel, official_skel):
    """Ayni uzunlukta ve yalnizca ASCII disi harflerin bulundugu 1-2 konumda farkli mi?
    Tabloda olmayan benzer harfler (Z-09) icin genel yedek denetim."""
    n = official_skel.count(".") + 1
    tail = ".".join(host_skel.split(".")[-n:])
    if len(tail) != len(official_skel) or tail == official_skel:
        return False
    if tail != host_skel and not host_skel.endswith("." + tail):
        return False
    diffs = [(a, b) for a, b in zip(tail, official_skel) if a != b]
    return 1 <= len(diffs) <= 2 and all(not a.isascii() and b.isascii() for a, b in diffs)


def homograph_of(host):
    """Gorunusu resmi bir adresle (ya da kisitli resmi uzantiyla) ayni, kendisi farkli alan adi.

    işbank.com, akbánk.com, Kiril 'а' ile аkbank.com, sunexpreß.com, e-devlet.gоv.tr,
    Ermeni 'ո' ile iոg.com.tr...
    Doner: {"brand": kurum veya None, "official": taklit edilen resmi adres/uzanti} ya da None."""
    a_host = ascii_host(host)
    if official_brand(a_host) or is_restricted(a_host):
        return None
    skel = skeleton(a_host)
    if skel == a_host:
        # Saf ASCII alan adi: gorsel taklit degil (yazim benzeri taklit detect_brand ile aranir)
        return None
    owner = _owner(skel, lambda b: [skeleton(d) for d in b["domains"]])
    if owner:
        _, brand, domain = owner
        return {"brand": brand, "official": domain}
    for suffix in catalog()["restricted"]:
        if skel == suffix or skel.endswith("." + suffix):
            return {"brand": None, "official": suffix}
    # Tabloda olmayan benzer harf: yalnizca ASCII disi konumlarda farkli, gerisi ayni
    host_skel = normalize_text(to_unicode(a_host))
    for brand, domain, domain_skel in _official_skeletons():
        if _non_ascii_lookalike(host_skel, domain_skel):
            return {"brand": brand, "official": domain}
    return None


@lru_cache(maxsize=1)
def _official_skeletons():
    return [(b, d, skeleton(d)) for b in catalog()["brands"] for d in b["domains"]]


def _windows(parts):
    """Yazim benzeri arama icin pencereler: bir kez hesaplanir, boyuta gore gruplanir."""
    plain = parts["plain"]
    by_size = {}
    for size in range(5, min(len(plain), 22) + 1):
        for i in range(0, len(plain) - size + 1):
            w = plain[i:i + size]
            by_size.setdefault(size, set()).add((w, deglyph(w)))
    for tok in parts["label_tokens"]:
        by_size.setdefault(len(tok), set()).add((tok, deglyph(tok)))
    return by_size


@lru_cache(maxsize=2048)
def detect_brand(host, path=""):
    """En guclu marka taklidi eslesmesini dondurur; yoksa None."""
    cat = catalog()
    parts = url_parts(host, path)
    # Kisitli uzanti ve resmi adres karari sadelestirilmis bicimle DEGIL, ASCII bicimle verilir
    if is_restricted(host, cat["restricted"]):
        return None

    # Katalogdaki herhangi bir kurumun resmi alan adi taklit sayilmaz
    # (trendyolexpress.com gibi kardes markalar birbirinin adini tasir). Kurumun kullanici
    # icerigi alani da (steamcommunity.com, discord.gg) kurumun kendisine aittir; ancak
    # paylasimli sonek altindaki ad (garantibbva-giris.blogspot.com) burada elenmez (Z-01).
    if owner_brand(host):
        return None

    candidates = []
    windows = _windows(parts)

    for brand in cat["brands"]:
        lures = brand["lures"]
        lure_ctx = _has_lure(parts, lures)
        strong = brand["aliases"]
        weak = brand["weak_aliases"] if lure_ctx else []

        # 2) Kayitli alan adinda
        for alias in strong + weak:
            short = len(alias) <= 4
            tokens = parts["label_tokens"] + ([parts["plain"]] if not short else [])
            for tok in tokens:
                if (short and _short_hit(alias, tok, cat["all_lures"])) or (not short and _long_hit(alias, tok)):
                    candidates.append((0, _match(brand, "label", alias, tok)))
                    break

        # 3) Yazim benzeri (yalnizca uzun ifadeler). Markanin herhangi bir ifadesi alan adinda
        #    zaten aynen geciyorsa bu bilincli kullanimdir, yazim hatasi aranmaz (garantikasko).
        if not any(a in parts["plain"] for a in strong + brand["weak_aliases"] if len(a) >= 5):
            found = None
            for alias in strong:
                if len(alias) < 6:
                    continue
                limit = 2 if len(alias) >= 10 else 1
                for size in range(len(alias) - limit, len(alias) + limit + 1):
                    for w, w2 in windows.get(size, ()):
                        # Ucuz on filtre: taklitler cogunlukla ilk ya da son harfi korur
                        if w2[0] != alias[0] and w2[-1] != alias[-1]:
                            continue
                        if w2 == alias and w != alias:
                            found = _match(brand, "glyph", alias, w)
                            break
                        if w2 != alias and damerau(w2, alias, limit) <= limit:
                            found = _match(brand, "typo", alias, w)
                            break
                    if found:
                        break
                if found:
                    candidates.append((1, found))
                    break

        # 4) Alt alan adinda / 5) yolda
        for alias in strong + weak:
            if any(tok == alias or (len(alias) >= 5 and tok.startswith(alias)) for tok in parts["sub_tokens"]):
                candidates.append((2, _match(brand, "subdomain", alias, alias)))
                break
        for alias in strong:
            if len(alias) >= 4 and any(tok == alias for tok in parts["path_tokens"]):
                candidates.append((3, _match(brand, "path", alias, alias)))
                break

    if candidates:
        candidates.sort(key=lambda c: (c[0], -len(c[1]["token"])))
        return candidates[0][1]
    return None


def detect_fake_suffix(host):
    """'gov-tr', 'govtr', 'gov.tr' ifadesi gercek uzanti disinda kullanilmis mi?"""
    parts = url_parts(host)
    if is_restricted(host):
        return None
    body = parts["host"][: -len(parts["reg"])] + parts["label"] if parts["host"].endswith(parts["reg"]) else parts["host"]
    m = FAKE_SUFFIX_RE.search(body)
    return f"{m.group(1)}.tr" if m else None


def detect_unlisted_gov(host, path=""):
    """Katalogda olmayan kamu kurumlari: belediye, valilik, bakanlik... + kamu tuzagi."""
    parts = url_parts(host, path)
    if is_restricted(host):
        return None
    gov_lures = set(catalog()["sectors"]["government"]["lures"]) | set(catalog()["sectors"]["municipal"]["lures"])
    entity = next((w for w in GOV_ENTITY_WORDS if w in parts["blob"]), None)
    if entity and _has_lure(parts, gov_lures):
        return entity
    return None


def lure_words(host, path=""):
    """URL'de gecen sektor tuzak kelimeleri (tum sektorler)."""
    parts = url_parts(host, path)
    return sorted(parts["words"] & catalog()["all_lures"])


def _terms_in(text, brand, min_len=1):
    return [t for t in brand["terms"]
            if len(t) >= min_len and re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", text)]


def _term_count(text, term):
    return len(re.findall(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text))


def _lookalike_terms(text, brand):
    """Tabloda olmayan benzer harfler icin genel yedek denetim (E-09; alan adlarindaki `_non_ascii_lookalike`
    ile ayni ilke): kurum terimi, metinde yalnizca ASCII disi harflerin bulundugu 1-2 konumda farkli."""
    hits = []
    n = len(text)
    for term in brand["terms"]:
        size = len(term)
        if size < 6 or size > n:
            continue
        for i in range(n - size + 1):
            window = text[i:i + size]
            if window.isascii():
                continue
            diffs = 0
            for a, b in zip(window, term):
                if a != b:
                    if a.isascii() or not a.isalpha():
                        diffs = 9
                        break
                    diffs += 1
            if 1 <= diffs <= 2:
                before = text[i - 1] if i else " "
                after = text[i + size] if i + size < n else " "
                if not (before.isascii() and before.isalnum()) and not (after.isascii() and after.isalnum()):
                    hits.append(term)
                    break
    return hits


def _page_path(page):
    from urllib.parse import urlsplit

    try:
        return urlsplit(page.get("url") or page.get("final_url") or "").path or "/"
    except ValueError:
        return "/"


# Govde kaniti icin "kisa sayfa" siniri (yem / giris sayfasi); uzun metinli sayfalar haber, karsilastirma ya da
# magaza sayfasidir
BODY_EVIDENCE_MAX_TEXT = 1500


_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
# ASCII icindeki benzer harfler (G-05): buyuk I / kucuk L / 1 / | ve O / 0 ekranda ayni gorunur. Alan adi tarafinda
# DIGIT_GLYPHS ile uygulanan eslemenin icerik karsiligi; metin VE terim ayni bicime indirgenir.
_ASCII_FOLD = str.maketrans({"1": "i", "l": "i", "|": "i", "0": "o"})


def _loose(text):
    """Harf ve rakam disindaki her sey tek bosluga iner (G-05): 'garanti-bbva', 'garanti.bbva', 'garanti/bbva'
    ayni terimle eslesir. Sadelestirilmis (normalize_text) metne uygulanir."""
    return _NON_ALNUM_RE.sub(" ", text).strip()


def _short_aliases(brand):
    """Kisa adli kurumlarin (ING, PTT, THY ...) kisaltmasi (G-10). Katalog terimleri bu adlari tasimaz, cunku govde
    metninde siradan sozcuklerle karisir ('yok', 'sok'). Yalnizca BUYUK HARFLE yazilmis sozcuk olarak aranir."""
    first = brand["name"].split()[0]
    out = {t for t in brand["terms"] if 3 <= len(t) < 6 and " " not in t}
    if 3 <= len(first) <= 5 and first.isupper():
        out.add(normalize_text(first))
    if 3 <= len(brand["id"]) <= 4:
        out.add(brand["id"])
    return out


# Kisaltmanin yaninda durdugunda onu kurum adi yapan sozcukler ('ING Bank', 'PTT Kargo Takip'). Baska bir sozcukle
# birlikte gecen kisaltma ('UPS Sistemleri Bayi Girisi', 'BIM Yonetim Paneli', 'SGK Evrak Takip') kurum kaniti degildir.
_ACRONYM_CONTEXT = frozenset({
    "bank", "bankasi", "bankacilik", "internet", "sube", "subesi", "mobil", "online", "giris", "girisi", "kargo", "takip",
    "gonderi", "turkiye", "tr", "market", "havayollari", "hava", "yollari", "devlet", "kapisi", "hesap", "hesabim",
    "musteri", "bireysel", "kurumsal", "odeme", "kart", "kredi", "sigorta", "emeklilik", "dijital", "cuzdan", "com",
    "www", "resmi", "sitesi", "hos", "geldiniz", "ve", "ile", "e", "a", "s"})


def _upper_tokens(text, chunks=None):
    """Logo / baslik ogelerinde kurum adi olarak duran kisaltmalar (sadelestirilmis). Kisaltma, bulundugu ogede
    tek basina ya da yalnizca kurum baglami sozcukleriyle ('Bank', 'Kargo Takip') birlikte olmalidir; tamami buyuk
    harfle yazilmis uzun metin ('SIFRENIZ YOK MU') kanit sayilmaz."""
    found = set()
    for chunk in (chunks if chunks else [text or ""]):
        chunk = strip_invisible(chunk or "")
        tokens = re.findall(r"[^\W_]+", chunk)
        if not tokens or (not any(ch.islower() for ch in chunk) and len(tokens) > 2):
            continue
        acronyms = {normalize_text(tok) for tok in tokens if tok.isupper() and 3 <= len(tok) <= 5}
        others = {normalize_text(tok) for tok in tokens} - acronyms
        if acronyms and others <= _ACRONYM_CONTEXT:
            found |= acronyms
    return found


# Birlesince kurum adi veren, ancak ayri yazildiginda siradan Turkce sozcuk olan parcalar: 'en para kazandiran',
# 'yemek sepeti hazirlama'. Butun parcalari bu kumede olan birlesim kurum adi sayilmaz.
_COMMON_WORDS = frozenset({"en", "para", "yemek", "sepeti", "sepet", "hepsi", "burada", "bir", "bu", "de", "da", "ve",
                           "ile", "is", "ev", "el", "al", "sat", "git", "gel", "pazar", "ama", "cicek", "kitap",
                           "yurt", "ici", "dis", "kargo", "hizli", "kolay", "cep", "net", "tek", "cok", "yeni", "eski"})


def _fold(text):
    return text.translate(_ASCII_FOLD).replace("rn", "m").replace("vv", "w")


def _folded_terms_in(folded_text, brand, min_len=6):
    """ASCII benzer harfler eslendikten sonra gecen terimler (asil terim olarak doner)."""
    return [t for t in brand["terms"] if len(t) >= min_len
            and re.search(rf"(?<![a-z0-9]){re.escape(_fold(t))}(?![a-z0-9])", folded_text)]


def detect_brand_in_content(page):
    """Sayfa icerigindeki, adresin SAHIBINDEN FARKLI kurum kimligi (Z-01).

    - Kimlik alanlari (baslik, site adi, h1) guclu kanittir.
    - Birlesim ilkesi (E-07, G-04..G-06): kurum adi asagidaki gorunumlerin TAMAMINDA aranir ve herhangi birinde
      bulunmasi kanittir: gorunur metin; "gizli" sayilan metin, CSS ile yazilan metin ve gorunen oznitelik
      degerleri (girdi degeri, yer tutucu, dugme, aria-label, alt); ayraclari bosluga indirilmis metin
      ('Garanti-BBVA'); ASCII benzer harfleri eslenmis metin ('GARANTl'); ters cevrilmis metin (<bdo dir=rtl>,
      unicode-bidi, float ile tersten yazim); harf harf ogelere dagitilmis ad. Yalnizca dolayli bir gorunumde
      bulunan ad `obfuscated` isaretini tasir ("Kurum adi gizlenerek yazilmis").
    - Govde metni ve logolar, sayfa hassas bilgi istiyorsa ya da kisa ve etkilesimli bir sayfaysa (form, metin
      girdisi, dugme) sayilir (E-10); taninan hassas alan yalnizca agirligi artirir.
    - Hassas form varken "sayfada tek kurum gecmeli" kosulu yoktur (E-08): birden fazla kurum geciyorsa baskin
      olan (en sik gecen) hedef sayilir. Esitlikte adin GECTIGI YER belirleyicidir (G-10): logo / baslik benzeri
      ogede gecen kurum hedeftir. O da ayirt etmiyorsa sonuc `ambiguous` isaretiyle doner ve dusuk agirlikli bir
      bulgu olur (karsilastirma ve odeme sayfalari kurumlari birer kez sayar).
    - Adi alti karakterden kisa kurumlar (ING, PTT, THY ...) govdede yalnizca logo / baslik benzeri bir ogede ve
      hassas form varken aday olur (G-10).
    - Icerik HER ZAMAN incelenir; hicbir guven sinyali (resmi adres, kisitli uzanti) bu
      denetimi kapatmaz. Adresin sahibi olan kurum (owner_brand) aday degildir.
    - Guvenilen adreslerde (kurumun resmi adresi, .gov.tr/.k12.tr gibi kisitli uzantilar)
      siteler ortaklarini ve diger kurumlari anar. Bu adreslerde yalnizca kimlik alanlari kanit sayilir.
    - "Sayfa kendini adresin sahibi olarak tanitiyor" muafiyeti yalnizca icerigi sahibinin denetledigi
      adreslerde (official_brand) gecerlidir (E-11)."""
    if not page:
        return None
    cat = catalog()
    host = page.get("final_host") or ""
    owner = owner_brand(host) if host else None
    official = bool(host) and bool(official_brand(host)) and not is_user_content_path(host, _page_path(page))
    trusted = bool(host) and bool(official or is_restricted(host))

    def views(*texts):
        out = []
        for text in texts:
            if text:
                norm = normalize_text(text)
                for view in (norm, _loose(norm)):
                    if view and view not in out:
                        out.append(view)
        return out or [""]

    identity_views = views(" ".join(page.get("identity", [])), " ".join(page.get("identity_all") or []))
    logos = normalize_text(" ".join(page.get("logos", [])))
    body_views = views(page.get("text", ""), page.get("text_all") or "")
    prominent = _loose(normalize_text(page.get("prominent_text") or ""))
    acronyms = _upper_tokens(page.get("prominent_text"), page.get("prominent_chunks"))
    has_form = bool(page.get("password_input") or page.get("card_input") or page.get("tckn_input"))
    short = len(page.get("text", "")) <= BODY_EVIDENCE_MAX_TEXT
    short_interactive = bool(page.get("interactive")) and short
    # Yem sayfasi: form ya da dugme tasimaz; kisa metin, tuzak ifadesi ("hesabiniz kisitlandi") ve birkac hedefe
    # giden baglanti tasir. Kurum adi baslik yerine govdede / logo etiketinde yazilabilir.
    # `probe_for_links`: yoklama, baglantilari izleyip izlemeyecegine karar verirken sorar (tuzak ifadesi aranmaz);
    # skorlamada ayni sayfa ancak tuzak ifadesi tasiyorsa ya da baglantinin gittigi sayfa bilgi istiyorsa sayilir.
    lure = short and bool(page.get("prominent_external_link")) and bool(
        page.get("bait_text") or page.get("linked_sensitive") or page.get("probe_for_links"))
    restricted_host = bool(host) and not official and is_restricted(host)

    if owner and official and any(_terms_in(view, owner) for view in identity_views):
        # Sayfa kendini adresin sahibi olarak tanitiyor; anilan diger kurumlar ortaktir
        return None

    # Dolayli gorunumler: yalnizca bunlarda bulunan ad "gizlenerek yazilmis" sayilir
    compact_views = [view.replace(" ", "") for view in identity_views]
    non_ascii_identity = [view for view in identity_views if not view.isascii()]
    loose_identity = [_loose(view) for view in identity_views]
    folded_identity = [_fold(view) for view in loose_identity]
    reversed_identity = [view[::-1] for view in loose_identity]
    joined_identity = set()
    for view in loose_identity:
        tokens = view.split()
        for i in range(len(tokens) - 1):
            for parts in (tokens[i:i + 2], tokens[i:i + 3]):
                if len(parts) >= 2 and not all(part in _COMMON_WORDS for part in parts):
                    joined_identity.add("".join(parts))
    body_loose = _loose(body_views[-1])
    folded_body = _fold(body_loose)
    reversed_body = body_loose[::-1]

    strong = []
    indirect = []
    in_logos = []
    in_body = []
    for brand in cat["brands"]:
        if owner and brand["id"] == owner["id"]:
            continue
        hits = [t for view in identity_views for t in _terms_in(view, brand)]
        if hits:
            strong.append((brand, max(hits, key=len)))
            continue
        # Bosluklar silindiginde ortaya cikan kurum adi (A-03, G-06): 'G a r a n t i  B B V A', harf harf ogeler
        hidden = [t for t in brand["terms"] if " " in t and len(t.replace(" ", "")) >= 9
                  and any(t.replace(" ", "") in view for view in compact_views)]
        # Tek sozcuklu adin araya bosluk konarak bolunmesi ('Ak bank'): yan yana iki-uc sozcugun birlesimi.
        # Butun parcalari siradan sozcuk olan birlesimler ('en para', 'yemek sepeti') aday degildir.
        hidden += [t for t in brand["terms"] if " " not in t and len(t) >= 6 and t in joined_identity]
        hidden += [t for view in non_ascii_identity for t in _lookalike_terms(view, brand)]
        hidden += [t for view in folded_identity for t in _folded_terms_in(view, brand)]
        hidden += [t for view in reversed_identity for t in _terms_in(view, brand, 6)]
        if hidden:
            indirect.append((brand, max(hidden, key=len)))
            continue
        # Resmi adreste yalnizca kimlik alanlari kanittir. Kisitli uzantilarda (k12.tr, bel.tr ...) siteler ortak
        # kurumlari anar; ancak hassas bilgi isteyen sayfada govde / logo kimligi orada da kanittir: ele gecirilmis
        # okul ve belediye siteleri oltalama sayfalarinin sik barindirildigi yerlerdir.
        if official or (restricted_host and not has_form):
            continue
        if has_form:
            hits = _terms_in(logos, brand, 4)
            if hits:
                in_logos.append((brand, max(hits, key=len)))
        if has_form or short_interactive or lure:
            best = None
            obfuscated = False
            weak = False
            for view in body_views:
                for term in _terms_in(view, brand, 6):
                    count = _term_count(view, term)
                    if best is None or (count, len(term)) > (best[1], len(best[0])):
                        best = (term, count)
            if best is None:
                # Ayni dolayli gorunumler govde icin de gecerlidir: ASCII benzerleri ve ters yazim
                dolayli = _folded_terms_in(folded_body, brand) or _terms_in(reversed_body, brand, 6)
                if dolayli:
                    best, obfuscated = (max(dolayli, key=len), 1), True
            if best is None and has_form and acronyms:
                # Kisa adli kurum: yalnizca logo / baslik benzeri ogede, buyuk harfli tam sozcuk olarak (G-10)
                short_hits = sorted(_short_aliases(brand) & acronyms)
                if short_hits:
                    # Uc-bes harfli kisaltma baska anlamlar da tasir ('UPS Sistemleri', 'BIM Yonetim Paneli'):
                    # zayif kanit
                    best, weak = (max(short_hits, key=len), 1), True
            if best:
                in_body.append((brand, best[0], best[1], obfuscated, weak))

    if strong:
        brand, term = max(strong, key=lambda x: len(x[1]))
        return {"brand": brand, "zone": "identity", "term": term}
    if indirect:
        brand, term = max(indirect, key=lambda x: len(x[1]))
        return {"brand": brand, "zone": "identity", "term": term, "obfuscated": True}
    # Oltalama sayfalari 1-3 logo gosterir; onlarca logolu "musterilerimiz" duvarlari
    # kurumsal tanitim sayfalarina ozgudur ve logo kaniti sayilmaz
    logo_labels = {l.strip().lower() for l in page.get("logos", []) if l and l.strip()}
    if len({b["id"] for b, _ in in_logos}) == 1 and len(logo_labels) <= 8:
        brand, term = in_logos[0]
        return {"brand": brand, "zone": "logo", "term": term}

    def body_result(item, **extra):
        result = {"brand": item[0], "zone": "body", "term": item[1], **extra}
        if item[3]:
            result["obfuscated"] = True
        if item[4]:
            result["weak"] = True
        return result

    if len(in_body) == 1:
        return body_result(in_body[0])
    if len(in_body) > 1 and has_form:
        # Birden fazla kurum (E-08): sayfaya ikinci bir kurumun adini eklemek kimlik tespitini kapatamaz.
        ranked = sorted(in_body, key=lambda x: (-x[2], -len(x[1])))
        top, second = ranked[0], ranked[1]
        names = [item[0]["name"] for item in ranked[:4]]
        if top[2] >= 2 and top[2] > second[2]:
            return body_result(top, others=names[1:])
        # Esitlik (G-10): logo / baslik benzeri ogede gecen tek kurum hedeftir; alt bilgideki ad ile ayni sayilmaz
        featured = [item for item in ranked if _terms_in(prominent, item[0], 3)] if prominent else []
        if len(featured) == 1:
            return body_result(featured[0], others=[n for n in names if n != featured[0][0]["name"]])
        return body_result(top, ambiguous=True, brands=names)
    return None
