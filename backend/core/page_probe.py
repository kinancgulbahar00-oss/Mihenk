"""Sayfa icerigi yoklamasi.

Adreste marka gecmese bile oltalama sayfalari kimligini iceriginde tasir: baslikta
"Garanti BBVA", bir sifre ya da kart formu, verileri Telegram botuna gonderen kod.
Bu modul sayfayi JavaScript calistirmadan, boyut ve sure sinirli olarak indirir.

Guvenlik: sunucunun ic agina istek atilmamasi (SSRF) icin yalnizca herkese acik
IP adreslerine baglanilir; her yonlendirme adimi yeniden denetlenir.
"""

import contextvars
import io
import ipaddress
import json
import logging
import re
import threading
import time
import unicodedata
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import webencodings

from backend.config import settings
from backend.core import urls
from backend.core.cache import BoundedCache
from backend.core.hostnames import to_ascii_or_none
from backend.core.netguard import (
    DEGRADED_PAGE_BUDGET_SECONDS,
    MIN_HOP_SECONDS,
    PAGE_BUDGET_SECONDS,
    SLOW_PROBE_SECONDS,
    BlockedAddressError,
    Deadline,
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    SlowTargetError,
    TargetBusyError,
    current_probe_context,
    page_budget,
    resolve_public,
    targets,
)
from backend.core.suffixes import registrable_domain
from backend.sandbox import pool as parse_pool

try:  # Chrome HTTPS'te 'br' ve 'zstd' de bildirir (E-06); kitaplik yoksa bildirilmez
    import brotli
except ImportError:  # pragma: no cover
    brotli = None
try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None

logger = logging.getLogger("mihenk.page_probe")

# Yoklama istegi, guncel Chrome'un gezinme istegiyle ayni basliklari tasir (A-05, E-06). Baslik kumesi
# sabit DEGILDIR; tarayici gibi baglama gore uretilir:
#   * sec-ch-ua* ve Sec-Fetch-* yalnizca guvenli (https) baglantida gonderilir,
#   * refresh ile gelinen adimda ve cerceve isteginde Referer bulunur, Sec-Fetch-Site baslaticiya gore
#     hesaplanir, Sec-Fetch-User yalnizca kullanicinin baslattigi ilk istekte vardir,
#   * cerceve isteginde Sec-Fetch-Dest 'iframe' olur.
# Degerler gercek tarayicidan kaydedilip backend/data/chrome_headers.json dosyasinda tutulur; ana surum
# PROBE_CHROME_MAJOR ayariyla ezilebilir. Bu, parmak izini zorlastirir; kaldirmaz (TLS, HTTP/2).
_PROFILE_PATH = Path(__file__).resolve().parent.parent / "data" / "chrome_headers.json"


def _load_profile():
    try:
        return json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pragma: no cover
        return {}


CHROME_PROFILE = _load_profile()


def _chrome_major():
    return str(getattr(settings, "PROBE_CHROME_MAJOR", 0) or CHROME_PROFILE.get("chrome_major", 156))


def _user_agent():
    return (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{_chrome_major()}.0.0.0 Safari/537.36")


_SUBRESOURCE_ACCEPT = {"style": "text/css,*/*;q=0.1",
                        "image": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"}


def _request_headers(scheme, nav=None):
    """Tek bir gezinme isteginin basliklari. `nav`: {"referer", "site", "dest", "user"}; None ise adres
    cubuguna yazilmis ilk istek."""
    nav = nav or {}
    major = _chrome_major()
    secure = scheme == "https"
    headers = [("Connection", "keep-alive")]
    if secure:
        # Deger gercek tarayicidan kaydedilen sablondan uretilir (G-03): "GREASE" markasinin metni, surumu ve
        # SIRASI her ana surumde degisir; elle yazilan deger yoklamayi tek baslikla ayirt ettiriyordu.
        template = CHROME_PROFILE.get("sec_ch_ua") or '"Chromium";v="{major}", "Google Chrome";v="{major}"'
        headers += [
            ("sec-ch-ua", template.replace("{major}", major)),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", '"Windows"'),
        ]
    # Alt kaynak istegi (stil sayfasi, gorsel) gezinme istegi degildir: Accept ve Sec-Fetch-* degerleri farklidir
    dest = nav.get("dest", "document")
    sub = _SUBRESOURCE_ACCEPT.get(dest)
    if not sub:
        headers.append(("Upgrade-Insecure-Requests", "1"))
    headers += [
        ("User-Agent", _user_agent()),
        ("Accept", sub or CHROME_PROFILE.get("accept") or "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ]
    if secure:
        headers.append(("Sec-Fetch-Site", nav.get("site", "none")))
        headers.append(("Sec-Fetch-Mode", "no-cors" if sub else "navigate"))
        if nav.get("user", True) and not sub:
            headers.append(("Sec-Fetch-User", "?1"))
        headers.append(("Sec-Fetch-Dest", dest))
    if nav.get("referer"):
        headers.append(("Referer", nav["referer"]))
    encodings = ["gzip", "deflate"]
    if secure:
        if brotli is not None:
            encodings.append("br")
        if zstandard is not None:
            encodings.append("zstd")
    headers.append(("Accept-Encoding", ", ".join(encodings)))
    headers.append(("Accept-Language", CHROME_PROFILE.get("accept_language") or "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"))
    return headers


def _chrome_headers():
    """Geriye donuk uyumluluk: https uzerinden ilk gezinme isteginin basliklari."""
    return _request_headers("https")


REFERRER_POLICIES = frozenset({"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                               "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"})
DEFAULT_REFERRER_POLICY = "strict-origin-when-cross-origin"


def _referrer_policy(value, current=None):
    """Referrer-Policy basligi / <meta name=referrer> degeri: virgulle ayrilmis listede taninan SON ilke gecerlidir."""
    policy = current
    for token in (value or "").lower().split(","):
        token = token.strip()
        if token in REFERRER_POLICIES:
            policy = token
        elif token in ("never",):
            policy = "no-referrer"
        elif token in ("always",):
            policy = "unsafe-url"
    return policy


def _referer(from_url, to_url, policy=None):
    """Tarayicinin gonderecegi Referer degeri (W3C Referrer Policy). Sayfa ilkeyi `Referrer-Policy` basligi ya da
    <meta name=referrer> ile degistirebilir (G-03): 'no-referrer' altinda Referer gonderen istemci tarayici degildir."""
    policy = policy if policy in REFERRER_POLICIES else DEFAULT_REFERRER_POLICY
    source, target = urls.parse(from_url), urls.parse(to_url)
    if not source or not target or source.scheme not in ("http", "https") or policy == "no-referrer":
        return None
    full = source.without_fragment if not source.userinfo else source.origin + "/"
    origin = source.origin + "/"
    same = source.origin == target.origin
    downgrade = source.scheme == "https" and target.scheme != "https"
    if policy == "unsafe-url":
        return full
    if policy == "origin":
        return origin
    if policy == "same-origin":
        return full if same else None
    if policy == "origin-when-cross-origin":
        return full if same else origin
    if policy == "no-referrer-when-downgrade":
        return None if downgrade else full
    if policy == "strict-origin":
        return None if downgrade else origin
    if same:
        return full
    return None if downgrade else origin


def _fetch_site(from_url, to_url):
    source, target = urls.parse(from_url), urls.parse(to_url)
    if not source or not target:
        return "cross-site"
    if source.origin == target.origin:
        return "same-origin"
    if source.scheme == target.scheme and registrable_domain(source.host) == registrable_domain(target.host):
        return "same-site"
    return "cross-site"


def _nav(from_url, to_url, dest="document", user=False, policy=None):
    """Bir belgenin baslattigi gezinme (refresh, cerceve, baglanti) icin istek baglami."""
    return {"referer": _referer(from_url, to_url, policy), "site": _fetch_site(from_url, to_url), "dest": dest,
            "user": user}


USER_AGENT = _user_agent()
# Govde siniri. Sinirda kesilen govde "tam incelendi" sayilmaz (A-01): sonuc `truncated` isareti tasir.
MAX_BYTES = 1_000_000
# Tarayici 20 yonlendirmeye kadar izler; 4 adimlik sinir kolayca asiliyordu (A-14)
MAX_REDIRECTS = 10
# Gomulu belgeler (iframe/frame/object/embed) yonlendirme adimi gibi indirilip incelenir (A-01)
MAX_FRAMES = 3
# Basarisiz yoklama sonucu paylasilan onbellekte kisa sure tutulur (A-09)
FAILURE_CACHE_TTL_SECONDS = 30
# Ayni adresin sonucunu bekleyebilecek istek sayisi; fazlasi beklemeden vazgecer (A-08)
MAX_SHARED_WAITERS = 2
SHARED_WAIT_SECONDS = 6.0
TIMEOUT = 6
# Varsayilan toplam butce; analiz istegi icin gecerli butce netguard.page_budget() ile okunur
# (yuk altinda ve yakin zamanda zaman asimi ureten istemci icin daha kisa; D-03)
TOTAL_BUDGET_SECONDS = 15
# Ara sayfalarin (meta refresh) incelenen en fazla adim sayisi
# Zincirdeki HER belge sonuca girer (D-01): sinir, izlenen en uzun zincirden (yonlendirme + kendine yenileme)
# kisa olamaz; aksi halde besinci adimdaki sayfa hic puanlanmaz.
MAX_INSPECTED_STEPS = 16
# Kisa tutulur: saldirgan sayfayi zararsizken analiz ettirip sonra degistirebilir (F-15)
CACHE_TTL_SECONDS = 5 * 60

_cache = BoundedCache(maxsize=1024, max_age=CACHE_TTL_SECONDS)

PASSWORD_HINTS = ("password", "sifre", "parola", "passwd", "pin")
CARD_HINTS = ("cardnumber", "card_number", "ccnumber", "cc-number", "kartno", "kart_no", "kartnumarasi", "cvv", "cvc",
              "cvv2", "sonkullanma", "son_kullanma", "expiry", "exp-date", "skt")
TCKN_HINTS = ("tckn", "tcno", "tc_no", "tckimlik", "tc-kimlik", "kimlikno", "kimlik_no", "tcid")
PHONE_HINTS = ("telefon", "gsm", "phone", "cep")
SMS_HINTS = ("smskod", "sms_kod", "otp", "dogrulamakodu", "onaykodu", "verificationcode")
REDIRECT_CODES = (301, 302, 303, 307, 308)
# Sayfadaki charset degeri saldirganin denetimindedir. Etiketler tarayicinin tablosuyla (WHATWG Encoding
# Standard; `webencodings`) kodlamaya cevrilir (B-01, E-02). Onceki surumde yalnizca elle tutulan 27 etiket
# taniniyor, tanınmayan etiket sessizce yok sayiliyordu: tarayicinin destekledigi ISO-2022-JP ile etiketlenen
# sayfa platformda UTF-8 olarak cozuluyor ve tumuyle "yorum" saniliyordu.
#
# Kural: belge ancak ASCII uyumlu, durumsuz bir kodlamayla cozulebiliyorsa "tam incelendi" sayilir.
#   * Tablodaki tek baytli kodlamalar ve UTF-8/UTF-16: cozulur, guvenilir.
#   * Cok baytli ve durumlu kodlamalar (iso-2022-jp, gbk, gb18030, big5, euc-*, shift_jis): cozulur, ancak
#     Python ile tarayicinin cozuculeri farkli tablo ve hata kurallari kullandigi icin kapsam `partial` olur.
#   * Tabloda olmayan etiket (tarayici da yok sayar): icerik koklanir, kapsam `partial` olur.
_TRUSTED_ENCODINGS = frozenset({
    "utf-8", "utf-16le", "utf-16be", "ibm866", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5",
    "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-8-i", "iso-8859-10", "iso-8859-13", "iso-8859-14",
    "iso-8859-15", "iso-8859-16", "koi8-r", "koi8-u", "macintosh", "windows-874", "windows-1250",
    "windows-1251", "windows-1252", "windows-1253", "windows-1254", "windows-1255", "windows-1256",
    "windows-1257", "windows-1258", "x-mac-cyrillic", "x-user-defined", "replacement",
})
# Geriye donuk uyumluluk (onceki surumlerin izinli listesi); karar artik WHATWG tablosuyla verilir
ALLOWED_CHARSETS = _TRUSTED_ENCODINGS
_BOMS = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16le"), (b"\xfe\xff", "utf-16be"))
# <meta charset> / <meta http-equiv=Content-Type> on taramasi: tarayici gibi ilk 1.024 bayt (B-01)
_META_CHARSET_RE = re.compile(
    rb"<meta[^>]*?(?:charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]+)|content\s*=\s*[\"'][^\"']*?charset\s*=\s*([A-Za-z0-9._:-]+))",
    re.IGNORECASE)
_XML_DECL_RE = re.compile(rb"^<\?xml[^>]*encoding\s*=\s*[\"']([A-Za-z0-9._:-]+)", re.IGNORECASE)
# ISO-2022 kacis dizileri: kodlama bildirilmemis belgede tarayicinin otomatik algilamasi devreye girebilir
_ISO2022_ESCAPE_RE = re.compile(rb"\x1b[$(][@A-HJ-Z)(]")
# Tarayicinin HTML olarak isledigi XML turleri (B-01): XHTML ve SVG icindeki <foreignObject>
XML_DOCUMENT_TYPES = {"application/xhtml+xml", "application/xml", "text/xml", "image/svg+xml"}
# Icerik turu bildirilmemis ya da genel tur: WHATWG MIME koklama kurallariyla HTML aranir (B-01)
UNKNOWN_TYPES = {"", "unknown/unknown", "application/unknown", "*/*"}
_HTML_SNIFF_RE = re.compile(
    r"^\s*(?:<!doctype\s+html|<(?:html|head|script|iframe|h1|div|font|table|a|style|title|b|body|br|p|form|meta|"
    r"input|link|img|center|span|main|section|noscript)[\s/>]|<!--)", re.IGNORECASE)
_XML_SNIFF_RE = re.compile(r"^\s*<\?xml", re.IGNORECASE)

# Dogrudan dosya indiren adresler (B-10): Turkiye'deki SMS dolandiriciliklarinda APK baglantisi yaygindir
EXECUTABLE_TYPES = {
    "application/vnd.android.package-archive": "Android uygulaması (APK)",
    "application/x-msdownload": "Windows programı",
    "application/x-msdos-program": "Windows programı",
    "application/x-dosexec": "Windows programı",
    "application/x-msi": "Windows kurulum paketi",
    "application/x-ms-installer": "Windows kurulum paketi",
    "application/java-archive": "Java uygulaması",
    "application/hta": "HTML uygulaması (HTA)",
}
ARCHIVE_TYPES = {
    "application/zip": "Arşiv dosyası", "application/x-zip-compressed": "Arşiv dosyası",
    "application/x-rar-compressed": "Arşiv dosyası", "application/vnd.rar": "Arşiv dosyası",
    "application/x-7z-compressed": "Arşiv dosyası", "application/x-iso9660-image": "Disk görüntüsü",
    "application/x-apple-diskimage": "macOS disk görüntüsü",
}
EXECUTABLE_EXTENSIONS = {
    ".apk": "Android uygulaması (APK)", ".xapk": "Android uygulaması (APK)", ".exe": "Windows programı",
    ".msi": "Windows kurulum paketi", ".scr": "Windows programı", ".bat": "Windows betiği", ".cmd": "Windows betiği",
    ".vbs": "Windows betiği", ".ps1": "PowerShell betiği", ".hta": "HTML uygulaması (HTA)",
    ".lnk": "Windows kısayolu", ".jar": "Java uygulaması",
}
ARCHIVE_EXTENSIONS = {
    ".zip": "Arşiv dosyası", ".rar": "Arşiv dosyası", ".7z": "Arşiv dosyası", ".iso": "Disk görüntüsü",
    ".img": "Disk görüntüsü", ".dmg": "macOS disk görüntüsü", ".pkg": "macOS kurulum paketi",
}

# <meta http-equiv="refresh" content="0; url=..."> ara sayfalari HTTP yonlendirmesi gibi izlenir (Z-09).
# Etiket metin aramasiyla DEGIL, HTML ayristiricisiyla bulunur (D-01): HTML yorumu, <noscript>,
# <textarea>, <template>, <title>, <iframe> icindeki ya da betik dizesindeki etiket tarayicida
# yonlendirme yapmaz ve izlenmez. HTTP 'Refresh' yanit basligi da ayni kurallarla izlenir (B-02).
# Gecikmeli yonlendirme de izlenir (A-01): "Yukleniyor" yazan sayfa 12 saniye sonra oltalama sayfasina
# gidebilir. Bu sinirin ustundeki gecikme izlenmez, ancak sayfa "tam incelendi" de sayilmaz.
META_REFRESH_MAX_DELAY = 60
# Bu gecikmenin ustundeki yonlendirme ayrica bildirilir
META_REFRESH_NOTICE_DELAY = 10
_ASCII_WS = " \t\n\f\r"
# Betikle yonlendirme: izlenmez, yalnizca bildirilir (JavaScript calistirilmaz)
_SCRIPT_REDIRECT_RE = re.compile(
    r"(?:(?:window|document|top|self|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*[\"']([^\"']{1,2048})[\"']"
    r"|location\s*\.\s*(?:replace|assign)\s*\(\s*[\"']([^\"']{1,2048})[\"']",
    re.IGNORECASE)
# Ara sayfa: gorunur metni ve formu neredeyse olmayan sayfa
INTERSTITIAL_MAX_TEXT = 300
# Yalnizca standart web portlari; yonlendirmeler de dahil (Y-09)
ALLOWED_PORTS = (None, 80, 443)


class PortNotAllowedError(Exception):
    pass


class _FetchError(Exception):
    pass


def _target_key(host: str) -> str:
    """Hedef basina eszamanlilik sayaci anahtari: kayitli alan adi (IP icin IP)."""
    return host if _is_ip_literal(host) else registrable_domain(host)


def _scope_key(host: str, path: str) -> str:
    """Karantina anahtari (B-04): yavaslik ADRES duzeyinde bir ozelliktir. Bir platformdaki tek
    yavas adres (script.google.com/macros/...) ayni alan adindaki diger sayfalari kapatmasin diye
    karantina tam ad + ilk yol parcasina yazilir."""
    first = (path or "/").lstrip("/").split("/", 1)[0].split("?", 1)[0].lower()[:64]
    return f"{host}/{first}"


def is_protected_target(host: str) -> bool:
    """Katalogdaki bir kurumun adresi mi? Boyle hedefler tek bir zaman asimiyla karantinaya
    alinmaz (D-02): saldirgan baska bir kurumun adresini incelenemez kilamamalidir."""
    if not host or _is_ip_literal(host):
        return False
    from backend.core.brands import owner_brand

    try:
        return bool(owner_brand(host) or owner_brand(_target_key(host)))
    except Exception:
        return False


class _Response:
    def __init__(self, status, headers, body, truncated=False):
        self.status_code = status
        self.headers = headers
        self.body = body
        # Govde MAX_BYTES sinirinda kesildi mi? (A-01)
        self.truncated = truncated or len(body or b"") >= MAX_BYTES


# Bir yoklamanin (yonlendirme zinciri + gomulu belgeler) ortak durumu: cerez kabi ve "kisa butceyle
# yapildi" isareti. Tarayici gibi, zincir boyunca cerezler tasinir (A-05).
_probe_state: contextvars.ContextVar = contextvars.ContextVar("mihenk_probe_state", default=None)


# Cerez kabi tarayicinin kurallarini uygular (RFC 6265; G-03). Onceki surum cerezi yalnizca onu veren TAM ada
# yaziyor ve oznitelikleri okumuyordu: `Domain` ile alt alan adina tasinan cerez gonderilmiyor, `Path`'i
# uymayan / `Secure` / suresi dolmus cerez gonderiliyordu; sunucu bu farkla yoklamayi ayirt edebiliyordu.
# Tarayici alan adi basina 180 cerez ve cerez basina 4.096 bayt kabul eder; daha dusuk sinir sunucuya
# yoklamayi ayirt ettirir ("25. cerezi geri gonderdi mi?").
MAX_COOKIES = 180


def _default_cookie_path(path):
    path = (path or "/").split("?", 1)[0]
    if not path.startswith("/") or path.count("/") <= 1:
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def _path_matches(request_path, cookie_path):
    request_path = (request_path or "/").split("?", 1)[0] or "/"
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        return cookie_path.endswith("/") or request_path[len(cookie_path):len(cookie_path) + 1] == "/"
    return False


def _domain_matches(host, domain):
    return host == domain or (host.endswith("." + domain) and not _is_ip_literal(host))


def _cookie_header(host, path="/", secure=False):
    state = _probe_state.get()
    jar = (state or {}).get("cookies") or []
    if not isinstance(jar, list):
        return None
    host = (host or "").lower()
    now = time.time()
    matched = []
    for c in jar:
        if c["expires"] is not None and c["expires"] <= now:
            continue
        if c["secure"] and not secure:
            continue
        if (host != c["domain"]) if c["host_only"] else (not _domain_matches(host, c["domain"])):
            continue
        if not _path_matches(path, c["path"]):
            continue
        matched.append(c)
    # Tarayici daha uzun yollu cerezi once gonderir
    matched.sort(key=lambda c: -len(c["path"]))
    return "; ".join(f"{c['name']}={c['value']}" for c in matched[:MAX_COOKIES]) if matched else None


def _store_cookies(host, values, path="/", secure=False):
    state = _probe_state.get()
    if state is None or not values:
        return
    jar = state.get("cookies")
    if not isinstance(jar, list):
        jar = state["cookies"] = []
    host = (host or "").lower()
    registrable = host if _is_ip_literal(host) else registrable_domain(host)
    for value in values[:MAX_COOKIES]:
        parts = value.split(";")
        name, sep, val = parts[0].strip().partition("=")
        name, val = name.strip(), val.strip()
        if not sep or not name or len(name) + len(val) > 4096 or any(ch in name + val for ch in "\r\n"):
            continue
        cookie = {"name": name, "value": val, "domain": host, "host_only": True, "path": _default_cookie_path(path),
                  "secure": False, "expires": None}
        rejected = False
        max_age = None
        for attr in parts[1:]:
            key, _, attr_value = attr.strip().partition("=")
            key, attr_value = key.strip().lower(), attr_value.strip()
            if key == "domain" and attr_value:
                domain = attr_value.lstrip(".").lower()
                # Alan adi istegin adini kapsamali ve bir "public suffix" olmamali (com.tr, blogspot.com ...)
                if not _domain_matches(host, domain) or _is_ip_literal(host) or \
                        not (domain == registrable or domain.endswith("." + registrable)):
                    rejected = True
                else:
                    cookie["domain"], cookie["host_only"] = domain, False
            elif key == "path" and attr_value.startswith("/"):
                cookie["path"] = attr_value
            elif key == "secure":
                cookie["secure"] = True
            elif key == "max-age":
                try:
                    max_age = int(attr_value)
                except ValueError:
                    pass
            elif key == "expires" and max_age is None:
                try:
                    from email.utils import parsedate_to_datetime

                    cookie["expires"] = parsedate_to_datetime(attr_value).timestamp()
                except (TypeError, ValueError, OverflowError):
                    pass
        if rejected or (cookie["secure"] and not secure):
            continue  # tarayici duz HTTP uzerinden gelen Secure cerezi kabul etmez
        if max_age is not None:
            cookie["expires"] = time.time() + max_age if max_age > 0 else 0
        # Ayni ad + alan + yol: eskisinin yerine gecer; suresi dolmus deger cerezi siler
        jar[:] = [c for c in jar if not (c["name"] == name and c["domain"] == cookie["domain"]
                                         and c["host_only"] == cookie["host_only"] and c["path"] == cookie["path"])]
        if cookie["expires"] is not None and cookie["expires"] <= time.time():
            continue
        if len(jar) < MAX_COOKIES:
            jar.append(cookie)


def _is_ip_literal(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _fetch_once(url, deadline, pinned=None):
    """Tek bir istek. Alan adi bir kez cozumlenir, denetlenir ve baglanti o IP'ye sabitlenir.
    `pinned` ({ad: ip}) analiz hattinin basinda cozumlenmis adresi tasir (B-11): ilk adimda ad
    ikinci kez cozumlenmez; saldirganin ad sunucusu iki sorguya farkli yanit veremez.

    Adres TEK bir ayristiriciyla (tarayici kurallari; backend/core/urls.py) cozulur (E-03): denetlenen,
    baglanilan ve Host basliginda gonderilen ad aynidir.

    Sure butcesi soket duzeyinde zorlanir (Y-02): `deadline` aninda bekci soketi kapatir;
    TLS el sikismasi, baslik ve govde okumasi ne kadar yavas olursa olsun cagri en gec
    o anda doner. Govde, tamponun dolmasini beklemeyen read1() ile okunur."""
    target = urls.parse(url)
    if target is None or target.scheme not in ("http", "https") or not target.host:
        raise BlockedAddressError(url)
    host = target.host
    # Yonlendirme hedefi Unicode alan adi tasiyabilir: DNS, SNI ve Host basligi tarayicinin
    # kullanacagi UTS-46 ASCII bicimle yapilir (Python'un IDNA 2003 kodlayicisiyla degil; Y-06)
    if not _is_ip_literal(host):
        host = to_ascii_or_none(host)
        if not host:
            raise _FetchError("invalid host")
    port = target.port
    if port not in ALLOWED_PORTS:
        raise PortNotAllowedError(url)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _FetchError("budget exhausted")
    ip = (pinned or {}).get(host)
    if ip is None:
        ip = resolve_public(host, timeout=min(4, remaining))  # ic ag adresinde BlockedAddressError
    if ip is None:
        raise _FetchError("unresolved")
    ctx = current_probe_context()
    if ctx is not None:
        ctx.record_ip(ip)

    # Ayni hedefe sinirli sayida yoklama, ayni IP'ye sinirli sayida yoklama (Z-04, D-03, B-04).
    # Karantina tam ad + ilk yol parcasina yazilir (B-04).
    key = _target_key(host)
    scope = _scope_key(host, target.target.split("?", 1)[0])
    protected = is_protected_target(host)
    degraded = not protected and targets.ip_degraded(ip) and not targets.seen_ok(key)
    if degraded:
        state = _probe_state.get()
        if state is not None:
            state["reduced"] = True
        # Bu IP'de birbirinden farkli adlar yakin zamanda sure butcesini doldurdu (D-03). IP'deki
        # siteler INCELENMEYE devam eder (B-05). Kisa butce yalnizca bu IP'de daha once basariyla
        # yanit vermemis adlara uygulanir (A-10): paylasimli sunucudaki bilinen siteler - agir
        # sayfalari dahil - tam butce alir, saldirganin yeni adlari ortak yuvalari tutamaz.
        deadline = min(deadline, time.monotonic() + DEGRADED_PAGE_BUDGET_SECONDS)
    with targets.acquire(key, ip=ip, protected=protected, scope=scope, wait=0.0 if degraded else None):
        started = time.monotonic()
        given = deadline - started
        try:
            result = _fetch_pinned(target, host, ip, port, deadline)
        except _FetchError as exc:
            if str(exc) == "budget exhausted":
                # Alt kaynak (stil sayfasi, gorsel) kisa ve ayri bir sureyle istenir; yavas bir alt kaynak ne
                # istemciye ceza ne hedefe karantina yazar (mesru sitelerin ucuncu taraf kaynaklari yavas olabilir)
                if ctx and not (_probe_state.get() or {}).get("in_subresource"):
                    ctx.record_timeout(key)
                # Karantina yalnizca sureyi KENDISI tuketen hedefe yazilir (D-02): bu adima en az
                # MIN_HOP_SECONDS verilmis ve o bunu doldurmus olmali. Onceki adimlarin harcadigi
                # sure yonlendirilen hedefe yazilmaz.
                if given >= MIN_HOP_SECONDS and time.monotonic() - started >= MIN_HOP_SECONDS - 0.05:
                    targets.record_timeout(key, ip=ip, client=ctx.client if ctx else None,
                                           protected=protected, scope=scope)
                else:
                    logger.info("probe budget exhausted on short hop; not quarantined target=%s given=%.1fs",
                                scope, given)
            raise
        elapsed = time.monotonic() - started
        targets.record_success(key, scope=scope)
        if ctx is not None and elapsed >= SLOW_PROBE_SECONDS:
            # Butceyi asmayan ama uzun suren yoklamalar da istemciye yazilir (B-04): hedef sayacini
            # yavas bir adresle surekli dolu tutan istemci kisa butceye duser.
            ctx.record_slow(scope)
        return result


def _fetch_pinned(target, host, ip, port, deadline):

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _FetchError("budget exhausted")
    timeout = max(0.5, min(TIMEOUT, remaining))
    with Deadline(remaining) as watchdog:
        conn_cls = PinnedHTTPSConnection if target.scheme == "https" else PinnedHTTPConnection
        conn = conn_cls(host, ip, port=port, timeout=timeout, deadline=watchdog)
        try:
            # Basliklar istegin baglamina gore uretilir (E-06): ilk istek, refresh adimi, cerceve
            state = _probe_state.get()
            request_headers = dict(_request_headers(target.scheme, (state or {}).get("nav")))
            secure = target.scheme == "https"
            cookie = _cookie_header(host, target.path, secure)
            if cookie:
                request_headers["Cookie"] = cookie
            conn.request("GET", target.target, headers=request_headers)
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            _store_cookies(host, response.msg.get_all("set-cookie") or [], target.path, secure)
            # Location basligi olmayan 3xx yaniti yonlendirme DEGILDIR: tarayici govdesini sayfa olarak gosterir
            if response.status in REDIRECT_CODES and (headers.get("location") or "").strip():
                return _Response(response.status, headers, b"")

            raw = bytearray()
            while len(raw) < MAX_BYTES and time.monotonic() < deadline:
                chunk = response.read1(32_768)  # eldeki kadarini dondurur, tamponu doldurmayi beklemez
                if not chunk:
                    break
                raw += chunk
            if watchdog.expired:
                raise _FetchError("budget exhausted")
            truncated = len(raw) >= MAX_BYTES
            raw = _decode_body(bytes(raw[:MAX_BYTES]), headers.get("content-encoding", ""))
            return _Response(response.status, headers, raw, truncated=truncated)
        except _FetchError:
            raise
        except Exception as exc:
            # http.client.HTTPException, ssl hatalari, zaman asimi, bekci tarafindan kapatilan soket vb.
            if watchdog.expired or time.monotonic() >= deadline:
                raise _FetchError("budget exhausted") from exc
            raise _FetchError(str(exc)) from exc
        finally:
            conn.close()


def _decode_body(raw, encoding):
    """Sikistirilmis govdeyi acar. Acilan boyut her kodlamada MAX_BYTES ile sinirlidir (sikistirma bombasi)."""
    encoding = (encoding or "").lower().strip()
    if encoding == "br" and brotli is not None:
        try:
            decoder = brotli.Decompressor()
            return decoder.process(raw, output_buffer_limit=MAX_BYTES)[:MAX_BYTES]
        except Exception:
            return b""
    if encoding == "zstd" and zstandard is not None:
        try:
            # Chrome 8 MB'tan buyuk pencereyi reddeder; bellek kullanimi boylece sinirlidir
            reader = zstandard.ZstdDecompressor(max_window_size=8 * 1024 * 1024).stream_reader(io.BytesIO(raw))
            return reader.read(MAX_BYTES)
        except Exception:
            return b""
    if encoding not in ("gzip", "deflate", "x-gzip"):
        return raw  # bildirilmeyen bir kodlama gonderilirse govde HTML olarak taninmaz ve "incelenemedi" olur
    # gzip; deflate icin once zlib sarmali, sonra ham deflate (tarayicilar ikisini de acar; A-14)
    for wbits in ((16 + zlib.MAX_WBITS,) if "gzip" in encoding else (zlib.MAX_WBITS, -zlib.MAX_WBITS)):
        try:
            decoder = zlib.decompressobj(wbits)
            # Sikistirma bombasina karsi acilan boyut da sinirlidir
            return decoder.decompress(raw, MAX_BYTES)
        except zlib.error:
            continue
    return b""


# Sagdan sola gecersiz kilma (U+202E … U+202C): tarayici aradaki metni TERS sirayla gosterir. Kurum adi
# ters yazilip bu karakterle "duzeltilebilir" (A-03). Eslestirme gorsel sira uzerinden yapilir.
_RLO_RE = re.compile("\u202e([^\u202c\u202a\u202b\u202d\u202e]*)(?:\u202c|$)")
_BIDI_CONTROL_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")


def _visual(text):
    if "\u202e" not in (text or ""):
        return text
    return _RLO_RE.sub(lambda m: m.group(1)[::-1], text)


def _flatten(s):
    return re.sub(r"[^a-z0-9]", "", s.lower().translate(str.maketrans("ışğüöç", "isguoc")))


def _has(inputs, hints):
    return any(any(h in _flatten(i) for h in hints) for i in inputs)


def probe_page(url, resolved_ip=None):
    """Sayfayi indirir ve oltalama icin anlamli ozellikleri cikarir. Basarisizsa status ile doner.
    `resolved_ip`: analiz hattinin basinda bu adres icin dogrulanmis IP (B-11; ilk adimda kullanilir).

    Saldirganin denetimindeki hicbir veri (baslik, govde, yonlendirme adresi) bu islevden
    istisna firlatamaz (Z-02): her hata {"status": "error"} sonucuna donusur, analizin geri
    kalani (alan adi, kayit yasi, TLS) surer ve "sayfa incelenemedi" bulgusu uretilir."""
    if not getattr(settings, "PAGE_FETCH_ENABLED", True):
        return {"status": "disabled"}
    try:
        return _probe_page_shared(url, resolved_ip)
    except Exception:
        logger.warning("page probe failed url=%r", url[:200], exc_info=True)
        return _store(url, {"status": "error", "redirects": [url]})


# --- Icerik turu ve kodlama: tarayicinin kurallari (B-01) -------------------------

def _media_type(headers):
    return (headers.get("content-type", "") or "").split(";", 1)[0].strip().lower()


def _header_charset(headers):
    match = re.search(r"charset\s*=\s*[\"']?([A-Za-z0-9._:-]+)", headers.get("content-type", "") or "", re.IGNORECASE)
    return match.group(1) if match else None


def _lookup(label):
    """WHATWG etiketi -> kodlama; tarayicinin tanimadigi etiket icin None."""
    try:
        return webencodings.lookup((label or "").strip())
    except Exception:
        return None


def _codec(label):
    """Saldirganin denetimindeki kodlama etiketini Python kod cozucu adina cevirir; taninmiyorsa None."""
    encoding = _lookup(label)
    return encoding.codec_info.name if encoding else None


class _Decoded:
    """Bir govdenin kodlama karari. `confident`: BOM ya da Content-Type basligi (belgedeki <meta> dikkate
    alinmaz). `opaque`: cozulen metin tarayicinin gordugu metinle ayni olmayabilir (E-02)."""

    __slots__ = ("encoding", "body", "confident", "opaque")

    def __init__(self, encoding, body, confident, opaque):
        self.encoding = encoding
        self.body = body
        self.confident = confident
        self.opaque = opaque

    @property
    def name(self):
        return self.encoding.name

    @property
    def text(self):
        try:
            return self.encoding.codec_info.decode(self.body, "replace")[0]
        except (LookupError, UnicodeError, ValueError):
            return self.body.decode("utf-8", errors="replace")


def _meta_encoding(label):
    """<meta> ile bildirilen etiket: (kodlama | None, taninmadi mi). BOM'suz belgede UTF-16 etiketi UTF-8,
    x-user-defined etiketi windows-1252 sayilir (WHATWG)."""
    encoding = _lookup(label)
    if encoding is None:
        return None, bool((label or "").strip())
    if encoding.name in ("utf-16le", "utf-16be"):
        encoding = webencodings.UTF8
    elif encoding.name == "x-user-defined":
        encoding = _lookup("windows-1252")
    return encoding, False


def _encoding_plan(raw, header_charset, xml=False):
    """Tarayicinin sirasi: bayt sirasi isareti (BOM), Content-Type charset, ilk 1.024 bayttaki
    <meta charset> / <meta http-equiv=Content-Type> (XML'de bildirim), son olarak icerik:
    gecerli UTF-8 degilse Turkce sitelerde yaygin windows-1254."""
    for bom, name in _BOMS:
        if raw.startswith(bom):
            return _Decoded(_lookup(name), raw[len(bom):], True, False)
    unknown = False
    if header_charset:
        encoding = _lookup(header_charset)
        if encoding is not None:
            return _Decoded(encoding, raw, True, encoding.name not in _TRUSTED_ENCODINGS)
        unknown = True  # tarayici da yok sayar; hangi kodlamaya dusecegi bilinmez
    head = raw[:1024]
    m = (_XML_DECL_RE.search(head) if xml else None) or _META_CHARSET_RE.search(head)
    if m:
        label = next((g for g in m.groups() if g), b"").decode("ascii", "ignore")
        encoding, not_recognised = _meta_encoding(label)
        unknown = unknown or not_recognised
        if encoding is not None:
            return _Decoded(encoding, raw, False, unknown or encoding.name not in _TRUSTED_ENCODINGS)
    # Kodlama bildirilmemis: ISO-2022 kacis dizisi tasiyan govdede tarayicinin algilamasi baska bir kodlama
    # secebilir; sonuc guvenilir sayilmaz
    unknown = unknown or bool(_ISO2022_ESCAPE_RE.search(raw))
    try:
        raw.decode("utf-8")
        return _Decoded(webencodings.UTF8, raw, False, unknown)
    except UnicodeDecodeError as exc:
        # Govde sinirda kesilmis olabilir: yalnizca son birkac bayt hataliysa yine UTF-8
        if exc.start >= len(raw) - 4:
            return _Decoded(webencodings.UTF8, raw, False, unknown)
    return _Decoded(_lookup("windows-1254"), raw, False, unknown)


def _detect_encoding(raw, header_charset, xml=False):
    """Doner: (Python kod cozucu adi, BOM'suz govde)."""
    plan = _encoding_plan(raw, header_charset, xml=xml)
    return plan.encoding.codec_info.name, plan.body


def _decode_html(raw, charset, xml=False):
    return _encoding_plan(raw, charset, xml=xml).text


def _document_kind(response, text):
    """Yanit tarayicida HTML olarak mi islenir? 'html', 'xml' (XHTML/SVG) ya da None (B-01)."""
    mtype = _media_type(response.headers)
    if mtype in XML_DOCUMENT_TYPES or mtype.endswith("+xml"):
        return "xml"
    if "html" in mtype:
        return "html"
    head = text[:2048]
    if mtype in UNKNOWN_TYPES:
        # Icerik turu bildirilmemis: tarayici icerigi koklar; <html> etiketi HTML'de istege baglidir
        if _HTML_SNIFF_RE.match(head):
            return "html"
        if _XML_SNIFF_RE.match(head):
            return "xml"
    # Onceki surumle uyum: govdesinde <html bulunan yanit, turu ne olursa olsun incelenir
    if "<html" in head.lower():
        return "html"
    return None


def _is_html(response):
    return _document_kind(response, _decode_html(response.body, _header_charset(response.headers))) is not None


def _download_info(response, url):
    """Yanit dogrudan dosya indiriyor mu (B-10)? Doner: {kind, risk, filename, content_type, sha256} ya da None."""
    headers = response.headers
    mtype = _media_type(headers)
    disposition = headers.get("content-disposition", "") or ""
    attachment = disposition.strip().lower().startswith("attachment")
    m = re.search(r"filename\*?\s*=\s*(?:UTF-8'')?[\"']?([^\"';]+)", disposition, re.IGNORECASE)
    filename = (m.group(1).strip() if m else "") or (urlsplit(url).path.rsplit("/", 1)[-1])
    filename = filename[:120]
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    body = response.body or b""

    kind, risk = None, None
    if body[:4] == b"PK\x03\x04" and (b"AndroidManifest.xml" in body[:65536] or b"classes.dex" in body[:65536]):
        kind, risk = "Android uygulaması (APK)", "high"
    elif mtype in EXECUTABLE_TYPES:
        kind, risk = EXECUTABLE_TYPES[mtype], "high"
    elif ext in EXECUTABLE_EXTENSIONS and (attachment or mtype in ("application/octet-stream", "binary/octet-stream", "")
                                           or mtype in ARCHIVE_TYPES):
        kind, risk = EXECUTABLE_EXTENSIONS[ext], "high"
    elif body[:2] == b"MZ" and (attachment or mtype in ("application/octet-stream", "")):
        kind, risk = "Windows programı", "high"
    elif mtype in ARCHIVE_TYPES:
        kind, risk = ARCHIVE_TYPES[mtype], "medium"
    elif ext in ARCHIVE_EXTENSIONS and (attachment or mtype in ("application/octet-stream", "binary/octet-stream", "")):
        kind, risk = ARCHIVE_EXTENSIONS[ext], "medium"
    elif attachment and ext == ".js":
        kind, risk = "JavaScript dosyası", "high"
    if not kind:
        return None
    info = {"kind": kind, "risk": risk, "filename": filename or None, "content_type": mtype or None}
    if body and len(body) < MAX_BYTES:
        import hashlib

        info["sha256"] = hashlib.sha256(body).hexdigest()
    return info


# --- Yonlendirme: WHATWG "shared declarative refresh steps" (B-02) ------------------

def _parse_refresh(content):
    """Refresh degerini tarayici gibi ayristirir. Doner: (gecikme, adres) ya da None.
    Sure ile adres arasinda ';', ',' ya da bosluk; 'url=' oneki ve tirnak istege baglidir."""
    s = content or ""
    n = len(s)
    i = 0
    while i < n and s[i] in _ASCII_WS:
        i += 1
    start = i
    while i < n and "0" <= s[i] <= "9":
        i += 1
    digits = s[start:i]
    if not digits and not (i < n and s[i] == "."):
        return None
    delay = int(digits) if digits else 0
    while i < n and (s[i] == "." or "0" <= s[i] <= "9"):
        i += 1
    if i < n:
        if s[i] not in ";," + _ASCII_WS:
            return None
        while i < n and s[i] in _ASCII_WS:
            i += 1
        if i < n and s[i] in ";,":
            i += 1
        while i < n and s[i] in _ASCII_WS:
            i += 1
    if i >= n:
        return delay, None
    j = i
    if s[j:j + 3].lower() == "url":
        k = j + 3
        while k < n and s[k] in _ASCII_WS:
            k += 1
        if k < n and s[k] == "=":
            k += 1
            while k < n and s[k] in _ASCII_WS:
                k += 1
            j = k
    quote = None
    if j < n and s[j] in "'\"":
        quote = s[j]
        j += 1
    target = s[j:]
    if quote and quote in target:
        target = target[:target.index(quote)]
    # URL ayristiricisi sekme ve satir sonlarini atar, bastaki/sondaki bosluklari kirpar
    target = re.sub(r"[\t\n\r]", "", target).strip(" \x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f")
    return delay, (target or None)


def _refresh_target(content):
    """<meta http-equiv=refresh> / Refresh basligi degerinden izlenecek hedef; yoksa None.
    Gecikme META_REFRESH_MAX_DELAY saniyeye kadar izlenir (A-01)."""
    parsed = _parse_refresh(content)
    if not parsed:
        return None
    delay, target = parsed
    if target and delay <= META_REFRESH_MAX_DELAY:
        return target
    return None


def _refresh_delay(content):
    parsed = _parse_refresh(content)
    return parsed[0] if parsed and parsed[1] else 0


# Bir analiz isteginin butun belgeleri icin toplam ayristirma suresi (G-08). Ayristirma iscileri ortak bir
# kaynaktir: tek bir istek, zincirin her adiminda isciyi sure sinirina kadar tutan belgelerle havuzu
# dakikalarca mesgul edemez. Ilk zaman asimindan sonra ayni istegin kalan belgeleri kisa sureyle islenir.
PARSE_BUDGET_PER_PROBE = 4.0
PARSE_TIMEOUT_AFTER_STRIKE = 0.5
# Yakin zamanda ayristirma zaman asimi ureten istemci dusuk onceliklidir: havuzdaki SON bos isciyi alamaz
PARSE_STRIKE_SECONDS = 10 * 60
# Tarayicilar 512 duzeyden derin ic ice ogeleri duzlestirir. Acilan - kapanan etiket farki bu sinirin cok
# ustundeyse belge ayristirilmadan "incelenemedi" sayilir (agac kurucu derin ic ice ogelerde karesel sure tuketir).
MAX_NESTING_ESTIMATE = 20_000
_TAG_SCAN_RE = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9]*)")
_COMMENT_SCAN_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
# Ic ice SAYILMAYAN ogeler: bos ogeler (<br>, <img>, <input> ...) ve bir sonraki kardesiyle kendiliginden kapanan
# ogeler (<li>, <p>, <td>, <option> ...). Onceki surum acilan - kapanan etiket farkina bakiyordu: 20.001 <br>
# (80 KB) tasiyan sayfa hic ayristirilmiyor, bilinen bir oltalama sayfasi "incelenemedi" sonucuna iniyordu.
_NON_NESTING = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "param",
    "li", "p", "td", "th", "tr", "option", "optgroup", "dt", "dd", "thead", "tbody", "tfoot", "colgroup", "rt", "rp",
    "html", "head", "body"})


def _nesting_estimate(html):
    """Belgenin ulasabilecegi en buyuk ic ice derinlik (dogrusal tarama; yorumlar atlanir)."""
    depth = peak = 0
    for m in _TAG_SCAN_RE.finditer(_COMMENT_SCAN_RE.sub(" ", html)):
        if m.group(2).lower() in _NON_NESTING:
            continue
        if m.group(1):
            if depth:
                depth -= 1
        else:
            depth += 1
            if depth > peak:
                peak = depth
    return peak


_RAW_TITLE_RE = re.compile(r"<title[^<>]{0,200}>([^<]{0,300})", re.IGNORECASE)
_RAW_TAG_RE = re.compile(r"<[^<>]{0,400}>")
_parse_strikes = {}
_parse_strikes_lock = threading.Lock()


def _client_parse_struck(client):
    if not client:
        return False
    with _parse_strikes_lock:
        when = _parse_strikes.get(client)
        return when is not None and when >= time.monotonic() - PARSE_STRIKE_SECONDS


def _record_parse_strike(client):
    if not client:
        return
    with _parse_strikes_lock:
        if len(_parse_strikes) > 10_000:
            _parse_strikes.clear()
        _parse_strikes[client] = time.monotonic()


def _parse_timeout():
    """Ayristirma suresi: istegin yoklama butcesiyle orantili, istegin kalan ayristirma butcesiyle sinirli."""
    limit = min(parse_pool.PARSE_TIMEOUT_SECONDS, max(0.5, page_budget() / 5))
    state = _probe_state.get()
    if state is not None:
        if state.get("parse_strikes"):
            limit = min(limit, PARSE_TIMEOUT_AFTER_STRIKE)
        limit = min(limit, PARSE_BUDGET_PER_PROBE - state.get("parse_spent", 0.0))
    return limit


def _extract(html, xml=False, url=None):
    """Belgeyi isci surecte, HTML5 agac kurucusuyla ayristirir (E-01). Basarisizsa None."""
    state = _probe_state.get()
    ctx = current_probe_context()
    client = ctx.client if ctx else None
    timeout = _parse_timeout()
    if timeout < 0.2:
        logger.info("html parse skipped: probe parse budget exhausted chars=%d", len(html))
        return None
    if _nesting_estimate(html) > MAX_NESTING_ESTIMATE:
        logger.warning("html parse skipped: nesting estimate above limit chars=%d", len(html))
        if state is not None:
            state["parse_strikes"] = state.get("parse_strikes", 0) + 1
        return None
    low_priority = bool(state and state.get("parse_strikes")) or _client_parse_struck(client)
    started = time.monotonic()
    try:
        return parse_pool.extract(html, xml=xml, timeout=timeout, low_priority=low_priority)
    except parse_pool.ParseFailed as exc:
        logger.warning("html parse failed reason=%s chars=%d", exc, len(html))
        if str(exc) == "timeout":
            if state is not None:
                state["parse_strikes"] = state.get("parse_strikes", 0) + 1
            _record_parse_strike(client)
            _blame_slow_parse(url)
        return None
    finally:
        if state is not None:
            state["parse_spent"] = state.get("parse_spent", 0.0) + (time.monotonic() - started)


def _blame_slow_parse(url):
    """Ayristiriciyi sure sinirina kadar mesgul eden belge, yavas yanit veren hedef gibi islenir (Z-04, D-03):
    istemciye zaman asimi yazilir (yineleyen istemci kisa butceye duser) ve adres karantinaya alinir."""
    parsed = urls.parse(url) if url else None
    if parsed is None or not parsed.host:
        return
    host = _canonical_host(parsed)
    key = _target_key(host)
    ctx = current_probe_context()
    if ctx:
        ctx.record_timeout(key)
    try:
        targets.record_timeout(key, client=ctx.client if ctx else None, protected=is_protected_target(host),
                               scope=_scope_key(host, parsed.path))
    except Exception:  # pragma: no cover
        pass


def _first_refresh(contents):
    """Belgedeki ilk gecerli <meta http-equiv=refresh>: (gecikme, hedef, uzun_gecikme). Hedefi olmayan
    refresh sayfayi yeniden yukler; hedef olarak belgenin kendisi ('') doner (E-05)."""
    # Birden fazla gecerli etiket: Chromium, gecikmesi oncekinden KISA YA DA ESIT olan sonraki etiketi gecerli sayar
    # (Chromium 156 ile olculdu: '5; url=/A' + '0; url=/B' -> /B; '0; url=/A' + '0; url=/B' -> /B). Standart "ilk
    # etiket" der; hedefler farkliysa sayfa ayrica "tam incelendi" sayilmaz (`refresh_conflict`).
    chosen = None
    for content in contents or []:
        parsed = _parse_refresh(content)
        if parsed and (chosen is None or parsed[0] <= chosen[0]):
            chosen = parsed
    if chosen is None:
        return 0, None, False
    delay, target = chosen
    if delay > META_REFRESH_MAX_DELAY:
        return 0, None, True
    return delay, target or "", False


def _meta_refresh_target(html):
    """Gecikmesi kisa <meta http-equiv=refresh> hedefi; yoksa None. Etiket metin aramasiyla degil, kurulan
    agactan okunur (D-01, E-01): yorum, <noscript>, <textarea>, <template> icindeki etiket oge degildir."""
    facts = _extract(html)
    if not facts:
        return None
    return _first_refresh(facts.get("meta_refresh"))[1] or None


# Eylem cagrisi: haber sayfalarinda yaygin olan "devamini oku", "indirim" gibi ifadeler bilincli olarak yok
_PROMINENT_LINK_WORDS = ("dogrula", "girisyap", "oturumac", "onayla", "guncelle", "hesabim", "hesabini", "kimlig",
                         "sifre", "odemeyap", "verify", "login", "signin", "confirm", "unlock",
                         "devamet", "tiklayin", "buraya", "ilerle", "islemedevam", "hemenbasla", "continue", "proceed")
# Kurum adini bolen gorunmez bicim karakterleri (B-01) ve yon degistirme karakterleri (A-03)
_SPLIT_BY_INVISIBLE_RE = re.compile("\\w[\u00ad\u034f\u180e\u200b-\u200f\u2060-\u2064\ufeff\x01-\x08\x0e-\x1f\x7f-\x9f]+\\w")
# Yem sayfasinin imzasi: kisa metin + az sayida hedef (A-04, E-12). Haber sayfalarinda metin uzundur ve
# baglantilar cok sayida farkli adrese gider.
LURE_MAX_TEXT = 1500
LURE_MAX_EXTERNAL_HOSTS = 3
LURE_MAX_LINK_TARGETS = 3
# Baska bir kurumun kimligini tasiyan sayfadan izlenen en fazla adres (E-12, G-09)
MAX_FOLLOWED_LINKS = 3
# Bir analizin gomulu belgeler ve baglantilar icin gonderebilecegi en fazla istek (G-12)
MAX_EMBEDDED_REQUESTS = 12
# Sayfa metnindeki tuzak ifadeleri (G-09): yem sayfasi baglanti metnini degistirse de bu ifadeleri kullanir
_BAIT_TEXT = ("hesabinizkisit", "hesabinizaskiya", "hesabinizbloke", "hesabinizdondur", "olagandisi", "supheliislem",
              "kimliginizidogrula", "hesabinizidogrula", "bilgilerinizigüncelle".replace("ü", "u"), "kisitlamayikaldir",
              "erisiminizkisit", "guvenliginizicin", "unusualactivity", "verifyyouridentity", "accountsuspended",
              "accounthasbeen")
# Durum degistirebilecek baglantilar izlenmez (G-12): tek kullanimlik onay / iptal / sifre sifirlama baglantilari
_TOKEN_PARAMS = ("token", "key", "code", "sig", "signature", "hash", "auth", "otp", "ticket", "sid", "session", "confirm",
                 "verify", "unsubscribe", "reset", "activation", "invite")
_TOKEN_VALUE_RE = re.compile(r"[A-Za-z0-9_\-]{16,}")


def _state_changing_link(address):
    """Baglanti bir belirtec (token) tasiyor mu? Boyle bir adresi ziyaret etmek kullanici adina islem yapabilir."""
    parsed = urls.parse(address)
    if parsed is None:
        return True
    _, _, query = parsed.target.partition("?")
    if not query:
        return False
    for pair in query.split("&")[:30]:
        name, _, value = pair.partition("=")
        if any(t in name.lower() for t in _TOKEN_PARAMS) or _TOKEN_VALUE_RE.fullmatch(value or ""):
            return True
    return False


def _spelled_words(chunks):
    """Harf harf ayri ogelere yazilmis sozcukler (G-06): art arda gelen tek karakterlik metin parcalari birlestirilir
    ('<td>G</td><td>a</td><td>r</td>…' ekranda bitisik gorunur). En az dort harflik diziler doner."""
    words, run = [], []
    for chunk in list(chunks) + ["--"]:
        if len(chunk) == 1 and chunk.isalnum():
            run.append(chunk)
            continue
        if len(run) >= 4:
            words.append("".join(run))
        run = []
    return words[:10]
# Etiket (<label>) ve alan aciklamasi metninden alan tanima (A-04, E-10): yanlis eslesmeye acik kisa
# ipuclari ('pin', 'cep', 'skt') yok
# Tek alanli GET formunu arama kutusu sayan ipuclari (tur, ad, yer tutucu sozcukleri)
_SEARCH_WORDS = frozenset({"search", "q", "s", "k", "query", "ara", "arama", "aranacak", "keyword", "keywords", "kelime",
                           "sorgu", "find", "bul"})
LABEL_PASSWORD_HINTS = ("sifre", "parola", "password", "passwd", "giriskodu", "guvenlikkodunuz")
LABEL_CARD_HINTS = ("kartno", "kartnumara", "cardnumber", "cvv", "cvc", "sonkullanma", "guvenlikkodu", "16hane",
                    "kartinizin", "kartuzerindeki")
LABEL_TCKN_HINTS = ("tckimlik", "kimlikno", "tckn", "tcno", "kimliknumara", "vatandaslikno", "vatandasliknumara")
# Statik gorunum ile ham metnin kaba karsilastirmasi (rapor 7.1, "iki gorunum"): ham metinde form/parola
# alani var, kurulan agacta yoksa ayristirma belirsizdir
_RAW_PASSWORD_RE = re.compile(r"type\s*=\s*[\"']?\s*password", re.IGNORECASE)
_RAW_INPUT_RE = re.compile(r"<(?:input|textarea|select)[\s/>]", re.IGNORECASE)
_RAW_FORM_RE = re.compile(r"<form[\s/>]", re.IGNORECASE)
_RAW_FRAME_RE = re.compile(r"<(?:iframe|frame|object|embed)[\s/>]", re.IGNORECASE)
_XML_INTERNAL_RE = re.compile(r"<!doctype[^>\[]*\[|<!entity|<!attlist|<\?xml-stylesheet", re.IGNORECASE)
# Tek bir sozcukte Latin harflerle birlikte kullanilan benzer yazi sistemleri (E-09)
_LOOKALIKE_SCRIPTS = ("GREEK", "CYRILLIC", "ARMENIAN", "CHEROKEE", "COPTIC")
_WORD_RE = re.compile(r"\w+")


def _mixed_script(text):
    """Ayni sozcukte Latin ile Yunan/Kiril/Ermeni/Ceroki harfleri birlikte mi? ('AKΒANK': B yerine Yunan
    Beta.) Turkce ya da Ingilizce mesru metinde gorulmez; kurum adini benzer harfle yazmak icin kullanilir."""
    for word in _WORD_RE.findall(text or ""):
        if word.isascii():
            continue
        latin = other = False
        for ch in word:
            if ch.isascii():
                latin = latin or ch.isalpha()
                continue
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                latin = True
            elif name.startswith(_LOOKALIKE_SCRIPTS):
                other = True
        if latin and other:
            return True
    return False


def _canonical_host(url):
    host = (url.host or "").lower()
    return host if _is_ip_literal(host) else (to_ascii_or_none(host) or host)


def _empty_features(current, opaque):
    parsed = urls.parse(current)
    return {
        "url": current, "host": _canonical_host(parsed) if parsed else "", "base_url": current,
        "title": None, "identity": [], "identity_all": [], "logos": [], "text": "", "text_all": "",
        "password_input": False, "card_input": False, "tckn_input": False, "sms_input": False, "fields": [],
        "external_form_hosts": [], "external_links": [], "prominent_external_link": False, "interactive": False,
        "follow_links": [], "exfil": None, "script_redirect": None, "script_redirect_host": None,
        "script_rendered": False, "hidden_chars": False, "styled": False, "refresh_delay": 0, "opaque": list(opaque),
        "frame_srcs": [], "srcdocs": [], "meta_charsets": [],
    }


def _raw_features(html, current):
    """Ayristirilamayan (sure siniri, derin ic ice, isci hatasi) belgenin HAM METNINDEN okunan kanit. Belge "tam
    incelendi" sayilmaz (`parser`), ancak ham metinde acikca duran kurum adi ve parola alani yok sayilmaz: aksi
    halde belgeyi ayristirilamaz kilmak, bilinen bir oltalama sayfasini "Karar verilemedi"ye indirmenin ucuz
    bir yolu olur."""
    import html as _html_mod

    features = _empty_features(current, ["parser"])
    head = html[:300_000]
    m = _RAW_TITLE_RE.search(head)
    title = re.sub(r"\s+", " ", _html_mod.unescape(m.group(1))).strip()[:160] if m else ""
    text = re.sub(r"\s+", " ", _html_mod.unescape(_RAW_TAG_RE.sub(" ", head))).strip()
    password = bool(_RAW_PASSWORD_RE.search(html))
    features.update({
        "title": title or None, "identity": [title] if title else [], "text": text[:20_000],
        "password_input": password, "fields": ["Şifre"] if password else [],
        "interactive": bool(_RAW_INPUT_RE.search(html)), "collects_input": bool(_RAW_INPUT_RE.search(html)),
        "raw_only": True,
    })
    return features


def _inspect_html(html, current, xml=False):
    """Tek bir HTML belgesini inceler. Doner: (ozellikler, yonlendirme hedefi veya None). Hedef hamdir;
    `ozellikler["base_url"]` ile (belgenin <base href> degeri dahil) cozulmelidir (E-03)."""
    facts = _extract(html, xml=xml, url=current)
    lowered = html.lower()
    if facts is None:
        # Ayristirici sure sinirini asti ya da coktu: sayfa "tam incelendi" sayilmaz
        return _raw_features(html, current), None

    doc = urls.parse(current)
    doc_host = _canonical_host(doc) if doc else ""
    # Belgenin taban adresi: ilk <base href> (E-03). Goreli adresler tarayicida buna gore cozulur.
    base = current
    if facts.get("base_href") is not None:
        candidate = urls.parse(facts["base_href"], current)
        if candidate and candidate.scheme in ("http", "https"):
            base = candidate.href

    from backend.core.brands import normalize_text

    raw_inputs = facts["inputs"]
    # Alan ipuclari da kurum adlari gibi benzer harfler eslendikten sonra aranir: 'Şіfre' (Kiril і) tarayicida
    # 'Şifre' ile ayni gorunur.
    inputs = [normalize_text(i) for i in raw_inputs]
    # Alan aciklamasi <label> icinde, girdiden hemen once (div, span, tablo hucresi) ya da CSS `content` ile
    # (::before) yazilabilir (A-04, E-10)
    labels = [_flatten(normalize_text(x)) for x in
              facts["labels"] + facts["captions"] + list(facts.get("css_text") or [])]
    has_text_input = facts["text_inputs"] > 0

    def labelled(hints):
        return has_text_input and any(h in lab for lab in labels for h in hints)

    # Parola maskesi <style> kuraliyla verilmis metin alani da parola alanidir
    password = any("password" in i.split(" ")[0] for i in raw_inputs) or _has(inputs, PASSWORD_HINTS) \
        or labelled(LABEL_PASSWORD_HINTS) or bool(facts.get("css_masked") and has_text_input)
    card = _has(inputs, CARD_HINTS) or labelled(LABEL_CARD_HINTS)
    tckn = _has(inputs, TCKN_HINTS) or labelled(LABEL_TCKN_HINTS)
    sms = _has(inputs, SMS_HINTS)
    phone = _has(inputs, PHONE_HINTS)

    # Form hedefi (E-03, E-17): bos 'action' belgenin kendi adresidir; dolu deger ve dugmelerin
    # 'formaction' degeri taban adrese gore cozulur.
    form_hosts = set()
    actions = [(a, False) for a in facts["form_actions"]] + [(a, True) for a in facts["formactions"]]
    for action, is_formaction in actions[:100]:
        action = action.strip()
        if not action:
            continue
        target = urls.parse(action, base)
        if target is None or target.scheme not in ("http", "https"):
            continue
        target_host = _canonical_host(target)
        if target_host and target_host != doc_host:
            form_hosts.add(target_host)
            _note_visit(target.href, soft=True)  # gorulen adres: engel listesi (G-11)

    visible_text = _visual(" ".join(facts["text_visible"]))
    css_text = " ".join(facts.get("css_text") or [])
    # Tespit, gizli sayilan metni ve CSS ile yazilan metni de kullanir (E-07): gizleme sezgisi yalnizca esikler
    # ve "yalnizca ad geciyor" indirimi icindir.
    all_text = _visual(" ".join(facts["text"]) + (" " + css_text if css_text else ""))
    # Gorunen oznitelik metni (G-06): girdi degeri, yer tutucu, dugme degeri, aria-label, alt. Tarayici bunlari
    # cizer; metin dugumu degildirler.
    attr_text = " ".join(facts.get("attr_text") or [])
    if attr_text:
        all_text = (all_text + " " + attr_text).strip()
    # Harf harf yazilmis sozcukler (G-06)
    spelled = _spelled_words(facts["text"])
    if spelled:
        all_text = (all_text + " " + " ".join(spelled)).strip()
    # CSS `content: attr(data-x)` ile cizilen oznitelik degerleri
    data_text = " ".join(facts.get("data_text") or [])
    if data_text:
        all_text = (all_text + " " + data_text).strip()

    # Baglantilar (<a>, <area>): eylem cagrisi tasiyan baglanti - site ici ya da dis - ve yem sayfasi imzasi
    # (kisa metin + en fazla birkac hedef) belirleyicidir (B-10, A-04, E-12).
    doc_reg = registrable_domain(doc_host) if doc_host else ""
    here = doc.without_fragment if doc else current
    external_links = []
    targets_seen = []
    cta_links = []
    other_links = []
    prominent = False
    for href, label, kind in facts["links"][:500]:
        target = urls.parse(href.strip(), base)
        if target is None or target.scheme not in ("http", "https") or not target.host:
            continue
        link_host = _canonical_host(target)
        address = target.without_fragment
        if address == here:
            continue  # sayfa ici baglanti
        if address not in targets_seen:
            targets_seen.append(address)
        external = registrable_domain(link_host) != doc_reg
        if external:
            external_links.append(link_host)
        call = any(w in _flatten(label) for w in _PROMINENT_LINK_WORDS)
        if call:
            prominent = True
            if address not in cta_links:
                cta_links.append(address)
                _note_visit(address, soft=True)  # gorulen adres: engel listesi (G-11)
        elif address not in other_links:
            other_links.append(address)
    external_hosts = {registrable_domain(h) for h in external_links}
    short = len(visible_text) <= LURE_MAX_TEXT
    lure_shape = short and bool(targets_seen) and (
        (external_hosts and len(external_hosts) <= LURE_MAX_EXTERNAL_HOSTS)
        or len(targets_seen) <= LURE_MAX_LINK_TARGETS)
    if lure_shape:
        prominent = True

    # Etkilesim ogesi (A-04): form, metin girdisi ya da dugme tasiyan sayfa "yalnizca ad geciyor" sayilamaz.
    # Uzun metinli sayfadaki tek arama kutusu (haber sitesi) bu kapsamda degildir.
    has_forms = bool(facts["form_actions"])
    interactive = bool(form_hosts) or facts["text_inputs"] >= 2 or \
        (bool(has_forms or facts["text_inputs"] or facts["buttons"]) and short)

    # Veri toplayan form: taninan bir alan adi / etiketi olmasa da kullanicinin yazdigini sunucuya gonderir.
    # Alan tanima sozcuk listesine dayanir ve etiket gorselle verilerek atlatilabilir; bu isaret skorlamada
    # "kimligi belirlenemeyen form" taban kararini alan TURUNDEN bagimsiz kilar.
    # GET formu da girileni sunucuya gonderir (sorgu dizgisinde): birden fazla metin alani tasiyan ya da tek alani
    # arama kutusu OLMAYAN form da veri toplar.
    words = {w for i in inputs for w in re.split(r"[^a-z0-9]+", i) if w}
    search_like = facts["text_inputs"] == 1 and bool(words & _SEARCH_WORDS)
    # Arama kutusu bir SITENIN parcasidir: baska icerigi ve baglantisi olmayan sayfadaki tek alan, adi 'q' olsa da
    # arama kutusu sayilmaz (kimlik no / musteri no isteyen ilk adim sayfasi boyle yazilabilir)
    search_like = search_like and (len(targets_seen) >= 3 or len(visible_text) > INTERSTITIAL_MAX_TEXT)
    # Yalnizca <select> tasiyan GET formu (dil / sehir secici) serbest metin toplamaz
    free_input = facts.get("free_inputs", facts["text_inputs"]) > 0
    collects_input = has_text_input and bool(
        facts.get("post_forms") or form_hosts or (has_forms and free_input and not search_like))

    # Betikle yonlendiren ara sayfa: hedef izlenmez, bildirilir (Z-09)
    script_redirect = script_redirect_host = None
    if len(visible_text) <= INTERSTITIAL_MAX_TEXT and not inputs:
        m = _SCRIPT_REDIRECT_RE.search(html[:200_000])
        if m:
            target = urls.parse((m.group(1) or m.group(2) or "").strip(), base)
            if target is not None and target.scheme in ("http", "https"):
                script_redirect = target.href[:300]
                script_redirect_host = _canonical_host(target) or None
                # Hedef indirilmez, ancak platformun GORDUGU bir adrestir: engel listesiyle karsilastirilir (G-11)
                _note_visit(target.href)

    # Yurutulebilir betik (A-02): JavaScript calistirilmadigi icin betik iceren HICBIR sayfa "tam
    # incelendi" sayilmaz; esik yoktur. Gorunur metni ve formu neredeyse olmayan sayfa ayrica bulgu
    # uretir (B-02). Gizli (display:none) metin ve gizli girdiler sayilmaz.
    has_script = bool(facts["exec_scripts"]) or facts["event_handlers"]
    script_rendered = has_script and len(visible_text) <= INTERSTITIAL_MAX_TEXT \
        and not inputs and not has_forms

    exfil = None
    if "api.telegram.org/bot" in lowered:
        exfil = "Telegram bot API"
    elif "discord.com/api/webhooks" in lowered or "discordapp.com/api/webhooks" in lowered:
        exfil = "Discord webhook"

    fields = []
    if password:
        fields.append("Şifre")
    if card:
        fields.append("Kart bilgisi")
    if tckn:
        fields.append("T.C. kimlik no")
    if sms:
        fields.append("SMS doğrulama kodu")
    if phone:
        fields.append("Telefon")

    from backend.core.brands import strip_invisible

    title = facts.get("title") or ""
    metas = [x for x in facts.get("meta_identity") or [] if x and x.strip()]
    raw_identity = [x for x in [title, facts.get("h1_visible") or ""] + metas if x and x.strip()][:20]
    raw_identity_all = [x for x in [title, facts.get("h1") or ""] + metas if x and x.strip()][:20]
    hidden_chars = any(_SPLIT_BY_INVISIBLE_RE.search(x) or _BIDI_CONTROL_RE.search(x) or _mixed_script(x)
                       for x in raw_identity_all) or bool(spelled)
    identity = [re.sub(r"\s+", " ", _visual(x)).strip() for x in raw_identity]
    identity_all = [re.sub(r"\s+", " ", _visual(x)).strip() for x in raw_identity_all] + spelled[:3]
    prominent_text = re.sub(r"\s+", " ", _visual(" ".join(facts.get("prominent") or []))).strip()[:2000]
    bait_text = any(b in _flatten(all_text[:6000]) for b in _BAIT_TEXT)

    delay, meta_next, slow_refresh = _first_refresh(facts.get("meta_refresh"))

    # --- Goremedigini bil (A-01, A-02, E-01..E-04): statik incelemenin goremedigi yapilar ---
    # Bu listede bir sey varsa sayfa "tam incelendi" sayilmaz; karar "Dusuk risk" olamaz.
    opaque = []
    if has_script:
        opaque.append("script")
    if xml:
        # XML belgesi tarayicinin XML ayristiricisiyla islenir: belge ici tanimlar (ENTITY, ATTLIST varsayilan
        # oznitelikleri), XSLT ve CSS bildirimleri ogelerin anlamini degistirir (E-04). XML turleri gercek
        # sitelerde cok nadirdir; bu turlerin tamami "tam incelendi" sayilmaz.
        opaque.append("xml_dtd" if _XML_INTERNAL_RE.search(lowered) else "xml")
        if facts.get("empty_frames"):
            opaque.append("frame")  # kaynak DTD'den gelebilir
    if slow_refresh:
        opaque.append("delayed_refresh")
    # Birden fazla gecerli refresh etiketi farkli hedef gosteriyorsa hangisinin gecerli olacagi tarayiciya gore
    # degisir (ilk etiket / daha kisa gecikmeli etiket): ilk etiket izlenir, sayfa "tam incelendi" sayilmaz.
    refresh_targets = {parsed[1] or "" for parsed in (_parse_refresh(c) for c in facts.get("meta_refresh") or []) if parsed}
    if len(refresh_targets) > 1:
        opaque.append("refresh_conflict")
    if facts.get("truncated_tree"):
        opaque.append("truncated")
    if not has_script:
        # Iki gorunum kurali: ham metinde parola alani / form / cerceve var, agacta hic yok
        frames_seen = bool(facts["frames"] or facts["srcdocs"])
        if (_RAW_PASSWORD_RE.search(html) and not facts["password_inputs"]) \
                or (_RAW_INPUT_RE.search(html) and not facts["all_inputs"]) \
                or (_RAW_FORM_RE.search(html) and not has_forms) \
                or (_RAW_FRAME_RE.search(html) and not frames_seen):
            opaque.append("parse_mismatch")

    # Bir duzey derinlik (E-12, G-09, G-12). Izleme karari sayfanin BICIMINE (uzunluk, baglanti sayisi) degil
    # KIMLIGINE baglidir: kimlik alanlarinda adresin sahibi olmayan bir katalog kurumu gecen ve kendisi hassas
    # bilgi istemeyen sayfanin baglantilari ve GET formlarinin hedefleri izlenir (eylem cagrisi tasiyanlar once,
    # sonra sayfanin sonundan basa dogru). Kimlik tasimayan sayfanin baglantilarina dokunulmaz; belirtec tasiyan
    # (durum degistirebilecek) baglanti hicbir durumda izlenmez.
    follow = []
    link_evidence_needed = False
    if not (password or card or tckn):
        from backend.core.brands import detect_brand_in_content

        try:
            # Kimlik baslikta olmak zorunda degildir: govdede / logo etiketinde kurum adi tasiyan yem sayfasi
            # da ayni kuraldan gecer (kurum tespiti `lure` isaretiyle govdeyi de arar).
            found = detect_brand_in_content({
                "final_host": doc_host, "url": current, "identity": identity, "identity_all": identity_all,
                "logos": facts["logos"], "text": visible_text[:20_000], "text_all": all_text[:20_000],
                "prominent_text": prominent_text, "bait_text": bait_text, "prominent_external_link": prominent,
                "interactive": interactive, "probe_for_links": True})
        except Exception:
            found = None
        # Haber sayfasi (uzun metin + cok sayida baglanti) kurum adini basliginda tasisa da site ici baglantilari
        # gezilmez (B-10, G-12).
        news_like = len(visible_text) > LURE_MAX_TEXT and len(targets_seen) > 10
        # Tuzak ifadesi tasiyan kisa yem sayfasinin baglantilari, kurum adi GORSELLE verilmis olsa da izlenir
        bait_lure = bait_text and prominent and short
        skipped_token = False
        if (found and not found.get("weak")) or bait_lure:
            candidates = list(cta_links) + list(reversed(other_links))
            if news_like:
                # Haber gorunumlu sayfada site ici baglantilar gezilmez; yalnizca az sayida DIS alan adina giden
                # baglantilar izlenir (haber sayfalari cok sayida farkli alan adina baglanir)
                few_external = 0 < len(external_hosts) <= LURE_MAX_EXTERNAL_HOSTS
                # Eylem cagrisi tasiyan baglanti ("Devam et", "Dogrula") site ici de olsa izlenir
                candidates = [a for a in candidates if a in cta_links
                              or (few_external and registrable_domain(_canonical_host(urls.parse(a))) != doc_reg)]
            for action in (facts.get("get_forms") or [])[:5]:
                target = urls.parse(action.strip(), base)
                if target is not None and target.scheme in ("http", "https"):
                    candidates.append(target.without_fragment)
            for address in candidates:
                if address != here and address not in follow:
                    if _state_changing_link(address):
                        skipped_token = True
                    else:
                        follow.append(address)
                if len(follow) >= MAX_FOLLOWED_LINKS:
                    break
            # Kimligi baslik disinda tasiyan (ya da yalnizca tuzak ifadesi tasiyan) yem sayfasinda belirleyici kanit
            # baglantinin gittigi sayfadir. O sayfa incelenemiyorsa (belirtecli baglanti izlenmez; indirme
            # basarisiz olabilir) sayfa "tam incelendi" sayilmaz.
            link_evidence_needed = bool(candidates) and not (found and found.get("zone") == "identity")
            if link_evidence_needed and skipped_token and not follow:
                opaque.append("unfollowed_link")
        else:
            link_evidence_needed = False
            # Neredeyse hic metni olmayan, gorsel + bir-uc baglantidan olusan sayfa: kurum adi ve cagri GORSELDE
            # olabilir. Baglantilar izlenmez (kimlik yok; G-12), ancak sayfa "tam incelendi" de sayilmaz.
            if (facts.get("images") and not has_forms and not raw_inputs and targets_seen
                    and len(targets_seen) <= LURE_MAX_LINK_TARGETS and len(visible_text) <= INTERSTITIAL_MAX_TEXT):
                opaque.append("visual_only")

    features = {
        "url": current,
        "host": doc_host,
        "base_url": base,
        "title": re.sub(r"\s+", " ", _visual(strip_invisible(title))).strip()[:160] or None,
        "identity": identity,
        "identity_all": identity_all if identity_all != identity else [],
        "logos": facts["logos"],
        "text": visible_text[:20_000],
        "text_all": all_text[:20_000] if all_text != visible_text else "",
        "password_input": password,
        "card_input": card,
        "tckn_input": tckn,
        "sms_input": sms,
        "fields": fields,
        "external_form_hosts": sorted(form_hosts),
        "external_links": sorted(set(external_links))[:20],
        "prominent_external_link": prominent,
        "interactive": interactive,
        "collects_input": collects_input,
        "prominent_chunks": [re.sub(r"\s+", " ", x).strip()[:120] for x in (facts.get("prominent") or [])[:60]],
        "stylesheet_urls": list(facts.get("stylesheet_urls") or []),
        "image_urls": list(facts.get("image_urls") or []),
        "follow_links": follow,
        "link_evidence_needed": link_evidence_needed,
        "prominent_text": prominent_text,
        "bait_text": bait_text,
        # Metnin ekrandaki sirasini degistiren yapi (G-04) ve sayfanin yonlendiren ilkesi (G-03)
        "reordered": bool(facts.get("reordered")),
        "referrer_policy": _referrer_policy(facts.get("referrer_policy")),
        "exfil": exfil,
        "script_redirect": script_redirect,
        "script_redirect_host": script_redirect_host,
        "script_rendered": script_rendered,
        "hidden_chars": hidden_chars,
        # Kurum kimligi metin olmadan gorsel ya da stil sayfasiyla verilebilir (E-07)
        "styled": bool(facts.get("stylesheets") or facts.get("style_elements") or facts.get("images")
                       or facts.get("hidden_hits")),
        "refresh_delay": delay if meta_next is not None else 0,
        "opaque": opaque,
        "frame_srcs": list(facts["frames"])[:20],
        "srcdocs": facts["srcdocs"][:MAX_FRAMES + 1],
        "meta_charsets": facts.get("meta_charsets") or [],
    }
    return features, meta_next


def _step_summary(features):
    """Yonlendirmeden ONCEKI (ya da gomulu) belgenin bulgulari: sonuca her zaman girer (D-01)."""
    step = dict(features)
    step["final_host"] = features["host"]
    step["text"] = features["text"][:5_000]
    step["text_all"] = (features.get("text_all") or "")[:5_000]
    for key in ("srcdocs", "meta_charsets", "follow_links", "stylesheet_urls", "image_urls"):
        step.pop(key, None)
    return step


def _hop_key(url):
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return None
    host = host if _is_ip_literal(host) else (to_ascii_or_none(host) or "")
    return _target_key(host) if host else None


# --- Ayni adrese ayni anda tek yoklama, sonucu paylasilir (single-flight; B-04, A-08) -----

_inflight_lock = threading.Lock()
_inflight: dict = {}


def _cached(url):
    """Onbellekteki gecerli sonuc (cached_at ile) ya da None. Basarisiz sonuclar kisa omurludur (A-09)."""
    entry = _cache.get(url)
    if not entry:
        return None
    ttl = entry[2] if len(entry) > 2 else CACHE_TTL_SECONDS
    if time.time() - entry[0] >= ttl:
        return None
    result = dict(entry[1])
    result["cached_at"] = datetime.fromtimestamp(entry[0], timezone.utc).isoformat(timespec="seconds")
    return result


def _probe_page_shared(url, resolved_ip=None):
    cached = _cached(url)
    if cached:
        return cached
    with _inflight_lock:
        entry = _inflight.get(url)
        leader = entry is None
        if leader:
            entry = _inflight[url] = [threading.Event(), 0]
        elif entry[1] >= MAX_SHARED_WAITERS:
            # Ayni adresi bekleyen yeterince istek var: yuva tutmadan vazgec (A-08). Aksi halde ayni
            # yavas adresi gonderen istemciler, hedef ve IP sinirlarina takilmadan butun yuvalari tutar.
            return {"status": "target_busy", "redirects": [url], "steps": []}
        else:
            entry[1] += 1
    if not leader:
        # Suren yoklamanin sonucu kisa bir sure beklenir; hedef kilitlenmez, yoklama yinelenmez
        entry[0].wait(timeout=min(page_budget(), SHARED_WAIT_SECONDS))
        with _inflight_lock:
            entry[1] = max(0, entry[1] - 1)
        return _cached(url) or {"status": "target_busy", "redirects": [url], "steps": []}
    try:
        return _probe_page(url, resolved_ip)
    finally:
        with _inflight_lock:
            _inflight.pop(url, None)
        entry[0].set()


class _Fetched:
    """Tek bir belgenin indirilmesi ve incelenmesinin sonucu."""

    __slots__ = ("response", "kind", "doc", "next", "delay", "refresh", "deceptive", "raw_next")

    def __init__(self, response, kind=None, doc=None, nxt=None, delay=0, refresh=False, deceptive=False,
                 raw_next=None):
        self.response = response
        self.kind = kind
        self.doc = doc
        self.next = nxt          # tarayicinin gidecegi MUTLAK adres (tarayici kurallariyla cozulmus) ya da None
        self.delay = delay
        self.refresh = refresh   # True: <meta refresh> / Refresh basligi; False: HTTP 3xx
        self.deceptive = deceptive
        self.raw_next = raw_next


# Engel listesiyle karsilastirilan adresler. Zincir adimlari ve cerceveler HER ZAMAN kaydedilir; form hedefleri ve
# eylem baglantilari ("yumusak" kayitlar) ayri ve kucuk bir payla sinirlidir. Onceki surumde tek bir 60 kayitlik
# liste vardi: 60 sahte form hedefi listeyi dolduruyor, engellenen cerceve adresi listeye giremiyordu.
MAX_VISITED = 200
MAX_SOFT_VISITS = 40


def _note_visit(url, soft=False):
    state = _probe_state.get()
    if state is None or not url or url in state["visited"]:
        return
    if soft:
        if state.get("soft_visits", 0) >= MAX_SOFT_VISITS:
            return
        state["soft_visits"] = state.get("soft_visits", 0) + 1
    if len(state["visited"]) < MAX_VISITED:
        state["visited"].append(url)


def _note_trick(base, raw, target):
    """Yonlendirme / cerceve adresi inceleme araclarini baska bir siteye yoneltecek bicimde yazilmis (E-03)."""
    state = _probe_state.get()
    if state is not None and len(state["tricks"]) < 10:
        state["tricks"].append({"value": (raw or "")[:160], "target": (target or "")[:300]})


def _reinspect_with_meta_charset(body, plan, doc, url, xml):
    """Belgenin kendi icindeki <meta charset> bildirimi (agactan okunur) on taramadan farkli bir kodlama
    gosteriyorsa tarayici belgeyi o kodlamayla yeniden ayristirir. Guvenilir tek bir kodlama ise ayni sey
    yapilir; degilse kapsam dusurulur (E-02)."""
    if plan.confident or not doc.get("meta_charsets"):
        return doc, None, False
    names = set()
    unknown = False
    chosen = None
    for label in doc["meta_charsets"][:5]:
        encoding, not_recognised = _meta_encoding(label)
        unknown = unknown or not_recognised
        if encoding is not None:
            names.add(encoding.name)
            chosen = chosen or encoding
    if not names - {plan.name}:
        return doc, None, unknown
    if len(names) == 1 and chosen.name in _TRUSTED_ENCODINGS and not unknown:
        redo, meta_next = _inspect_html(_Decoded(chosen, body, False, False).text, url, xml=xml)
        return redo, (meta_next,), False
    return doc, None, True


# Tarayici sayfanin stil sayfalarini ve gorsellerini de ister. Platform bunlari hic istemediginde (1) kurum adi ya da
# alan etiketi harici stil sayfasindaki `content` kuraliyla yazilabiliyor, (2) sunucu "gorsel istenmediyse tarayici
# degildir" diyerek yonlendirmenin hedefinde zararsiz sayfa verebiliyordu.
MAX_STYLESHEETS = 2
MAX_STYLESHEET_BYTES = 200_000
SUBRESOURCE_SECONDS = 2.5


def _load_subresources(doc, text, url, deadline, xml, refreshing=False):
    """Belgenin stil sayfalarini (form tasiyan sayfada) indirip belgeyle birlikte yeniden inceler; yonlendiren ara
    sayfanin ilk gorselini ister (icerigi kullanilmaz). Doner: (belge, (yeni yonlendirme hedefi,) | None)."""
    state = _probe_state.get()
    if state is None or state.get("in_subresource") or doc is None:
        return doc, None
    sheets = list(doc.get("stylesheet_urls") or [])[:MAX_STYLESHEETS]
    # Stil sayfasi, form tasiyan ya da kisa (giris / yem sayfasi boyutunda) belgede istenir: kurum adi ve alan etiketi
    # `content` kuraliyla yazilabilir. Uzun icerik sayfalarinda (haber, magaza) istenmez.
    if not (doc.get("collects_input") or doc.get("fields") or doc.get("interactive")
            or len(doc.get("text") or "") <= LURE_MAX_TEXT):
        sheets = []
    images = list(doc.get("image_urls") or [])[:1] if refreshing else []
    if not sheets and not images:
        return doc, None
    css_parts = []
    saved_nav = state.get("nav")
    state["in_subresource"] = True
    try:
        for dest, raw in [("style", s) for s in sheets] + [("image", i) for i in images]:
            target = urls.parse(raw, doc.get("base_url") or url)
            if target is None or target.scheme not in ("http", "https"):
                continue
            if deadline - time.monotonic() <= 1.5 or state.get("embedded_requests", 0) >= MAX_EMBEDDED_REQUESTS:
                break
            state["nav"] = _nav(url, target.href, dest=dest, policy=doc.get("referrer_policy"))
            # Alt kaynak sayfanin butcesini tuketemez: istek basina kisa, ayri bir sure; tarayici gibi en fazla iki
            # HTTP yonlendirmesi izlenir.
            response, address = None, target.href
            for _ in range(3):
                if state.get("embedded_requests", 0) >= MAX_EMBEDDED_REQUESTS:
                    response = None
                    break
                state["embedded_requests"] = state.get("embedded_requests", 0) + 1
                try:
                    response = _fetch_once(address, min(deadline, time.monotonic() + SUBRESOURCE_SECONDS))
                except Exception:
                    response = None
                    break
                location = (response.headers.get("location") or "").strip()
                if response.status_code in REDIRECT_CODES and location:
                    address = urls.resolve(address, location)
                    response = None
                    if not address or urls.parse(address).scheme not in ("http", "https"):
                        break
                    continue
                break
            if response is None:
                continue
            if dest == "style" and response.status_code == 200 and response.body:
                css_parts.append(_encoding_plan(response.body[:MAX_STYLESHEET_BYTES], None).text)
    finally:
        state["nav"] = saved_nav
        state["in_subresource"] = False
    if not css_parts:
        return doc, None
    # Stil metni belgeye <style> ogesi olarak eklenir ve belge yeniden incelenir; '<' atilir (HTML eklenemez)
    css = "\n".join(css_parts).replace("<", " ")
    redo, meta_next = _inspect_html(text + "<style>" + css + "</style>", url, xml=xml)
    return redo, (meta_next,)


def _fetch_document(url, deadline, pinned=None):
    """Tek belge: indir, turunu belirle, incele. Doner: _Fetched."""
    _note_visit(url)
    response = _fetch_once(url, deadline, pinned) if pinned else _fetch_once(url, deadline)
    if response.status_code in REDIRECT_CODES and (response.headers.get("location") or "").strip():
        raw = response.headers.get("location")
        target = urls.resolve(url, raw.strip()) if raw else None
        return _Fetched(response, nxt=target, deceptive=bool(target) and urls.is_deceptive(url, raw),
                        raw_next=raw)
    # HTTP 'Refresh' yanit basligi: tarayicilarin tamami izler (B-02)
    # <meta> ve HTTP basligi AYNI kuraldan gecer (G-02): hedefsiz deger ("Refresh: 1") belgenin kendisini yeniden
    # yukler. Onceki surumde hedefsiz baslik tumuyle yok sayiliyordu.
    header_value = response.headers.get("refresh", "")
    header_delay, header_target, header_slow = _first_refresh([header_value]) if header_value.strip() else (0, None, False)
    charset = _header_charset(response.headers)
    plan = _encoding_plan(response.body, charset)
    text = plan.text
    kind = _document_kind(response, text)
    if kind == "xml":
        plan = _encoding_plan(response.body, charset, xml=True)
        text = plan.text
    doc = meta_next = None
    if kind:
        doc, meta_next = _inspect_html(text, url, xml=(kind == "xml"))
        charset_opaque = plan.opaque
        doc, redo, late_opaque = _reinspect_with_meta_charset(plan.body, plan, doc, url, kind == "xml")
        if redo is not None:
            meta_next = redo[0]
        doc, redo = _load_subresources(doc, text, url, deadline, kind == "xml",
                                       refreshing=meta_next is not None or header_target is not None)
        if redo is not None:
            meta_next = redo[0]
        if charset_opaque or late_opaque:
            # Kodlama taninmadi ya da guvenilir bicimde cozulemedi: tarayici baska bir metin goruyor olabilir
            doc["opaque"].append("charset")
        if response.truncated:
            doc["opaque"].append("truncated")
        if header_slow:
            doc["opaque"].append("delayed_refresh")
        # Sayfanin yonlendiren ilkesi (G-03): <meta name=referrer> basliktan sonra islenir ve onu ezer
        doc["referrer_policy"] = doc.get("referrer_policy") or _referrer_policy(response.headers.get("referrer-policy"))
    if header_target is not None:
        raw, base, delay = header_target, url, header_delay
    elif meta_next is not None:
        # Hedefsiz refresh belgenin KENDI adresini yeniden yukler; goreli hedef taban adrese gore cozulur
        raw, base, delay = meta_next, (doc["base_url"] if meta_next else url), doc.get("refresh_delay", 0)
    else:
        return _Fetched(response, kind, doc)
    target = urls.resolve(base, raw.strip()) if raw else url
    if target is None or urls.parse(target).scheme not in ("http", "https"):
        # Cozumlenemeyen ya da http(s) disi hedef (javascript:, data:): izlenemez, kapsam duser
        if doc is not None:
            doc["opaque"].append("delayed_refresh")
        return _Fetched(response, kind, doc)
    return _Fetched(response, kind, doc, nxt=target, delay=delay, refresh=True,
                    deceptive=bool(raw) and urls.is_deceptive(base, raw), raw_next=raw)


def _fetch_embedded(url, deadline, nav):
    """Gomulu ya da baglantili belge: HTTP yonlendirmeleri izlenerek indirilir. Doner: (_Fetched | None, adres)."""
    state = _probe_state.get()
    fetched = None
    for _ in range(3):
        if deadline - time.monotonic() <= 0.3:
            return None, url
        if state is not None:
            # Bir analizin gomulu belge ve baglantilar icin gonderebilecegi istek sayisi sinirlidir (G-12)
            if state.get("embedded_requests", 0) >= MAX_EMBEDDED_REQUESTS:
                return None, url
            state["embedded_requests"] = state.get("embedded_requests", 0) + 1
            state["nav"] = nav
        fetched = _fetch_document(url, deadline)
        if fetched.response.status_code in REDIRECT_CODES and fetched.next:
            if fetched.deceptive:
                _note_trick(url, fetched.raw_next, fetched.next)
            url = fetched.next
            fetched = None
            continue
        break
    return fetched, url


def _inspect_frames(doc, current, deadline):
    """Gomulu belgeleri (iframe/frame/object/embed, srcdoc) indirip inceler (A-01). Tarayici bunlari sayfanin
    parcasi olarak gosterir. Doner: (cerceve ozetleri, incelenemeyen cerceve var mi)."""
    frames, opaque = [], False
    base = doc.get("base_url") or current
    policy = doc.get("referrer_policy")
    for srcdoc in doc.get("srcdocs", [])[:MAX_FRAMES]:
        try:
            fdoc, inner_next = _inspect_html(srcdoc[:MAX_BYTES], current)
        except Exception:
            opaque = True
            continue
        # srcdoc belgesinin taban adresi kapsayan belgeninkidir (kendi <base href> degeri yoksa)
        inner_base = fdoc["base_url"] if fdoc.get("base_url") and fdoc["base_url"] != current else base
        if fdoc["opaque"] or fdoc["srcdocs"]:
            opaque = True
        frames.append(_step_summary(fdoc))
        # srcdoc belgesinin gomdugu cerceveler ve yonlendirmesi `src` cercevesiyle AYNI kuraldan gecer (G-01):
        # onceki surumde yonlendirme hedefi atiliyor, sayfa "tam incelendi" sayiliyordu.
        inner_targets = []
        if inner_next is not None:
            target = urls.parse(inner_next.strip(), inner_base) if inner_next else None
            if target is None or target.scheme not in ("http", "https"):
                opaque = True
            else:
                inner_targets.append(target.href)
        for src in fdoc["frame_srcs"][:MAX_FRAMES]:
            if not src or src.lower().startswith("about:"):
                continue
            target = urls.parse(src, inner_base)
            if target is None or target.scheme not in ("http", "https"):
                opaque = True
            else:
                inner_targets.append(target.href)
        if len(fdoc["frame_srcs"]) > MAX_FRAMES:
            opaque = True
        for inner in inner_targets[:MAX_FRAMES]:
            _note_visit(inner)  # gorulen adres: engel listesi (G-11)
            try:
                fetched, _final = _fetch_embedded(inner, deadline, _nav(current, inner, dest="iframe", policy=policy))
            except Exception:
                fetched = None
            inner_doc = fetched.doc if fetched is not None else None
            if inner_doc is None:
                opaque = True
                continue
            if inner_doc["opaque"] or inner_doc["frame_srcs"] or inner_doc["srcdocs"] or fetched.next:
                opaque = True
                if fetched.next:
                    _note_visit(fetched.next)
            frames.append(_step_summary(inner_doc))
    srcs = [f for f in doc.get("frame_srcs", [])]
    if len(srcs) > MAX_FRAMES or len(doc.get("srcdocs", [])) > MAX_FRAMES:
        opaque = True
    # Cozumlenen butun cerceve adresleri kaydedilir (indirilmeyenler dahil): engel listesi denetimi (E-14)
    resolved = []
    for src in srcs:
        if not src or src.lower().startswith("about:"):
            resolved.append(None)
            continue
        target = urls.parse(src, base)
        if target is None:
            opaque = True
            resolved.append(None)
            continue
        if target.scheme not in ("http", "https"):
            opaque = True  # data:, blob:, javascript: … icerigi goremiyoruz
            resolved.append(None)
            continue
        _note_visit(target.href)
        if urls.is_deceptive(base, src):
            _note_trick(base, src, target.href)
        resolved.append(target.href)
    for furl in resolved[:MAX_FRAMES]:
        if not furl:
            continue
        try:
            fetched, furl = _fetch_embedded(furl, deadline, _nav(current, furl, dest="iframe", policy=policy))
        except Exception:
            fetched = None
        fdoc = fetched.doc if fetched is not None else None
        if fdoc is None:
            opaque = True
            continue
        # Ic ice cerceveler ve cercevenin kendi goremedikleri: tam inceleme degil
        if fdoc["opaque"] or fdoc["frame_srcs"] or fdoc["srcdocs"] or fetched.next:
            opaque = True
            # Cercevenin gittigi / gomdugu adresler indirilmez ama GORULMUSTUR: engel listesi (G-11)
            if fetched.next:
                _note_visit(fetched.next)
            for src in fdoc["frame_srcs"][:MAX_FRAMES]:
                inner = urls.parse(src, fdoc.get("base_url") or furl) if src else None
                if inner is not None and inner.scheme in ("http", "https"):
                    _note_visit(inner.href)
        frames.append(_step_summary(fdoc))
    return frames, opaque


def _inspect_links(doc, current, deadline):
    """Yem sayfasindaki eylem cagrisi baglantilarinin gittigi sayfalar (E-12): iki sayfali oltalama kitinde
    form, bildirim sayfasinin baglandigi ikinci sayfadadir. En fazla MAX_FOLLOWED_LINKS adres, ayni sure
    butcesi icinde indirilir; indirilemeyen baglanti kapsami dusurmez (yem sayfasi zaten belirleyicidir)."""
    linked = []
    for link in (doc.get("follow_links") or [])[:MAX_FOLLOWED_LINKS]:
        if deadline - time.monotonic() <= 1.0:
            break
        try:
            _note_visit(link)
            fetched, final = _fetch_embedded(link, deadline, _nav(current, link, user=True,
                                                                  policy=doc.get("referrer_policy")))
        except Exception:
            continue
        if fetched is None or fetched.doc is None:
            continue
        linked.append(_step_summary(fetched.doc))
    return linked


def _fingerprint(doc):
    """Belgenin yapisal ozeti: kendine yenileyen sayfanin ikinci yaniti ayni sayfa mi? (E-05) Gorunur metin
    bilincli olarak yoktur: haber sitelerinde metin her istekte degisir."""
    return (doc.get("title"), tuple(doc.get("identity") or []), tuple(doc.get("fields") or []),
            bool(doc.get("interactive")), len(doc.get("frame_srcs") or []), len(doc.get("srcdocs") or []),
            tuple(doc.get("external_form_hosts") or []), bool(doc.get("script_rendered")))


# Kendine yenileyen sayfa en fazla bu kadar kez yeniden istenir (E-05)
MAX_SELF_REFRESH = 3
# Baska adrese giden gecikmeli yonlendirmede beklenen en uzun sure
REFRESH_WAIT_SECONDS = 2.0
# Bu gecikmenin altindaki kendine yenileme, yanit degismese de izlenir (G-02)
QUICK_SELF_REFRESH_SECONDS = 10


def _probe_page(url, resolved_ip=None):
    cached = _cached(url)
    if cached:
        return cached

    chain = [url]
    # Yonlendiren ara sayfalarin incelemesi; hicbir adimin bulgusu atilmaz (D-01)
    steps = []
    current = url
    response = None
    doc = None
    budget = page_budget()
    deadline = time.monotonic() + budget
    # Zincir devam edecekse bir sonraki adima en az bu kadar sure kalmali (D-02)
    min_hop = min(MIN_HOP_SECONDS, budget / 3)
    hop_times = []
    ctx = current_probe_context()
    pinned = {}
    first = urls.parse(url)
    first_host = _canonical_host(first) if first else ""
    if not resolved_ip and ctx is not None:
        resolved_ip = ctx.pinned.get(first_host)
    if resolved_ip and first_host:
        pinned[first_host] = resolved_ip
    # Bir yoklamanin ortak durumu: cerez kabi, istek baglami (E-06), ziyaret edilen adresler (E-14)
    state = {"cookies": [], "reduced": budget < PAGE_BUDGET_SECONDS - 0.01, "nav": None, "visited": [], "tricks": [],
             "parse_spent": 0.0, "parse_strikes": 0, "embedded_requests": 0}
    token = _probe_state.set(state)
    max_delay = 0
    self_refreshes = 0
    last_fingerprint = None
    last_jar = None
    pre_refresh = None

    def _ips():
        return list(ctx.ips) if ctx is not None else []

    def failed(status):
        result = {"status": status, "redirects": chain, "steps": steps, "ips": _ips(),
                  "visited": list(state["visited"]), "url_tricks": list(state["tricks"])}
        # Kisa butceyle (istemci cezasi, yuk, kisitli IP) alinan basarisiz sonuc PAYLASILMAZ (A-09):
        # tam butceyle incelenebilecek bir sayfa icin herkese "incelenemedi" gosterilmemeli.
        if state["reduced"]:
            return result
        return _store(url, result, ttl=FAILURE_CACHE_TTL_SECONDS)

    try:
        try:
            for hop in range(MAX_REDIRECTS + 1):
                remaining = deadline - time.monotonic()
                if hop and remaining < min_hop:
                    # Zincir cok yavas: son hedef suclanmaz, sureyi tuketen onceki adim suclanir (D-02)
                    _blame_slow_hop(hop_times)
                    return failed("error")
                if remaining <= 0:
                    return failed("error")
                # Her yonlendirme adimi yeniden cozumlenir, denetlenir ve sabitlenir
                started = time.monotonic()
                fetched = _fetch_document(current, deadline, pinned if hop == 0 else None)
                response, doc = fetched.response, fetched.doc
                hop_times.append((current, time.monotonic() - started))
                target = fetched.next
                if not target:
                    break
                here = urls.parse(current)
                there = urls.parse(target)
                if doc is not None and here and there and there.without_fragment == here.without_fragment:
                    # Kendi kendini yenileyen sayfa (E-05). Haber siteleri boyle calisir; ayni yontem cerez
                    # sinamasi icin de kullanilir: ilk yanit "Yukleniyor" + Set-Cookie, cerezli ikinci istek
                    # oltalama sayfasi. Tarayici gibi, istek cerez kabiyla YINELENIR; ikinci yanit yapisal
                    # olarak ayniysa VE sunucu cerezleri degistirmediyse durulur, aksi halde zincir surer
                    # (sayacli cerez: ayni "Yukleniyor" sayfasi iki kez, ucuncu istekte asil sayfa).
                    fingerprint = _fingerprint(doc)
                    jar = json.dumps(state["cookies"], sort_keys=True)
                    # Kisa gecikmeli kendine yenileme "Yukleniyor" sayfalarina ozgudur (haber siteleri onlarca
                    # saniye kullanir). Sunucu cerez kullanmadan, istek SAYARAK ya da sure tutarak da asil sayfayi
                    # sonraya birakabilir (G-02): kisa gecikmede ikinci yanit ayni olsa da yenileme, gecikme kadar
                    # beklenerek MAX_SELF_REFRESH kez izlenir; sayfa hic degismezse "tam incelendi" sayilmaz.
                    quick = (fetched.delay or 0) <= QUICK_SELF_REFRESH_SECONDS
                    unchanged = last_fingerprint is not None and fingerprint == last_fingerprint and jar == last_jar
                    if unchanged and not quick:
                        pre_refresh = None  # ikinci yanit ayni sayfa: gercek "kendini yenileme"
                        # Yenileme gecikmesi (10-60 sn) BEKLENMEDI: sunucu asil sayfayi sure dolunca verebilir.
                        # Sayfa "tam incelendi" sayilmaz.
                        doc["opaque"].append("self_refresh")
                        break
                    if self_refreshes >= MAX_SELF_REFRESH:
                        doc["opaque"].append("self_refresh")
                        if unchanged:
                            pre_refresh = None
                        break
                    if last_fingerprint is not None and fingerprint == last_fingerprint:
                        pre_refresh = None  # ayni sayfa: adim olarak yinelenmez
                    if quick and self_refreshes:
                        pause = min(max(fetched.delay or 0, 0.2), 1.0, max(0.0, deadline - time.monotonic() - min_hop))
                        if pause > 0:
                            time.sleep(pause)
                    last_jar = jar
                    if pre_refresh is not None and len(steps) < MAX_INSPECTED_STEPS:
                        steps.append(pre_refresh)
                    pre_refresh = _step_summary(doc)
                    self_refreshes += 1
                    last_fingerprint = fingerprint
                    state["nav"] = _nav(current, target, policy=doc.get("referrer_policy"))
                    continue
                if pre_refresh is not None:
                    # Kendine yenilemeden ONCEKI (farkli) belge de sonuca girer
                    if (doc is None or _fingerprint(doc) != last_fingerprint) and len(steps) < MAX_INSPECTED_STEPS:
                        steps.append(pre_refresh)
                    pre_refresh, last_fingerprint = None, None
                if fetched.deceptive:
                    _note_trick(current, fetched.raw_next, target)
                max_delay = max(max_delay, fetched.delay or 0)
                if doc is not None and len(steps) < MAX_INSPECTED_STEPS:
                    steps.append(_step_summary(doc))
                if fetched.refresh:
                    state["nav"] = _nav(current, target, policy=(doc or {}).get("referrer_policy"))
                    # Gecikmeli yonlendirme tarayicidaki gibi BEKLENIR (kisa bir ust sinirla). Beklenmeyen kisim
                    # varsa zincir "tam incelendi" sayilmaz: sunucu, erken gelen istege zararsiz sayfa verebilir.
                    wanted = float(fetched.delay or 0)
                    if wanted > 0:
                        pause = max(0.0, min(wanted, REFRESH_WAIT_SECONDS, deadline - time.monotonic() - 2 * min_hop))
                        if pause > 0:
                            time.sleep(pause)
                        if wanted > pause + 0.05:
                            state["unwaited_refresh"] = True
                current = target
                chain.append(current)
            else:
                return failed("too_many_redirects")

            if response is None:
                return failed("error")
            if pre_refresh is not None and (doc is None or _fingerprint(doc) != last_fingerprint) \
                    and len(steps) < MAX_INSPECTED_STEPS:
                steps.append(pre_refresh)
        except BlockedAddressError:
            # Yonlendirme hedefi ic aga cozumlendi. Yanitta 'error'dan ayirt edilmez: aksi halde
            # yonlendirme zinciri ic agdaki adlari sinamak icin kullanilabilir (Z-07)
            logger.info("page probe redirect to non-public address blocked url=%r", url[:200])
            return failed("error")
        except PortNotAllowedError:
            return failed("port_not_allowed")
        except TargetBusyError:
            # Onbellege alinmaz: hedef bosaldiginda yeniden denenebilir
            return {"status": "target_busy", "redirects": chain, "steps": steps, "ips": _ips()}
        except SlowTargetError:
            return {"status": "slow_target", "redirects": chain, "steps": steps, "ips": _ips()}
        except (_FetchError, ValueError):
            return failed("error")

        final = urls.parse(current)
        final_host = _canonical_host(final) if final else ""
        result = {
            "status": "ok",
            "http_status": response.status_code,
            "final_url": current,
            "final_host": final_host,
            "redirects": chain,
            "steps": steps,
            "ips": _ips(),
            "content_type": _media_type(response.headers) or None,
            "redirect_delay": max_delay,
            "truncated": bool(response.truncated),
        }
        if doc is None:
            # HTML olarak islenmeyen yanit: incelenmedigi acikca bildirilir (B-01, B-10)
            result.update({"title": None, "identity": [], "text": "", "fields": [], "opaque": [], "frames": [],
                           "visited": list(state["visited"]), "url_tricks": list(state["tricks"])})
            download = _download_info(response, current)
            if download:
                result.update({"status": "download", "download": download})
            elif not (response.body or b"").strip():
                result["status"] = "empty"
            else:
                result["status"] = "not_html"
            return _store(url, result)

        # Gomulu belgeler sayfanin parcasidir (A-01)
        frames, frames_opaque = [], False
        if doc.get("frame_srcs") or doc.get("srcdocs"):
            try:
                frames, frames_opaque = _inspect_frames(doc, current, deadline)
            except Exception:
                frames_opaque = True
        # Yem sayfasinin baglandigi sayfalar (E-12)
        linked = []
        if doc.get("follow_links"):
            try:
                linked = _inspect_links(doc, current, deadline)
            except Exception:
                linked = []
            if doc.get("link_evidence_needed") and len(linked) < len(doc["follow_links"][:MAX_FOLLOWED_LINKS]):
                doc["opaque"].append("unfollowed_link")
        features = dict(doc)
        for key in ("url", "host", "srcdocs", "meta_charsets", "follow_links", "stylesheet_urls", "image_urls"):
            features.pop(key, None)
        opaque = list(features.pop("opaque", []))
        if frames_opaque:
            opaque.append("frame")
        if state.get("unwaited_refresh"):
            opaque.append("delayed_refresh")
        result.update(features)
        result["frames"] = frames
        result["linked"] = linked
        # Baglantinin gittigi sayfa hassas bilgi istiyorsa yem sayfasi belirleyicidir (G-09)
        result["linked_sensitive"] = any(
            [f for f in (item.get("fields") or []) if f != "Telefon"] or item.get("collects_input") for item in linked)
        result["opaque"] = sorted(set(opaque))
        result["ips"] = _ips()
        result["visited"] = list(state["visited"])
        result["url_tricks"] = list(state["tricks"])
        if not features.get("title") and not features.get("text") and not features.get("fields") \
                and not features.get("script_rendered") and not frames and not opaque \
                and not (response.body or b"").strip():
            result["status"] = "empty"
        return _store(url, result)
    finally:
        _probe_state.reset(token)


def _blame_slow_hop(hop_times):
    """Zincirin butcesi bittiyse sureyi tuketen adimin hedefi zaman asimi sayilir (D-02)."""
    if not hop_times:
        return
    slow_url, spent = max(hop_times, key=lambda h: h[1])
    if spent < MIN_HOP_SECONDS:
        return
    key = _hop_key(slow_url)
    ctx = current_probe_context()
    if ctx:
        ctx.record_timeout(key or "?")
    if key:
        try:
            parts = urlsplit(slow_url)
            host = parts.hostname or ""
            host = host if _is_ip_literal(host) else (to_ascii_or_none(host) or host)
            scope = _scope_key(host, parts.path)
        except ValueError:
            host, scope = "", None
        targets.record_timeout(key, client=ctx.client if ctx else None, protected=is_protected_target(host),
                               scope=scope)


def _store(key, value, ttl=None):
    _cache[key] = (time.time(), value) if ttl is None else (time.time(), value, ttl)
    return dict(value)
