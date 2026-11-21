import contextvars
import ipaddress
import logging
import re
import unicodedata
from functools import lru_cache
from urllib.parse import quote, unquote, urlparse, urlsplit

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session
from backend.core.domain_intel import lookup_domain_registration, resolve_ip, probe_tls
from backend.core.hostnames import InvalidHostError, to_ascii, to_ascii_or_none
from backend.core.netguard import BlockedAddressError, current_probe_context, resolve_all_public
from backend.core.suffixes import is_known_tld
from backend.core.reputation import check_ip_reputation, check_url_reputation
from backend.core.scoring import collect_signals, score_signals
from backend.core.page_probe import probe_page
from backend.models.list_model import ListModel


logger = logging.getLogger("mihenk.analyze")


class InvalidTargetError(ValueError):
    """Girdi analiz edilemez: gecersiz/belirsiz URL veya ic ag adresi. Mesaj istemciye gosterilir."""


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOST_PORT_RE = re.compile(r"^[^:/?#]+:\d+(?:[/?#]|$)")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f-\x9f]")
# WHATWG URL standardinda alan adinda yasak karakterler (yuzde kod cozuldukten sonra)
_FORBIDDEN_HOST_CHARS = set(" #%/:<>?@[\\]^|\t\r\n\x00")
_DOT_VARIANTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
MAX_HOST_LENGTH = 253
# Gorunen (Unicode) adresin en fazla karakter sayisi; analizden ONCE denetlenir (Y-09)
MAX_URL_LENGTH = 2048
# Kanonik adres yuzde kodlu ASCII'dir (Z-02); 2.048 karakterlik Unicode adres kodlandiginda en
# fazla ~24 KB olur. Kayit sutunu sinirsiz metin, dizin ise degerin SHA-256 ozeti uzerindedir.
MAX_URL_BYTES = 32 * 1024
# Tarayicilarin (WHATWG URL) yuzde kodladigi karakterler disindaki yazdirilabilir ASCII
_ASCII_PRINTABLE = "".join(chr(c) for c in range(0x21, 0x7f))
_PATH_SAFE = "".join(c for c in _ASCII_PRINTABLE if c not in '"#<>?`{}')
_QUERY_SAFE = "".join(c for c in _ASCII_PRINTABLE if c not in "\"#<>'")
_FRAGMENT_SAFE = "".join(c for c in _ASCII_PRINTABLE if c not in '"<>`')
# WHATWG "userinfo percent-encode set" disindaki yazdirilabilir ASCII
_USERINFO_SAFE = "".join(c for c in _ASCII_PRINTABLE if c not in '"#<>?`{}/:;=@[\\]^|')
_DOT_SEGMENTS = {".", "%2e"}
_DOUBLE_DOT_SEGMENTS = {"..", ".%2e", "%2e.", "%2e%2e"}
_UNRESERVED_ESCAPE = re.compile(r"%(2[dDeE]|3[0-9]|[46][1-9a-fA-F]|[57][0-9aA]|5[fF]|7[eE])")
REGISTRAR_MAX_LENGTH = 255
# Sayfa icerigi yalnizca standart web portlarindan indirilir (Y-09)
PAGE_PORTS = (None, 80, 443)


def _whatwg_ipv4(host):
    """WHATWG IPv4 ayristiricisi: '2130706433', '0x7f.1', '0177.0.0.1' gibi bicimleri tarayicinin
    yaptigi gibi noktali IPv4'e cevirir. IPv4 degilse None, gecersiz IPv4 ise InvalidTargetError."""
    parts = host.split(".")
    if parts and parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    last = parts[-1] if parts else ""
    if not re.fullmatch(r"(0[xX][0-9A-Fa-f]*|\d+)", last):
        return None
    if len(parts) > 4:
        raise InvalidTargetError("Geçersiz IPv4 adresi.")
    numbers = []
    for part in parts:
        if re.fullmatch(r"0[xX][0-9A-Fa-f]*", part):
            value = int(part[2:] or "0", 16)
        elif re.fullmatch(r"0[0-7]+", part):
            value = int(part, 8)
        elif re.fullmatch(r"\d+", part):
            value = int(part, 10)
        else:
            raise InvalidTargetError("Geçersiz IPv4 adresi.")
        numbers.append(value)
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise InvalidTargetError("Geçersiz IPv4 adresi.")
    ipv4 = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        ipv4 += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(ipv4))


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(address):
    if address.ipv4_mapped:
        return str(address.ipv4_mapped)
    if address.sixtofour:
        return str(address.sixtofour)
    if address in _NAT64:
        return str(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    return None


def _canonical_host(raw_host):
    host = unquote(raw_host)
    if not host:
        raise InvalidTargetError("Adreste alan adı bulunamadı.")
    if host.startswith("[") and host.endswith("]"):
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise InvalidTargetError("Geçersiz IPv6 adresi.")
        # IPv4 eslemeli / gomulu IPv6 yazimi (::ffff:a.b.c.d, 6to4, NAT64) ayni IPv4 sunucusuna
        # baglanir: kanonik bicim gomulu IPv4 adresidir (B-09). Liste kurallari ve tum denetimler bu
        # degeri kullanir.
        embedded = _embedded_ipv4(address)
        if embedded:
            return embedded, False
        return str(address), True
    host = unicodedata.normalize("NFKC", host.translate(_DOT_VARIANTS)).lower()
    if any(c in _FORBIDDEN_HOST_CHARS for c in host) or _CONTROL_OR_SPACE.search(host):
        raise InvalidTargetError("Alan adı geçersiz karakter içeriyor.")
    ipv4 = _whatwg_ipv4(host)
    if ipv4:
        return ipv4, False
    host = host.rstrip(".")
    if not host or ".." in host:
        raise InvalidTargetError("Alan adı geçersiz.")
    # Tek kanonik bicim: tarayicilarla ayni kurallarla (UTS-46, gecissiz) ASCII/Punycode.
    # Sonraki tum adimlar (liste, sahiplik, DNS, TLS, sayfa, kayit) yalnizca bu degeri kullanir.
    try:
        host = to_ascii(host)
    except InvalidHostError:
        raise InvalidTargetError("Alan adı geçersiz (uluslararası alan adı ASCII biçimine çevrilemedi).")
    if len(host) > MAX_HOST_LENGTH or any(c in _FORBIDDEN_HOST_CHARS for c in host):
        raise InvalidTargetError("Alan adı geçersiz.")
    return host, False


def parse_url_components(raw: str):
    """Ham girdiyi tek ve kanonik bicime getirir (bkz. _parse_url_components). Saldirganin denetimindeki
    hicbir deger bu islevden InvalidTargetError disinda bir istisna firlatamaz (Z-02, E-15): beklenmeyen
    her hata "adres ayristirilamadi" (HTTP 400) olur, sunucu hatasi (HTTP 500) degil."""
    try:
        return _parse_url_components(raw)
    except InvalidTargetError:
        raise
    except Exception as exc:
        logger.warning("url parsing failed unexpectedly error=%s input=%r", type(exc).__name__, (raw or "")[:200])
        raise InvalidTargetError("Adres ayrıştırılamadı.") from exc


def _parse_url_components(raw: str):
    """Ham girdiyi tek ve kanonik bicime getirir; analiz, kayit ve sayfa indirme yalnizca
    bu degeri kullanir. Tarayicilarin (WHATWG URL standardi) davranisi esas alinir:
    ters egik cizgi yol ayiricidir, 'http:ornek.com' gecerli bir adrestir, alan adindaki
    yuzde kodlari cozulur, sayisal IPv4 bicimleri noktali bicime cevrilir.
    Belirsiz veya http/https disi girdiler InvalidTargetError ile reddedilir.
    Sema yazilmamissa 'scheme' None doner; hangi semanin kullanilacagi TLS yoklamasindan sonra belirlenir."""
    text = (raw or "").strip()
    if not text:
        raise InvalidTargetError("URL boş olamaz.")
    # Tarayici (WHATWG URL) adresteki sekme ve satir sonlarini atar: 'ht\ttp://...' gecerli bir
    # adrestir. Reddetmek yerine atilir ve "adres gizleme" bulgusu uretilir (B-11).
    stripped = re.sub(r"[\t\n\r]", "", text)
    stripped_whitespace = stripped != text
    text = stripped
    if not text:
        raise InvalidTargetError("URL boş olamaz.")
    if _CONTROL_OR_SPACE.search(text):
        raise InvalidTargetError("Adres boşluk veya kontrol karakteri içeremez.")
    # Tarayicilar http/https adreslerinde '\\' karakterini '/' olarak yorumlar
    text = text.replace("\\", "/")

    scheme = None
    match = _SCHEME_RE.match(text)
    if match and match.group(1).lower() in ("http", "https"):
        scheme = match.group(1).lower()
        remainder = text[match.end():].lstrip("/")
    elif match and not _HOST_PORT_RE.match(text):
        raise InvalidTargetError("Yalnızca http ve https adresleri analiz edilebilir.")
    else:
        remainder = text.lstrip("/")

    try:
        parts = urlsplit(f"{scheme or 'http'}://{remainder}")
        port = parts.port
    except ValueError:
        raise InvalidTargetError("Adres ayrıştırılamadı (geçersiz port veya köşeli parantez).")

    netloc = parts.netloc
    userinfo, has_userinfo, hostport = "", "@" in netloc, netloc
    if has_userinfo:
        userinfo, _, hostport = netloc.rpartition("@")
        # Kullanici bilgisi tarayicinin yaptigi gibi yuzde kodlanir (E-15): ASCII disi karakter tasiyan deger
        # kanonik adresi ASCII olmaktan cikariyor ve analiz HTTP 500 ile sonuclaniyordu.
        user, colon, password = userinfo.partition(":")
        userinfo = quote(user, safe=_USERINFO_SAFE + "%") + colon + quote(password, safe=_USERINFO_SAFE + "%")
    if hostport.startswith("["):
        raw_host = hostport[: hostport.find("]") + 1]
    else:
        raw_host = hostport.rsplit(":", 1)[0] if ":" in hostport else hostport
    host, is_v6 = _canonical_host(raw_host)

    host_part = f"[{host}]" if is_v6 else host
    authority = (f"{userinfo}@" if has_userinfo else "") + host_part + (f":{port}" if port is not None else "")
    # Yol tarayicilarin yaptigi gibi sadelestirilir ('.', '..') ve ASCII'ye yuzde kodlanir
    # (Z-02, Z-06): liste eslestirme, sayfa indirme ve kayit tarayicinin acacagi adresi kullanir.
    path = _normalize_path(parts.path)
    query = quote(parts.query, safe=_QUERY_SAFE + "%") if parts.query else ""
    fragment = quote(parts.fragment, safe=_FRAGMENT_SAFE + "%") if parts.fragment else ""
    rest = path
    if query:
        rest += "?" + query
    if fragment:
        rest += "#" + fragment

    result = {
        "raw": text,
        "scheme": scheme,
        "domain": host,
        "port": port,
        "authority": authority,
        "userinfo": has_userinfo,
        "rest": rest,
        "path": path,
        "query": query,
        "fragment": fragment,
        "stripped_whitespace": stripped_whitespace,
    }
    # Uzunluk analizden ONCE denetlenir (Y-09): gorunen adres karakter, kanonik adres bayt
    # cinsinden (Z-02). Kanonik adres ASCII oldugu icin karakter sayisi bayt sayisina esittir.
    canonical = normalized_url(result, "https")
    if len(unquote(canonical)) > MAX_URL_LENGTH:
        raise InvalidTargetError(f"Adres çok uzun (en fazla {MAX_URL_LENGTH} karakter).")
    if len(canonical.encode("ascii")) > MAX_URL_BYTES:
        raise InvalidTargetError("Adres çok uzun.")
    return result


def _normalize_path(path: str) -> str:
    """RFC 3986 / WHATWG yol sadelestirmesi: '.' ve '..' parcalari (yuzde kodlu bicimleri dahil)
    kaldirilir, ASCII disi ve tarayicinin kodladigi karakterler yuzde kodlanir."""
    if not path:
        return ""
    encoded = quote(path, safe=_PATH_SAFE + "%")
    segments = encoded.split("/")[1:]
    out = []
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        low = seg.lower()
        if low in _DOUBLE_DOT_SEGMENTS:
            if out:
                out.pop()
            if last:
                out.append("")
        elif low in _DOT_SEGMENTS:
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def normalized_url(parsed, scheme):
    return f"{scheme}://{parsed['authority']}{parsed['rest']}"


def extract_host(value: str) -> str:
    """google.com, www.google.com, https://www.google.com/x?y -> google.com

    Alan adi analiz hattiyla ayni kurallarla (UTS-46, gecissiz) ASCII'ye cevrilir; boylece
    'sunexpreß.com' bir 'sunexpress.com' kuralini devralamaz (Y-06). Cevrilemeyen deger
    hicbir kuralla eslesmez (bos doner)."""
    v = (value or "").strip()
    if "://" not in v:
        v = "http://" + v
    try:
        host = (urlparse(v).hostname or "").rstrip(".")
    except ValueError:
        return ""
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    host = to_ascii_or_none(host) or ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _canonical_ip(value: str):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 6:
        embedded = _embedded_ipv4(ip)
        if embedded:
            return embedded
    return str(ip)


def host_matches(host: str, pattern_host: str) -> bool:
    if not host or not pattern_host:
        return False
    # IP ise sadece birebir eslesme; IPv4 eslemeli IPv6 yazimi gomulu IPv4 ile karsilastirilir (B-09)
    host_ip = _canonical_ip(host)
    if host_ip is not None:
        return host_ip == _canonical_ip(pattern_host)
    return host == pattern_host or host.endswith("." + pattern_host)


def _decode_unreserved(segment: str) -> str:
    """Ayrilmamis karakterlerin yuzde kodlarini cozer ('%67iris' -> 'giris'); '/' gibi
    anlamli karakterlerin kodlari korunur (RFC 3986 6.2.2.2)."""
    return _UNRESERVED_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), segment)


def _url_key(value: str):
    """Adres kurali karsilastirmasi icin bilesenler (Z-06): metin oneki yerine alan adi,
    port, sadelestirilmis yol parcalari ve sorgu ayri ayri karsilastirilir."""
    return _url_key_from_parsed(parse_url_components(value))


def _url_key_from_parsed(parsed):
    """Ayristirilmis bilesenlerden kural anahtari (D-05). Metin yeniden ayristirilmaz: adresteki
    kullanici bilgisi ('a:b@') sema sanilip kural denetimini atlatamaz."""
    host = parsed["domain"]
    if host.startswith("www."):
        host = host[4:]
    port = parsed["port"] if parsed["port"] not in (80, 443) else None
    segments = [_decode_unreserved(s) for s in parsed["path"].split("/")[1:]] if parsed["path"] else []
    return host, port, segments, parsed["query"]


def _url_rule_matches(url_key, rule_key, list_type: str) -> bool:
    host, port, segments, query = url_key
    r_host, r_port, r_segments, r_query = rule_key
    if host != r_host or port != r_port:
        return False
    if list_type == "blacklist":
        # Engel kurali genis yorumlanir: bos parcalar ('//'), harf buyuklugu, sorgu ve parca
        # yok sayilir; bilinen oltalama adresi sonuna karakter eklenerek listeden cikamaz.
        segments = [s.lower() for s in segments if s]
        r_segments = [s.lower() for s in r_segments if s]
        return segments[:len(r_segments)] == r_segments
    # Izin kurali dar yorumlanir: sadelestirilmis yol, harf buyuklugu korunarak, parca parca
    # onek olmali; kuralda sorgu varsa birebir ayni olmali.
    while r_segments and r_segments[-1] == "":
        r_segments = r_segments[:-1]
    if segments[:len(r_segments)] != r_segments:
        return False
    return not r_query or r_query == query


@lru_cache(maxsize=4096)
def _rule_key(entry_type: str, pattern: str):
    """Kayitli kurali bugunku dogrulamadan gecirir (Z-05). Gecersiz kural (onceki surumlerde
    kaydedilmis 'com.tr', 'www.com.tr' gibi) devre disidir: None doner ve kayda yazilir."""
    from backend.core.list_rules import InvalidPatternError, canonical_pattern

    try:
        canonical = canonical_pattern(entry_type, pattern)
    except InvalidPatternError as exc:
        logger.warning("list rule disabled (invalid pattern) type=%s pattern=%r reason=%s", entry_type, pattern, exc)
        return None
    if entry_type == "url":
        try:
            return _url_key(canonical)
        except InvalidTargetError:
            return None
    return canonical


def check_list_match(db: Session, domain: str, raw_url: str, list_type: str, parsed=None, entries=None):
    """Kurallar host uzerinden eslesir; 'evil.com/google.com' gibi adresler
    'google.com' kuralina takilmaz. Tam URL kurallari bilesen bilesen karsilastirilir (Z-06).
    Kurallar eslestirmeden once yeniden dogrulanir; gecersiz kural uygulanmaz (Z-05).
    `parsed` verilirse adres kurali anahtari dogrudan bilesenlerden uretilir (D-05)."""
    if not db:
        return None
    from backend.core.brands import user_content_boundary

    host = extract_host(domain) or extract_host(raw_url)
    try:
        url_key = _url_key_from_parsed(parsed) if parsed else _url_key(raw_url)
    except InvalidTargetError:
        url_key = None
        if "@" in raw_url:
            # Kullanici bilgisi metinden ayiklanip yeniden denenir; ayristirma hatasi sessizce
            # "eslesme yok" sayilmaz (D-05)
            try:
                authority, sep, rest = raw_url.partition("/")
                url_key = _url_key(authority.rpartition("@")[2] + sep + rest)
            except InvalidTargetError:
                url_key = None
        if url_key is None:
            logger.warning("list check: url could not be parsed; url rules not applied list=%s url=%r",
                           list_type, raw_url[:200])
    # Kullanici icerigi sunan adreste (sites.google.com, x.blogspot.com) ust alan adina yazilmis
    # izin kurali icerigi yayimlayan kisiye guven vermez; yalnizca o sinirdaki veya altindaki kural gecerlidir
    boundary = user_content_boundary(host) if list_type == "whitelist" else None
    if entries is None:
        entries = db.query(ListModel).filter(ListModel.list_type == list_type).all()
    for entry in entries:
        key = _rule_key(entry.entry_type, entry.pattern)
        if key is None:
            continue
        if entry.entry_type == "url":
            if url_key and _url_rule_matches(url_key, key, list_type):
                return entry
        elif host_matches(host, key):
            if boundary and not host_matches(key, boundary):
                continue
            return entry
    return None


def check_ip_rules(db: Session, ips, list_type: str = "blacklist"):
    """'ip' turundeki kurallari alan adinin CoZuMLENDIGI adreslere uygular (B-09): bir oltalama
    sunucusunun IP'sini engelleyen kural, o sunucudaki alan adlarini ve yonlendirme zincirindeki
    her adimi da kapsar."""
    if not db:
        return None
    candidates = [c for c in (_canonical_ip(ip) for ip in ips or [] if ip) if c]
    if not candidates:
        return None
    entries = (db.query(ListModel)
               .filter(ListModel.list_type == list_type, ListModel.entry_type == "ip").all())
    for entry in entries:
        key = _rule_key(entry.entry_type, entry.pattern)
        if key is None:
            continue
        if any(host_matches(ip, key) for ip in candidates):
            return entry
    return None


def _blacklisted_step(db: Session, page: dict, first_url: str):
    """Yoklamanin ziyaret ettigi adreslerden (yonlendirme adimlari, son adres, cerceveler, izlenen baglantilar)
    engel listesindeki bir 'domain' ya da 'url' kuraliyla eslesen ilki: (kural, adres) ya da None (E-14)."""
    seen = set()
    # Kurallar istek basina BIR kez okunur (G-13); her adim icin ayri sorgu yapilmaz
    entries = db.query(ListModel).filter(ListModel.list_type == "blacklist").all()
    if not entries:
        return None
    candidates = list(page.get("visited") or []) + list(page.get("redirects") or [])
    if page.get("final_url"):
        candidates.append(page["final_url"])
    for step in candidates[:80]:
        if not isinstance(step, str) or step in seen or step == first_url:
            continue
        seen.add(step)
        try:
            step_parsed = parse_url_components(step)
        except InvalidTargetError:
            continue
        entry = check_list_match(db, step_parsed["domain"], step_parsed["authority"] + step_parsed["rest"],
                                 "blacklist", parsed=step_parsed, entries=entries)
        if entry is not None:
            return entry, step
    return None


def _list_result(kind, entry, parsed, url, resolved_note=""):
    note = f" ({entry.description})" if entry.description else ""
    if kind == "blacklist":
        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "reasons": [{
                "rule_name": "Engel listesi eşleşmesi",
                "description": f"Gösterge analist engel listesindeki '{entry.pattern}' kuralıyla eşleşti"
                               f"{resolved_note}{note}.",
                "severity": "critical",
                "contribution": 100,
            }],
            "ioc_details": dict(_empty_ioc(parsed["domain"], url, parsed["scheme"] != "http", "blacklisted"),
                                inspection_coverage="list"),
            "mitre_techniques": [],
            "related_domains": [],
        }
    raise ValueError(kind)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _empty_ioc(domain, url, has_https, status):
    """Liste eslesmesinde harici kaynaklar sorgulanmaz; degerler uydurulmaz."""
    return {
        "domain": domain,
        "registrar": None,
        "domain_age_days": None,
        "domain_registration_date": None,
        "ip_address": None,
        "abuse_score": None,
        "ip_reports_count": None,
        "abuse_status": status,
        "url": url,
        "vt_positives": None,
        "vt_total": None,
        "vt_status": status,
        "has_https": has_https,
        "tls_status": None,
    }


def require_internet_name(domain: str) -> None:
    """Tek etiketli adlar ('db', 'vault', 'localhost') ve IANA kok bolgesinde olmayan uzantilar
    ('.local', '.internal', '.corp', '.example') internette yoktur; cozumlenmeden ONCE ayni genel
    iletiyle reddedilir. Boylece yanit, adin ic agda tanimli olup olmadigini aciga cikarmaz (Z-07).
    IP adresleri bu denetime tabi degildir (ic ag denetimi resolve_public'tedir)."""
    if _is_ip_literal(domain):
        return
    if "." not in domain or not is_known_tld(domain.rsplit(".", 1)[-1]):
        raise InvalidTargetError("Alan adı geçersiz.")


def _in_context(fn):
    """Cagiranin contextvars baglamini (ProbeContext) havuz is parcacigina tasir. Her gorev
    kendi kopyasini kullanir: ayni Context nesnesi iki is parcaciginda ayni anda calistirilamaz."""
    ctx = contextvars.copy_context()

    def run(*args, **kwargs):
        return ctx.run(fn, *args, **kwargs)

    return run


def inspection_coverage(page: dict) -> str:
    """Inceleme kapsami (B-01, B-02; rapor 7.1): 'full' sayfa icerigi incelendi, 'partial' sayfaya
    ulasildi ama icerik tam incelenemedi (betikle uretilen, HTML olmayan, bos, dosya), 'none'
    icerik hic indirilemedi. Kapsam tam degilken "Dusuk risk" yerine "Karar verilemedi" gosterilir."""
    status = (page or {}).get("status")
    if status == "ok":
        # Statik ayristiricinin goremedigi herhangi bir yapi (betik, gomulu belge, kesilen govde, XML
        # tanimlari, izlenmeyen yonlendirme) varsa inceleme tam degildir (A-01, A-02)
        if page.get("script_rendered") or page.get("opaque") or page.get("truncated"):
            return "partial"
        return "full"
    if status in ("not_html", "empty", "download"):
        return "partial"
    return "none"


def analyze_url_pipeline(raw_url: str, db: Session = None) -> dict:
    parsed = parse_url_components(raw_url)
    domain = parsed["domain"]
    require_internet_name(domain)

    # Liste kontrolleri sema bilinmeden de yapilabilir. URL kurallari ham girdiyle degil,
    # kanonik (ASCII alan adli) adresle karsilastirilir.
    list_url = parsed["authority"] + parsed["rest"]

    # '@' iceren adreslerde izin listesi indirimi uygulanmaz (kullaniciyi yaniltma hilesi)
    whitelist_match = (check_list_match(db, domain, list_url, "whitelist", parsed=parsed)
                       if db and not parsed["userinfo"] else None)
    if whitelist_match:
        url = normalized_url(parsed, parsed["scheme"] or "https")
        note = f" ({whitelist_match.description})" if whitelist_match.description else ""
        return {
            "url": url,
            "risk_score": 0,
            "risk_level": "SAFE",
            "reasons": [{
                "rule_name": "İzin listesi eşleşmesi",
                "description": f"Gösterge analist izin listesindeki '{whitelist_match.pattern}' kuralıyla eşleşti{note}.",
                "severity": "low",
                "contribution": 0,
            }],
            "ioc_details": dict(_empty_ioc(domain, url, parsed["scheme"] != "http", "whitelisted"),
                                inspection_coverage="list"),
            "mitre_techniques": [],
            "related_domains": [],
        }

    # Engel kurali kullanici bilgisi ('a:b@') eklenerek atlatilamaz (D-05)
    blacklist_match = check_list_match(db, domain, list_url, "blacklist", parsed=parsed) if db else None
    if blacklist_match:
        return _list_result("blacklist", blacklist_match, parsed, normalized_url(parsed, parsed["scheme"] or "https"))

    # Ic ag denetimi hattin basinda: alan adi bir kez cozumlenir, ozel/loopback/link-local
    # adreslere cozumlenen hedefler reddedilir; dogrulanan IP tum baglantilarda sabit kullanilir.
    try:
        ip_address = resolve_ip(domain)
    except BlockedAddressError:
        if _is_ip_literal(domain):
            raise InvalidTargetError("İç ağ, loopback veya özel kullanımlı adresler analiz edilemez.")
        # Ic ag adresine cozumlenen AD, cozumlenmeyen adla ayni yaniti alir; ayrinti yalnizca
        # sunucu kaydina yazilir. Aksi halde yanit farki ic agdaki adlari sinamaya yarar (Z-07).
        logger.info("target name resolves to non-public address; treated as unresolved domain=%s", domain)
        ip_address = None

    # 'ip' engel kurali alan adinin cozumlendigi TUM adreslere uygulanir (B-09, A-14)
    if ip_address and db and not _is_ip_literal(domain):
        ip_match = check_ip_rules(db, [ip_address] + [x for x in resolve_all_public(domain) if x != ip_address])
        if ip_match:
            return _list_result("blacklist", ip_match, parsed, normalized_url(parsed, parsed["scheme"] or "https"),
                                resolved_note=f" (alan adı bu adrese çözümleniyor: {ip_address})")
    # Sayfa yoklamasi ayni adi yeniden cozumlemez (B-11): dogrulanan adres yoklamaya tasinir
    ctx = current_probe_context()
    if ctx is not None and ip_address:
        ctx.pinned[domain] = ip_address

    # Harici sorgular paralel: kayit bilgisi ve TLS yoklamasi. Istegin yoklama butcesi ve
    # istemcisi (netguard.ProbeContext) havuz is parcaciklarina tasinir (D-03).
    with ThreadPoolExecutor(max_workers=2) as pool:
        registration_task = pool.submit(_in_context(lookup_domain_registration), domain)
        tls_task = pool.submit(_in_context(probe_tls), domain, ip_address)
        registration = registration_task.result()
        tls = tls_task.result()

    # Alan adi cozumlenmiyorsa sunucu hakkinda HTTPS hukmu verilemez
    if ip_address is None:
        tls = "unreachable"

    # Sema yazilmamissa sunucunun gercekte ne sundugu esas alinir
    if tls == "unreachable":
        scheme = parsed["scheme"] or "https"
        tls_signal = "http_link" if parsed["scheme"] == "http" else None
    elif parsed["scheme"] == "http":
        scheme, tls_signal = "http", "http_link"
    elif parsed["scheme"] == "https":
        scheme, tls_signal = "https", tls if tls != "valid" else None
    else:
        scheme = "https" if tls in ("valid", "invalid") else "http"
        tls_signal = None if tls == "valid" else tls
    has_https = scheme == "https" and tls in ("valid", "invalid")
    url = normalized_url(parsed, scheme)

    with ThreadPoolExecutor(max_workers=3) as pool:
        url_task = pool.submit(_in_context(check_url_reputation), url)
        ip_rep_task = pool.submit(_in_context(check_ip_reputation), ip_address)
        # Sayfa yalnizca 80/443 portlarindan indirilir: servis, ucuncu taraflarin keyfi
        # portlarina istek gondermek icin kullanilamaz (Y-09)
        fetch_page = ip_address and parsed.get("port") in PAGE_PORTS
        page_task = pool.submit(_in_context(probe_page), url) if fetch_page else None
        url_reputation = url_task.result()
        ip_reputation = ip_rep_task.result()
        if page_task:
            page = page_task.result()
        elif ip_address:
            page = {"status": "port_not_allowed"}
        else:
            page = {"status": "unreachable"}

    # Yonlendirme zincirindeki her adimin adresi de 'ip' engel kurallariyla karsilastirilir (B-09)
    if db and page.get("ips"):
        hop_ips = [ip for ip in page["ips"] if ip != ip_address or _is_ip_literal(domain)]
        hop_match = check_ip_rules(db, hop_ips) if hop_ips else None
        if hop_match:
            return _list_result("blacklist", hop_match, parsed, url,
                                resolved_note=" (yönlendirme zincirindeki bir adım bu adrese bağlanıyor)")

    # 'domain' ve 'url' engel kurallari da yonlendirme zincirindeki her adima, son adrese ve sayfanin
    # gosterdigi cercevelere uygulanir (E-14): engel kurali "bu alan adi zararlidir" hukmudur; kullanici ona
    # kisa baglanti, ara sayfa ya da cerceve uzerinden ulastiginda da gecerlidir.
    if db:
        step_match = _blacklisted_step(db, page, url)
        if step_match:
            entry, step_url = step_match
            return _list_result("blacklist", entry, parsed, url,
                                resolved_note=f" (yönlendirme zincirindeki ya da çerçevedeki bir adım: {step_url[:120]})")

    intel = {
        "tls": tls_signal,
        "age_days": registration["age_days"],
        "vt_positives": url_reputation["vt_positives"],
        "vt_total": url_reputation["vt_total"],
        "abuse_score": ip_reputation["abuse_score"],
        "resolved": ip_address is not None,
        "page": page,
    }
    signals, mitigations, context = collect_signals({**parsed, "url": url}, intel)
    risk_score, risk_level, reasons = score_signals(signals, mitigations)

    # Karar SUNUCUDA uretilir (A-13): sayfa icerigi tam incelenemediyse ve skor "Dikkat" esiginin altindaysa
    # duzey "LOW" degil "UNKNOWN" olur; API yaniti, kayit ve sayimlar bu degeri tasir. Istisna: adres
    # katalogdaki bir kurumun resmi adresi ya da kisitli resmi uzantidaysa karar adresin sahipligine dayanir.
    coverage = inspection_coverage(page)
    gaps = set(page.get("opaque") or [])
    if context.get("unverified_form"):
        # Hassas bilgi isteyen ve kimligi metinden belirlenemeyen form (E-07): "tam incelendi" sayilmaz
        gaps.add("unverified_form")
        if coverage == "full":
            coverage = "partial"
    # Istisna yalnizca katalogdaki resmi adresler icindir. Kisitli uzantilar (k12.tr, edu.tr, bel.tr ...)
    # on binlerce bagimsiz yonetilen siteyi kapsar; incelenemeyen sayfa orada da "Karar verilemedi" olur (E-13).
    trusted_site = any(m.get("key") == "official" for m in mitigations) and \
        not any(s.get("key") in ("content_brand", "harvest", "exfil") for s in signals)
    if risk_level == "LOW" and coverage != "full" and not trusted_site:
        risk_level = "UNKNOWN"

    if not reasons:
        reasons.append({
            "rule_name": "Bilinen gösterge yok",
            "description": "Kontrol edilen kuralların hiçbiri tetiklenmedi. Bu, adresin güvenli olduğu anlamına gelmez.",
            "severity": "low",
            "contribution": 0,
        })
    if risk_level in ("LOW", "UNKNOWN") and page.get("status") in ("ok", "not_html", "empty"):
        # Gizlenme notu yalnizca bulgu listesi bosken degil, her dusuk sonucta gosterilir (A-05)
        reasons.append({
            "rule_name": "Gizlenme olasılığı",
            "description": "Sayfa içeriği tek bir anda, tek bir tarayıcı kimliği ve sunucunun IP adresiyle indirildi; "
                           "betik çalıştırılmadı. Saldırgan bu istemciye zararsız bir sayfa gösterebilir (gizlenme / "
                           "cloaking). Düşük skor, adresin güvenli olduğu anlamına gelmez.",
            "severity": "low",
            "contribution": 0,
        })

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "ioc_details": {
            "domain": domain,
            "registrar": (registration["registrar"] or None) and registration["registrar"][:REGISTRAR_MAX_LENGTH],
            "domain_age_days": registration["age_days"],
            "domain_registration_date": registration["registration_date"],
            "ip_address": ip_address,
            "abuse_score": ip_reputation["abuse_score"],
            "ip_reports_count": ip_reputation["reports_count"],
            "abuse_status": ip_reputation["status"],
            "url": url,
            "vt_positives": url_reputation["vt_positives"],
            "vt_total": url_reputation["vt_total"],
            "vt_status": url_reputation["status"],
            "has_https": has_https,
            "tls_status": tls,
            "target_brand": context["target_brand"],
            "target_sector": context["target_sector"],
            "page_status": page.get("status"),
            "page_title": page.get("title"),
            "final_url": page.get("final_url") if page.get("final_url") != url else None,
            "page_fields": page.get("fields") or [],
            "page_cached_at": page.get("cached_at"),
            "inspection_coverage": coverage,
            "inspection_gaps": sorted(gaps) or None,
            "download": page.get("download"),
        },
        "mitre_techniques": [],
        "related_domains": [],
    }
