import re
import socket
import time
from datetime import datetime, timezone

import requests

from backend.core.cache import BoundedCache
from backend.core.netguard import (
    DEGRADED_TLS_BUDGET_SECONDS, MIN_HOP_SECONDS, BlockedAddressError, Deadline, TargetBusyError, connect_pinned,
    current_probe_context, resolve_public, targets, tls_budget,
)
from backend.core.suffixes import icann_registrable_domain, registrable_domain

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"
IANA_WHOIS_HOST = "whois.iana.org"
LOOKUP_TIMEOUT = 5
LOOKUP_BUDGET_SECONDS = 8
WHOIS_MAX_BYTES = 256 * 1024
CACHE_TTL_SECONDS = 6 * 60 * 60
UNKNOWN_CACHE_TTL_SECONDS = 10 * 60

_cache = BoundedCache(maxsize=4096, max_age=CACHE_TTL_SECONDS)

_DATE_PATTERNS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d.%m.%Y %H:%M:%S",
    "%d/%m/%Y",
    "%Y-%b-%d",
    "%Y.%m.%d",
)

_CREATION_FIELDS = (
    "creation date",
    "created",
    "created on",
    "created date",
    "registered on",
    "registration time",
    "domain record created",
    "domain record activated",
    "registered",
)

_REGISTRAR_FIELDS = (
    "registrar",
    "sponsoring registrar",
    "registrar name",
    "organization name",
)


def _now():
    return datetime.now(timezone.utc)


def _parse_datetime(value):
    if not value:
        return None
    text = str(value).strip().rstrip(".")
    if text.endswith("Z"):
        text = text[:-1] + "+0000"
    text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
    for pattern in _DATE_PATTERNS:
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _age_days(registered):
    if not registered:
        return None
    delta = _now() - registered
    return max(delta.days, 0)


def _candidate_domains(domain):
    labels = domain.strip(".").lower().split(".")
    candidates = []
    for start in range(len(labels) - 1):
        candidate = ".".join(labels[start:])
        if candidate.count(".") >= 1:
            candidates.append(candidate)
    return candidates[:3]


def _rdap_registrar(payload):
    for entity in payload.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) > 3:
                    return str(item[3]).strip()
        if entity.get("handle"):
            return str(entity["handle"]).strip()
    return None


def _rdap_lookup(domain):
    try:
        response = requests.get(
            RDAP_BOOTSTRAP_URL.format(domain=domain),
            headers={"Accept": "application/rdap+json"},
            timeout=LOOKUP_TIMEOUT,
        )
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None

    registered = None
    for event in payload.get("events") or []:
        if event.get("eventAction") == "registration":
            registered = _parse_datetime(event.get("eventDate"))
            break
    if not registered:
        return None

    return {
        "registration_date": registered.date().isoformat(),
        "age_days": _age_days(registered),
        "registrar": _rdap_registrar(payload),
        "source": "rdap",
    }


def _whois_query(host, query):
    deadline = time.monotonic() + LOOKUP_BUDGET_SECONDS
    with socket.create_connection((host, 43), timeout=LOOKUP_TIMEOUT) as sock, \
            Deadline(LOOKUP_BUDGET_SECONDS) as watchdog:
        watchdog.watch(sock)
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        total = 0
        while time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= WHOIS_MAX_BYTES:
                break
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _whois_server_for(tld):
    try:
        response = _whois_query(IANA_WHOIS_HOST, tld)
    except OSError:
        return None
    match = re.search(r"^whois:\s*(\S+)", response, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _normalize_key(key):
    return re.sub(r"[\s._-]+", " ", key).strip().lower()


def _whois_field(text, field_names):
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if _normalize_key(key) in field_names:
            value = value.strip()
            if value:
                return value
    return None


def _registrar_section(text):
    match = re.search(r"^\*\*\s*Registrar:?\s*$", text, re.MULTILINE | re.IGNORECASE)
    if not match:
        return text
    rest = text[match.end():]
    nxt = re.search(r"^\*\*\s", rest, re.MULTILINE)
    if nxt:
        return rest[:nxt.start()]
    return rest


def _whois_lookup(domain):
    tld = domain.rsplit(".", 1)[-1]
    server = _whois_server_for(tld)
    if not server:
        return None
    try:
        text = _whois_query(server, domain)
    except OSError:
        return None
    if not text:
        return None

    registered = _parse_datetime(_whois_field(text, _CREATION_FIELDS))
    registrar = _whois_field(_registrar_section(text), _REGISTRAR_FIELDS)
    if not registered and not registrar:
        return None

    return {
        "registration_date": registered.date().isoformat() if registered else None,
        "age_days": _age_days(registered),
        "registrar": registrar,
        "source": "whois",
    }


UNKNOWN_REGISTRATION = {
    "registration_date": None,
    "age_days": None,
    "registrar": None,
    "source": None,
}


def lookup_domain_registration(domain):
    if not domain:
        return dict(UNKNOWN_REGISTRATION)

    # Onbellek ve sorgu kayit kurumundaki alan adiyla yapilir (D-06): rastgele alt alan adlariyla
    # ('a1.duckdns.org', 'a2.duckdns.org') gonderilen her istek RDAP/WHOIS'e yeni sorgu uretmez.
    key = icann_registrable_domain(domain.lower().rstrip("."))
    cached = _cache.get(key)
    if cached:
        age_of_entry = time.time() - cached[0]
        ttl = CACHE_TTL_SECONDS if cached[1].get("source") else UNKNOWN_CACHE_TTL_SECONDS
        if age_of_entry < ttl:
            return dict(cached[1])

    deadline = time.monotonic() + LOOKUP_BUDGET_SECONDS
    result = None
    for candidate in _candidate_domains(key)[:1]:
        if time.monotonic() >= deadline:
            break
        result = _rdap_lookup(candidate)
        if result:
            break
        if time.monotonic() >= deadline:
            break
        result = _whois_lookup(candidate)
        if result:
            break

    if not result:
        result = dict(UNKNOWN_REGISTRATION)

    _cache[key] = (time.time(), result)
    return dict(result)


def resolve_ip(domain):
    """Alan adini cozumler ve herkese acik oldugunu dogrular.
    Ic ag adresine cozumlenirse BlockedAddressError firlatir (sonuc onbellege alinmaz).
    DNS rebinding'e karsi bu IP sonraki tum baglantilarda sabit kullanilir; bu yuzden
    sonuc yalnizca kisa sure onbellekte tutulur."""
    if not domain:
        return None
    key = f"ip:{domain.lower()}"
    cached = _cache.get(key)
    if cached and time.time() - cached[0] < IP_CACHE_TTL_SECONDS:
        return cached[1]
    address = resolve_public(domain, timeout=LOOKUP_TIMEOUT)
    _cache[key] = (time.time(), address)
    return address


IP_CACHE_TTL_SECONDS = 5 * 60


TLS_TIMEOUT = 4
# El sikismasinin tamami icin kesin ust sinir (soket zaman asimi her okumada yeniden baslar; Y-02)
TLS_BUDGET_SECONDS = 6


def probe_tls(host, ip=None):
    """443 portunda TLS el sikismasi dener. Baglanti yalnizca onceden dogrulanmis,
    herkese acik `ip` adresine yapilir (SNI ve sertifika dogrulamasi `host` ile).

    'valid'   : HTTPS var ve sertifika dogrulandi
    'invalid' : HTTPS var ama sertifika dogrulanamadi
    'none'    : 443 portunda HTTPS sunulmuyor / baglanti kurulamadi
    """
    import ssl

    if not host or not ip:
        return "none"
    # Sayfa yoklamasinda veya onceki TLS yoklamasinda sure butcesini asan hedef yeniden
    # beklenmez (Z-04): yolu degistirilen her istek yeni bir 6 saniyelik bekleme baslatamaz
    # Karantina anahtari tam addir (B-04): platformdaki yavas bir ad ayni alan adindaki digerlerini kapatmaz
    target = registrable_domain(host)
    scope = host.lower()
    if targets.is_slow(target, scope=scope):
        return "unreachable"
    key = f"tls:{host.lower()}:{ip}"
    cached = _cache.get(key)
    if cached and time.time() - cached[0] < UNKNOWN_CACHE_TTL_SECONDS:
        return cached[1]

    from backend.core.page_probe import is_protected_target

    protected = is_protected_target(host)
    status = "none"
    # Butce istemciye ve yuke gore kisalabilir (D-03); varsayilan TLS_BUDGET_SECONDS
    budget = min(TLS_BUDGET_SECONDS, tls_budget())
    held = None
    if not protected and targets.ip_degraded(ip):
        # Kisitli IP (B-05): adlar incelenir, ancak kisa butceyle ve IP siniri icinde, beklemeden
        budget = min(budget, DEGRADED_TLS_BUDGET_SECONDS)
        try:
            held = targets.acquire_ip(ip, wait=0.0)
        except TargetBusyError:
            return "unreachable"
    started = time.monotonic()
    watchdog = Deadline(budget)
    try:
        with watchdog, connect_pinned(ip, 443, TLS_TIMEOUT) as sock:
            context = ssl.create_default_context()
            try:
                # El sikismasi ayri yapilir: yavas el sikismasi bekci tarafindan kesilebilsin
                with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False) as ssock:
                    watchdog.watch(ssock)
                    ssock.do_handshake()
                    status = "valid"
            except ssl.SSLCertVerificationError:
                status = "invalid"
            except (ssl.SSLError, OSError, ValueError):
                status = "none"
    except (OSError, UnicodeError, BlockedAddressError):
        status = "none"
    finally:
        if held is not None:
            held.__exit__(None, None, None)

    if watchdog.expired:
        # El sikismasi butceyi asti (Z-04). Zaman asimi istemciye yazilir (D-03); hedef ancak
        # en az MIN_HOP_SECONDS beklendiyse yavas sayilir, katalogdaki kurum adresi tek zaman
        # asimiyla karantinaya alinmaz (D-02).
        ctx = current_probe_context()
        if ctx:
            ctx.record_timeout(target)
        if budget >= MIN_HOP_SECONDS and time.monotonic() - started >= MIN_HOP_SECONDS - 0.05:
            targets.record_timeout(target, ip=ip, client=ctx.client if ctx else None,
                                   protected=protected, scope=scope)
        status = "unreachable"
        # Kisa butceyle alinan sonuc onbellege yazilmaz
        return status
    _cache[key] = (time.time(), status)
    return status
