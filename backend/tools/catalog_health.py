"""Kurum katalogu saglik denetimi (B-07, A-12; rapor 7.6).

Katalogdaki (backend/data/tr_brands.json) her resmi alan adi icin:
  * DNS: ad ya da 'www.' oneki cozumleniyor mu (getaddrinfo);
  * kayit: alan adi KAYITLI mi, kaydin bitis tarihi yakin mi, durumu 'hold' mu?

Kayit sorgusunun kaynagi uzantiya gore secilir (A-12):
  * '.tr'                      -> TRABIS WHOIS (whois.trabis.gov.tr);
  * RDAP hizmeti olan uzantilar -> RDAP (rdap.org; IANA RDAP onyukleme dosyasiyla dogrulanir);
  * digerleri                   -> IANA'nin yonlendirdigi WHOIS sunucusu.
RDAP hizmeti OLMAYAN bir uzanti icin rdap.org da HTTP 404 dondurur; bu yanit "kayitli degil" SAYILMAZ.
Hicbir kaynaktan yanit alinamazsa sonuc "dogrulanamadi" olur.

Sonuclar iki sinifa ayrilir:
  * HATA   : ad kayitli degil; kayit askida (hold); kaydin bitmesine EXPIRY_ERROR_DAYS gunden az kaldi.
             Kayitli olmayan bir "resmi" ad, herkesin kaydedip kurumun resmi adres guvenini devralabilecegi
             bir addir (cepte-sok.com).
  * UYARI  : ad cozumlenmiyor (ama kayitli); kayit durumu dogrulanamadi.
Katalogdaki `health_exceptions` ({ad: gerekce}) bilinen ve kabul edilmis durumlari uyari listesinden cikarir
(or. microsoftonline.com: kayitli, yalnizca alt alan adlari cozumlenir).

Cikis kodu: 0 hata yok, 1 en az bir HATA var (uyarilar isi basarisiz yapmaz; --strict ile yapar).

Calistirma:
    py -3.11 -m backend.tools.catalog_health              # tum resmi adlar
    py -3.11 -m backend.tools.catalog_health --json       # makine okunur cikti
    py -3.11 -m backend.tools.catalog_health --no-registry  # yalnizca DNS

Bu denetim AGA ERISIR; birim testlerinden ayri, CI'da zamanlanmis bir is olarak calisir
(.github/workflows/security.yml, catalog-health). Yanitlarin yorumlanmasi birim testleriyle sinanir
(backend/tests/test_security_v6.py).
"""

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / "data" / "tr_brands.json"
RDAP_URL = "https://rdap.org/domain/{domain}"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TR_WHOIS = "whois.trabis.gov.tr"
IANA_WHOIS = "whois.iana.org"
USER_AGENT = "mihenk-catalog-health/1.1"
EXPIRY_ERROR_DAYS = 30
RDAP_MIN_INTERVAL = 1.2
HOLD_STATUSES = {"client hold", "server hold", "pending delete", "redemption period"}
_NOT_FOUND = ("no match", "not found", "no data found", "no entries found", "status: free", "status: available",
              "domain not found", "is available for")


def _resolves(name: str) -> bool:
    for host in (name, "www." + name):
        try:
            socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            return True
        except (OSError, UnicodeError):
            continue
    return False


def _whois(server: str, query: str, timeout: float = 10.0) -> str | None:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((query + "\r\n").encode("ascii", "ignore"))
            chunks, total = [], 0
            while total < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        return b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return None


def parse_whois(text: str | None) -> dict:
    """WHOIS yanitini yorumlar: registered / not_registered / unverifiable."""
    if not text or not text.strip():
        return {"registry": "unverifiable", "detail": "whois yanıt vermedi"}
    low = text.lower()
    if any(marker in low for marker in _NOT_FOUND):
        return {"registry": "not_registered", "source": "whois"}
    if "domain name:" in low or "domain:" in low:
        result = {"registry": "registered", "source": "whois"}
        if "frozen status: yes" in low or "clienthold" in low.replace(" ", "") or "serverhold" in low.replace(" ", ""):
            result["status"] = ["client hold"]
        return result
    return {"registry": "unverifiable", "detail": "whois yanıtı tanınmadı"}


@lru_cache(maxsize=1)
def rdap_tlds() -> frozenset | None:
    """RDAP hizmeti olan uzantilar (IANA onyukleme dosyasi). Alinamazsa None."""
    import requests

    try:
        response = requests.get(RDAP_BOOTSTRAP_URL, timeout=10, headers={"User-Agent": USER_AGENT})
        services = response.json().get("services", [])
    except (requests.RequestException, ValueError):
        return None
    return frozenset(t.lower() for service in services for t in service[0])


def parse_rdap(status_code: int, payload, tld_has_rdap: bool | None) -> dict:
    """RDAP yanitini yorumlar. 404 yalnizca uzantinin RDAP hizmeti OLDUGU biliniyorsa "kayitli degil"dir."""
    if status_code == 404:
        if tld_has_rdap:
            return {"registry": "not_registered", "source": "rdap"}
        return {"registry": "unverifiable", "detail": "uzantının RDAP hizmeti yok ya da bilinmiyor"}
    if status_code != 200 or not isinstance(payload, dict):
        return {"registry": "unverifiable", "detail": f"RDAP HTTP {status_code}"}
    result = {"registry": "registered", "source": "rdap",
              "status": [str(s).lower() for s in payload.get("status") or []]}
    for event in payload.get("events") or []:
        if event.get("eventAction") == "expiration":
            try:
                expires = datetime.fromisoformat(str(event.get("eventDate")).replace("Z", "+00:00"))
            except ValueError:
                continue
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            result["expires"] = expires.date().isoformat()
            result["days_left"] = (expires - datetime.now(timezone.utc)).days
    return result


_rdap_lock = threading.Lock()
_rdap_last = [0.0]


def _rdap(name: str, tld_has_rdap: bool | None, timeout: float = 10.0) -> dict:
    import requests

    response = None
    for attempt in range(4):
        # rdap.org istek hizini sinirlar (HTTP 429): sorgular sirayla ve aralikli gonderilir
        with _rdap_lock:
            wait = RDAP_MIN_INTERVAL - (time.monotonic() - _rdap_last[0])
            if wait > 0:
                time.sleep(wait)
            try:
                response = requests.get(RDAP_URL.format(domain=name), timeout=timeout,
                                        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT})
            except requests.RequestException as exc:
                return {"registry": "unverifiable", "detail": type(exc).__name__}
            finally:
                _rdap_last[0] = time.monotonic()
            if response.status_code != 429:
                break
            try:
                pause = min(60.0, float(response.headers.get("Retry-After", "10")))
            except ValueError:
                pause = 10.0
            time.sleep(pause * (attempt + 1))
    try:
        payload = response.json() if response.status_code == 200 else None
    except ValueError:
        payload = None
    return parse_rdap(response.status_code, payload, tld_has_rdap)


def registration(name: str) -> dict:
    """Alan adinin kayit durumu; kaynak uzantiya gore secilir. Katalogdaki ad bir alt alan adiysa
    (login.windows.net, ff.garena.com) kayit kurumunda sorulan, onun kayitli alan adidir."""
    from backend.core.suffixes import icann_registrable_domain

    name = icann_registrable_domain(name.lower().rstrip(".")) or name
    tld = name.rsplit(".", 1)[-1].lower()
    if tld == "tr":
        return parse_whois(_whois(TR_WHOIS, name))
    known = rdap_tlds()
    has_rdap = None if known is None else tld in known
    if has_rdap:
        return _rdap(name, True)
    # RDAP hizmeti yok ya da bilinmiyor: IANA'nin gosterdigi WHOIS sunucusu
    referral = _whois(IANA_WHOIS, tld) or ""
    server = next((line.split(":", 1)[1].strip() for line in referral.splitlines()
                   if line.lower().startswith("whois:") and line.split(":", 1)[1].strip()), None)
    if server:
        return parse_whois(_whois(server, name))
    return {"registry": "unverifiable", "detail": "uzantı için kayıt sorgu servisi bulunamadı"}


def classify(item: dict, exceptions: dict | None = None) -> dict:
    """Denetim sonucunu HATA / UYARI olarak siniflandirir (A-12)."""
    errors, warnings = [], []
    state = item.get("registry")
    if state == "not_registered":
        errors.append("kayıtlı değil")
    elif state == "unverifiable":
        warnings.append("kayıt durumu doğrulanamadı" + (f" ({item['detail']})" if item.get("detail") else ""))
    held = HOLD_STATUSES & set(item.get("status") or [])
    if held:
        errors.append("askıda: " + ", ".join(sorted(held)))
    if item.get("days_left") is not None and item["days_left"] < EXPIRY_ERROR_DAYS:
        errors.append(f"kaydın bitmesine {item['days_left']} gün")
    if item.get("resolves") is False:
        warnings.append("çözümlenmiyor")
    reason = (exceptions or {}).get(item.get("domain"))
    if reason:
        # Kabul edilmis durum: uyarilar bastirilir; HATA sinifi (kayitli degil, askida) bastirilMAZ
        item["exception"] = reason
        warnings = []
    item["errors"], item["warnings"] = errors, warnings
    return item


def check(name: str, use_registry: bool = True, exceptions: dict | None = None) -> dict:
    item = {"domain": name, "resolves": _resolves(name)}
    if use_registry:
        item.update(registration(name))
    return classify(item, exceptions)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="JSON cikti")
    parser.add_argument("--no-registry", "--no-rdap", dest="no_registry", action="store_true",
                        help="kayit sorgusu yapma (yalnizca DNS)")
    parser.add_argument("--strict", action="store_true", help="uyarilar da isi basarisiz yapsin")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)

    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    restricted = tuple(data["restricted_suffixes"])
    exceptions = data.get("health_exceptions") or {}
    owners = {}
    for brand in data["brands"]:
        for domain in brand.get("domains", []):
            owners.setdefault(domain, brand["name"])  # ayni ad birden fazla kurumda olabilir: bir kez denetlenir

    def run(entry):
        domain, brand = entry
        # Kisitli uzantilarda (gov.tr, edu.tr...) kaydi yalnizca yetkili kurum yapabilir: DNS yeterli
        is_restricted = any(domain == s or domain.endswith("." + s) for s in restricted)
        item = check(domain, use_registry=not args.no_registry and not is_restricted, exceptions=exceptions)
        item["brand"] = brand
        time.sleep(0.2)
        return item

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 6))) as pool:
        results = list(pool.map(run, sorted(owners.items())))
    errors = [r for r in results if r["errors"]]
    warnings = [r for r in results if r["warnings"] and not r["errors"]]
    if args.json:
        print(json.dumps({"checked": len(results), "errors": errors, "warnings": warnings}, ensure_ascii=False, indent=1))
    else:
        print(f"{len(results)} resmi alan adı denetlendi; {len(errors)} hata, {len(warnings)} uyarı.")
        for label, rows, key in (("HATA ", errors, "errors"), ("UYARI", warnings, "warnings")):
            for r in rows:
                print(f"  {label} {r['domain']:<34} {r['brand']:<30} {'; '.join(r[key] + (r['warnings'] if key == 'errors' else []))}")
    return 1 if errors or (args.strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
