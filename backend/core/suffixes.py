"""Alan adi sonekleri icin TEK kaynak (Z-01, Z-05, Z-07).

Guven kararlari "bu adres kime ait" degil, "bu adreste icerigi kim yayimliyor" sorusuyla
verilir. Bunun icin uc kavram gerekir ve hepsi bu modulden okunur:

  * Genel sonek (public suffix): altinda herkesin alan adi kaydedebildigi deger
    (com, com.tr, co.uk). Kaynak: Mozilla Public Suffix List (backend/data/public_suffix_list.dat).
  * Paylasimli barindirma soneki: altinda herkesin ucretsiz alt alan adi acabildigi deger
    (blogspot.com, s3.amazonaws.com, blob.core.windows.net, github.io). Kaynak: PSL'nin
    "PRIVATE DOMAINS" bolumu + asagidaki EXTRA_SHARED_SUFFIXES. Boyle bir sonekin altindaki
    ad (garantibbva-giris.blogspot.com) KENDI BASINA kayitli alan adi gibi degerlendirilir;
    sonekin sahibi olan kurumun (Google) guvenini devralmaz.
  * Kayitli alan adi (registrable domain): genel/paylasimli sonek + bir etiket.

Kullananlar: brands.registered_domain / official_brand / owner_brand (kurum katalogu),
list_rules (izin/engel listesi kaliplari), analyzer_interface (gecerli ust alan adi denetimi).

PSL guncellemesi: https://publicsuffix.org/list/public_suffix_list.dat dosyasini
backend/data/ altina indirin; test paketi katalogla tutarliligi denetler.
"""

from functools import lru_cache
from pathlib import Path

from backend.core.hostnames import to_ascii_or_none

PSL_PATH = Path(__file__).resolve().parent.parent / "data" / "public_suffix_list.dat"

# PSL'de bulunmayan ya da yalnizca dar kayitlarla bulunan, altinda herkesin (veya her
# musterinin) alt alan adi acabildigi barindirma/depolama/tunel sonekleri.
EXTRA_SHARED_SUFFIXES = frozenset({
    # Bulut depolama ve barindirma
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "amplifyapp.com",
    "googleusercontent.com", "googleapis.com", "appspot.com", "withgoogle.com", "web.app", "firebaseapp.com",
    "cloudfunctions.net", "run.app", "translate.goog",
    "core.windows.net", "blob.core.windows.net", "web.core.windows.net", "azurewebsites.net",
    "azurestaticapps.net", "azureedge.net", "azurefd.net", "cloudapp.net", "trafficmanager.net",
    "sharepoint.com",
    # Gelistirici ve statik site platformlari
    "github.io", "gitlab.io", "bitbucket.io", "github.dev", "githubusercontent.com",
    "vercel.app", "now.sh", "netlify.app", "netlify.com", "pages.dev", "workers.dev", "r2.dev",
    "herokuapp.com", "herokudns.com", "onrender.com", "fly.dev", "railway.app",
    "glitch.me", "repl.co", "replit.app", "replit.dev", "surge.sh", "neocities.org", "tiiny.site",
    "ipfs.io", "dweb.link",
    # Blog ve site kuruculari
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "webflow.io", "framer.app",
    "squarespace.com", "carrd.co", "000webhostapp.com",
    # Tuneller ve dinamik DNS
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt", "serveo.net",
    "duckdns.org", "no-ip.org", "ddns.net", "hopto.org",
})

# Kisa baglanti servisleri: hedefi gizler; karar yonlendirilen son adres uzerinden verilir.
SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "lnkd.in", "youtu.be", "fb.me", "wa.me", "ow.ly", "buff.ly", "rebrand.ly", "s.id", "v.gd",
})


def _ascii(label: str) -> str:
    return to_ascii_or_none(label) or label.lower()


@lru_cache(maxsize=1)
def _rules():
    """PSL'yi bir kez ayristirir. Her kural hem yazildigi bicimde hem ASCII (Punycode) bicimde tutulur."""
    exact, wildcard, exception, private, tlds = set(), set(), set(), set(), set()
    section_private = False
    for line in PSL_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "===BEGIN PRIVATE DOMAINS===" in line:
            section_private = True
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        forms = {rule}
        body = rule.lstrip("!")
        if body.startswith("*."):
            forms.add("*." + ".".join(_ascii(p) for p in body[2:].split(".")))
        else:
            forms.add(("!" if rule.startswith("!") else "") + ".".join(_ascii(p) for p in body.split(".")))
        for form in forms:
            if form.startswith("!"):
                exception.add(form[1:])
            elif form.startswith("*."):
                wildcard.add(form[2:])
                if section_private:
                    private.add(form)
            else:
                exact.add(form)
                if section_private:
                    private.add(form)
                elif "." not in form:
                    tlds.add(form)
    return {
        "exact": frozenset(exact), "wildcard": frozenset(wildcard), "exception": frozenset(exception),
        "private": frozenset(private), "tlds": frozenset(tlds),
    }


def _labels(host):
    return [l for l in (host or "").lower().strip().rstrip(".").split(".") if l]


@lru_cache(maxsize=8192)
def _suffix_info(host: str):
    """(sonek, paylasimli_mi). Sonek, PSL algoritmasina gore en uzun eslesen kuraldir;
    hicbir kural eslesmezse son etiket (PSL varsayilan '*' kurali)."""
    labels = _labels(host)
    if not labels:
        return "", False
    rules = _rules()
    best, best_len, shared = labels[-1], 1, False
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        n = len(labels) - i
        parent = ".".join(labels[i + 1:])
        if candidate in rules["exception"]:
            # '!www.ck': kuralin kendisi degil, bir ust etiketi sonektir
            if n - 1 >= best_len:
                best, best_len = parent, n - 1
                shared = parent in rules["private"]
            break
        matched_private = None
        if candidate in rules["exact"]:
            matched_private = candidate in rules["private"]
        elif parent and parent in rules["wildcard"]:
            matched_private = ("*." + parent) in rules["private"]
        if candidate in EXTRA_SHARED_SUFFIXES:
            matched_private = True
        if matched_private is not None and n > best_len:
            best, best_len, shared = candidate, n, matched_private
    return best, shared


def public_suffix(host: str) -> str:
    """En uzun genel/paylasimli sonek (PSL + EXTRA_SHARED_SUFFIXES)."""
    return _suffix_info(host)[0]


def is_public_suffix(host: str) -> bool:
    """Deger kendisi bir sonek mi? ('com', 'com.tr', 'co.com', 'github.io', 'blogspot.com')"""
    host = ".".join(_labels(host))
    return bool(host) and public_suffix(host) == host


def shared_suffix(host: str):
    """Ad, herkesin alt alan adi acabildigi bir paylasimli sonekin ALTINDAYSA o sonek; degilse None.
    'garantibbva-giris.blogspot.com' -> 'blogspot.com';  'blogspot.com' -> None."""
    host = ".".join(_labels(host))
    suffix, shared = _suffix_info(host)
    if shared and host != suffix and host.endswith("." + suffix):
        return suffix
    return None


def registrable_domain(host: str) -> str:
    """Sonek + bir etiket. Paylasimli sonek altindaki ad kendi basina kayitli alan adi sayilir."""
    labels = _labels(host)
    if not labels:
        return (host or "").lower()
    suffix = public_suffix(".".join(labels))
    n = suffix.count(".") + 1 if suffix else 1
    if len(labels) <= n:
        return ".".join(labels)
    return ".".join(labels[-(n + 1):])


@lru_cache(maxsize=8192)
def icann_registrable_domain(host: str) -> str:
    """Kayit kurumundaki (RDAP/WHOIS) alan adi: yalnizca ICANN sonekleri dikkate alinir.
    'x.duckdns.org' -> 'duckdns.org', 'kova.s3.amazonaws.com' -> 'amazonaws.com',
    'sube.garanti.com.tr' -> 'garanti.com.tr'. Kayit sorgulari ve onbellegi bu degerle yapilir (D-06)."""
    labels = _labels(host)
    if not labels:
        return (host or "").lower()
    rules = _rules()
    best = 1
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        n = len(labels) - i
        parent = ".".join(labels[i + 1:])
        if candidate in rules["exception"]:
            best = max(best, n - 1)
            break
        if candidate in rules["exact"] and candidate not in rules["private"]:
            best = max(best, n)
        elif parent and parent in rules["wildcard"] and ("*." + parent) not in rules["private"]:
            best = max(best, n)
    if len(labels) <= best:
        return ".".join(labels)
    return ".".join(labels[-(best + 1):])


def is_known_tld(tld: str) -> bool:
    """IANA kok bolgesindeki ust alan adlari (PSL ICANN bolumu). 'local', 'internal', 'corp',
    'lan', 'home' gibi ic ag uzantilari bu listede yoktur (Z-07)."""
    tld = (tld or "").lower().strip(".")
    return bool(tld) and (tld in _rules()["tlds"] or _ascii(tld) in _rules()["tlds"])
