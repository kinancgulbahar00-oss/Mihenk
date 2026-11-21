"""Sayfanin ICINDEN gelen adreslerin (yonlendirme, refresh, cerceve, form, baglanti) cozumlenmesi (E-03).

Tarayicilar adresleri WHATWG URL standardiyla cozer: ters egik cizgi yol ayiricidir (egik cizgi + ters egik
cizgi + ad baska bir siteye gider), 'http:///host' gecerlidir, sekme ve satir sonlari atilir, ters egik
cizgiden sonra gelen '@' kullanici bilgisi baslatmaz.
Python'un urljoin/urlsplit islevleri RFC 3986'yi izler ve ayni dizgiyi baska bir adrese cozer; platform
tarayicinin gittigi adresten BASKA bir sayfayi inceliyordu. Butun cozumleme bu modulden gecer ve standardin
yaygin bicimde sinanan bir uygulamasini (Ada; Node.js'in URL ayristiricisi) kullanir.
"""

import re
from urllib.parse import urljoin, urlsplit

import ada_url

MAX_URL_CHARS = 8192
_TRICK_RE = re.compile("[\\\\\t\n\r]")
_SCHEME_SLASHES_RE = re.compile(r"^\s*https?:(?!//[^/\\])", re.IGNORECASE)


class Url:
    __slots__ = ("href", "scheme", "host", "port", "target", "userinfo", "origin")

    def __init__(self, parsed):
        self.href = parsed.href
        self.scheme = (parsed.protocol or "").rstrip(":").lower()
        host = parsed.hostname or ""
        # IPv6 adresi koseli parantezle doner; baglanti ve karsilastirma icin parantezsiz bicim kullanilir
        self.host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        self.port = int(parsed.port) if parsed.port else None
        self.target = (parsed.pathname or "/") + (parsed.search or "")
        self.userinfo = bool(parsed.username or parsed.password)
        self.origin = f"{self.scheme}://{host}" + (f":{parsed.port}" if parsed.port else "")

    @property
    def path(self):
        return self.target.split("?", 1)[0]

    @property
    def without_fragment(self):
        return self.href.split("#", 1)[0]


def parse(value, base=None):
    """Adresi tarayici kurallariyla cozer; gecersizse None. `base` verilirse goreli adres ona gore cozulur."""
    if not isinstance(value, str) or len(value) > MAX_URL_CHARS:
        return None
    try:
        parsed = ada_url.URL(value, base=base) if base else ada_url.URL(value)
        return Url(parsed)
    except Exception:
        # ValueError (gecersiz adres), UnicodeError (tek basina vekil kod noktasi) vb.
        return None


def resolve(base, value):
    """Goreli ya da mutlak adresin tarayicida gidecegi adres (href); cozumlenemezse None."""
    url = parse((value or ""), base)
    return url.href if url else None


def host_of(value):
    url = parse(value)
    return url.host if url and url.scheme in ("http", "https") else None


def is_deceptive(base, value):
    """Deger, RFC 3986 ayristiricisinda ve tarayicida FARKLI bir siteye mi cozumleniyor, ya da kullanici bilgisi
    ('@') mi tasiyor? Mesru sitelerin yonlendirme ve cerceve adreslerinde bu yazimlar gorulmez; inceleme
    araclarini baska bir adrese yoneltmek icin kullanilir (E-03)."""
    value = value or ""
    url = parse(value, base)
    if url is None or url.scheme not in ("http", "https"):
        return False
    if url.userinfo:
        return True
    if not (_TRICK_RE.search(value) or _SCHEME_SLASHES_RE.match(value) or value.lstrip().startswith("///")):
        return False
    try:
        naive = (urlsplit(urljoin(base, value.strip())).hostname or "").lower()
    except ValueError:
        return True
    return naive != url.host.lower()
