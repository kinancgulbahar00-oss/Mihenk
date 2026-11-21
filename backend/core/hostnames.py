"""Alan adinin tek kanonik bicimi (Y-01, Y-06).

Tarayicilar alan adini WHATWG URL standardina gore UTS-46 *gecissiz* (nontransitional)
islemeyle ASCII'ye cevirir: 'ß' korunur (sunexpreß.com -> xn--sunexpre-xya.com),
Turkce ve aksanli harfler Punycode'a donusur (işbank.com -> xn--ibank-jdb.com).
Python'un yerlesik 'idna' kodlayicisi ise eski IDNA 2003 kurallarini uygular ve
'ß' harfini 'ss' yapar; yani tarayicinin gidecegi siteden farkli bir siteyi tarif eder.

Kural: girdi hattin basinda bir kez to_ascii() ile cevrilir; liste eslestirme, sahiplik
karari, DNS, TLS, sayfa indirme ve kayit yalnizca bu degeri kullanir. Benzerlik tespiti
icin kullanilan sadelestirme (brands.normalize_text) hicbir zaman sahiplik karari vermez.
"""

import idna


class InvalidHostError(ValueError):
    """Alan adi tarayicilarin kabul ettigi bicimde ASCII'ye cevrilemiyor."""


def _check_a_label(label: str) -> None:
    """'xn--' ile baslayan ASCII etiket gecerli bir Punycode olmali ve gecerli bir
    Unicode etikete donmeli; aksi halde tarayici da adresi reddeder."""
    try:
        decoded = label[4:].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        raise InvalidHostError(label)
    if not decoded or decoded.isascii():
        raise InvalidHostError(label)
    try:
        if idna.uts46_remap(decoded, std3_rules=False, transitional=False) != decoded:
            raise InvalidHostError(label)
    except idna.IDNAError:
        raise InvalidHostError(label)


def to_ascii(host: str) -> str:
    """Alan adini tarayicilarla ayni kurallarla (UTS-46, gecissiz, STD3 kurallari kapali:
    alt cizgi gibi tarayicinin kabul ettigi karakterler korunur) kucuk harfli ASCII'ye cevirir.
    Cevrilemeyen girdi sessizce kabul edilmez: InvalidHostError."""
    host = (host or "").strip()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise InvalidHostError("bos alan adi")
    try:
        mapped = idna.uts46_remap(host, std3_rules=False, transitional=False)
    except (idna.IDNAError, UnicodeError):
        raise InvalidHostError(host)

    labels = []
    for label in mapped.split("."):
        if not label:
            raise InvalidHostError(host)
        if label.isascii():
            label = label.lower()
            if label.startswith("xn--"):
                _check_a_label(label)
            labels.append(label)
        else:
            try:
                labels.append("xn--" + label.encode("punycode").decode("ascii"))
            except UnicodeError:
                raise InvalidHostError(host)
    return ".".join(labels)


def to_ascii_or_none(host: str):
    try:
        return to_ascii(host)
    except InvalidHostError:
        return None


def to_unicode(host: str) -> str:
    """Gosterim ve benzerlik tespiti icin: 'xn--' etiketlerini Unicode'a cevirir.
    Cozulemeyen etiket oldugu gibi kalir. Sahiplik karari icin KULLANILMAZ."""
    labels = []
    for label in (host or "").split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)
