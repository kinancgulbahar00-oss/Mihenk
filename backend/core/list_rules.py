"""Izin/engel listesi kaliplarinin dogrulanmasi ve kanonik bicimi (Y-07).

Alan adi kurallari "kendisi veya herhangi bir alt alan adi" olarak eslesir. Bu yuzden
kalip kaydedilebilir bir alan adi olmalidir: 'com.tr' veya 'example' gibi bir ust alan
adi, o uzantidaki TUM adresleri sessizce izinli/engelli yapar. Paylasimli barindirma
sonekleri (github.io, vercel.app...) ayni etkiyi daha az fark edilir bicimde yaratir.
"""

import ipaddress

from backend.core.analyzer_interface import InvalidTargetError, extract_host, parse_url_components
from backend.core.brands import catalog, user_content_boundary, user_content_domains
from backend.core.hostnames import InvalidHostError, to_ascii
from backend.core.suffixes import EXTRA_SHARED_SUFFIXES, SHORTENERS, is_public_suffix, shared_suffix

MAX_PATTERN_LENGTH = 1024

# Geriye donuk uyumluluk: paylasimli sonek listesi artik tek kaynaktan (backend/core/suffixes.py)
# okunur; kurum katalogu, liste kurallari ve kayitli alan adi karari ayni veriyi kullanir (Z-01).
SHARED_HOSTING_SUFFIXES = EXTRA_SHARED_SUFFIXES


class InvalidPatternError(ValueError):
    """Mesaj istemciye gosterilir."""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_domain(host: str) -> str:
    """Eslestirmenin GORECEGI deger dogrulanir (Z-05): 'www.com.tr' kurali eslestirmede 'com.tr'
    olur; dogrulama da bu deger uzerinde yapilir."""
    if "." not in host:
        raise InvalidPatternError(
            f"'{host}' tek etiketli bir değer (üst alan adı). Kural, bu uzantıdaki tüm adresleri "
            f"etkileyeceği için kabul edilmez; kaydedilebilir bir alan adı girin (ör. ornek.com.tr)."
        )
    if host in catalog()["restricted"] or (is_public_suffix(host) and host not in EXTRA_SHARED_SUFFIXES
                                            and not shared_suffix(host)):
        raise InvalidPatternError(
            f"'{host}' genel bir alan adı uzantısı. Kural, bu uzantıdaki tüm adresleri etkileyeceği "
            f"için kabul edilmez; kaydedilebilir bir alan adı girin (ör. ornek.{host})."
        )
    if is_public_suffix(host):
        raise InvalidPatternError(
            f"'{host}' paylaşımlı bir barındırma/tünel alanı; herkes bu alanın altında adres "
            f"açabilir. Yalnızca belirli bir alt alan adını ekleyin (ör. kullanici.{host})."
        )
    if host in user_content_domains() or host in SHORTENERS:
        raise InvalidPatternError(
            f"'{host}' kullanıcı içeriği sunan bir alan (blog, form, dosya paylaşımı veya kısa bağlantı); "
            f"alan adı kuralı bu alandaki herkesin sayfasını kapsar. Belirli bir sayfa için 'url' "
            f"türünde kural ekleyin (ör. {host}/view/sirket)."
        )
    return host


def _is_platform_host(host: str) -> bool:
    """Herkesin icerik yayimlayabildigi alanin KENDISI mi (alt yayimci siniri degil)?"""
    if _is_ip(host):
        return False
    if host in user_content_domains() or host in SHORTENERS:
        return True
    return bool(user_content_boundary(host)) and not shared_suffix(host)


def canonical_pattern(entry_type: str, raw: str) -> str:
    """Kalibi dogrular ve eslestirmede kullanilan kanonik bicime getirir.
    - domain: UTS-46 ile ASCII (Punycode) alan adi; 'www.' atilir (eslestirme de atar; Z-05)
    - ip    : standart IP gosterimi
    - url   : semasiz kanonik adres (ASCII alan adi + yol)"""
    value = (raw or "").strip()
    if not value:
        raise InvalidPatternError("Kalıp boş olamaz.")

    if entry_type == "ip":
        try:
            return str(ipaddress.ip_address(value.strip("[]")))
        except ValueError:
            raise InvalidPatternError("Geçerli bir IPv4 veya IPv6 adresi girin.")

    if entry_type == "domain":
        # 'https://ornek.com/yol' gibi girdilerden yalnizca alan adi alinir
        try:
            parsed = parse_url_components(value)
        except InvalidTargetError as exc:
            raise InvalidPatternError(f"Alan adı geçersiz: {exc}")
        if parsed["userinfo"]:
            raise InvalidPatternError("Alan adı kuralı '@' içeremez.")
        host = parsed["domain"]
        if _is_ip(host):
            raise InvalidPatternError("IP adresleri için kural türü olarak 'ip' seçin.")
        try:
            host = to_ascii(host)
        except InvalidHostError:
            raise InvalidPatternError("Alan adı ASCII biçimine çevrilemedi.")
        # Kaydedilen ve dogrulanan deger, eslestirmenin kullandigi degerdir ('www.' atilmis; Z-05)
        return _validate_domain(extract_host(host) or host)

    if entry_type == "url":
        try:
            parsed = parse_url_components(value)
        except InvalidTargetError as exc:
            raise InvalidPatternError(f"Adres geçersiz: {exc}")
        if parsed["userinfo"]:
            raise InvalidPatternError("Adres kuralı '@' içeremez.")
        if "." not in parsed["domain"] and ":" not in parsed["domain"]:
            raise InvalidPatternError("Adresin alan adı tek etiketli olamaz.")
        # Kullanici icerigi sunan alanda (sites.google.com, docs.google.com, t.co) yolsuz adres kurali,
        # reddedilen alan adi kuraliyla ayni etkiyi yapar: alandaki herkesin sayfasini kapsar (D-05).
        # Paylasimli sonek altindaki ad (sirket.blogspot.com) tek bir yayimciya aittir; ona yolsuz kural eklenebilir.
        host = parsed["domain"][4:] if parsed["domain"].startswith("www.") else parsed["domain"]
        has_path = any(seg for seg in (parsed["path"] or "").split("/"))
        if not has_path and _is_platform_host(host):
            raise InvalidPatternError(
                f"'{host}' kullanıcı içeriği sunan bir alan; yolsuz adres kuralı bu alandaki herkesin sayfasını "
                f"kapsar. Belirli bir sayfanın yolunu da yazın (ör. {host}/view/sirket)."
            )
        # Alan adi kucuk harfli ASCII, yol sadelestirilmis ve yuzde kodlu; yolun harf
        # buyuklugu korunur (Z-06)
        pattern = parsed["authority"] + parsed["rest"]
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise InvalidPatternError(f"Kalıp en fazla {MAX_PATTERN_LENGTH} karakter olabilir.")
        return pattern

    raise InvalidPatternError("Kural türü 'domain', 'ip' veya 'url' olmalıdır.")
