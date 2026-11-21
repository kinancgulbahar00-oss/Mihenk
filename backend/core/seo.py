"""Arama motoru gorunurlugu (SEO): robots.txt, sitemap.xml, llms.txt ve index.html basligindaki etiketler.

Tasarim ilkeleri:
  * Kritik SEO etiketleri (robots, canonical, yapilandirilmis veri) JavaScript ile DEGIL, sunucunun dondurdugu
    ilk HTML icinde verilir: Google'in JavaScript SEO belgesi canonical / robots etiketlerinin ham HTML'de
    bulunmasini onerir; yapay zeka tarayicilarinin cogu JavaScript calistirmaz.
  * Dizine eklenme ACIKCA istenir: PUBLIC_BASE_URL tanimli degilse (yerel kurulum, ic ag, deneme ortami) butun
    sayfalar `noindex` olur ve robots.txt taramayi kapatir. Boylece bir deneme kurulumu yanlislikla dizine girmez.
  * Mutlak adresler istegin Host basligindan URETILMEZ (Host basligi istemcinin denetimindedir); yalnizca
    yapilandirmadaki PUBLIC_BASE_URL kullanilir.
  * API yanitlari (analiz sonuclari, kayitlar, yonetim) hicbir kosulda dizine eklenmez.
"""

import html
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from backend.config import settings

HEAD_PLACEHOLDER = "<!--MIHENK_SEO_HEAD-->"
# Dizine eklenmemesi gereken yollar: API uc noktalari ve yonetim
PRIVATE_PREFIXES = ("/admin", "/analyze", "/ioc", "/campaign", "/lists", "/brands", "/health", "/docs", "/redoc",
                    "/openapi.json")
SITE_NAME = "Mihenk"
TITLE = "Mihenk — Oltalama (Phishing) URL ve Alan Adı Analizi"
DESCRIPTION = ("Şüpheli bir bağlantıyı ya da alan adını ücretsiz sorgulayın. Mihenk, sayfanın taklit ettiği kurumu, "
               "bilgi toplayan formları ve yönlendirme zincirini inceler; 0–100 arası gerekçeli bir risk skoru ve "
               "TLP işaretli tehdit istihbaratı brifingi üretir.")
FEATURES = [
    "URL ve alan adı için açıklanabilir 0–100 risk skoru",
    "Türkiye'deki banka, kargo, e-ticaret ve kamu kurumlarının taklitlerini tanıyan kurum kataloğu",
    "Yönlendirme zinciri, çerçeve ve form incelemesi (JavaScript çalıştırılmadan)",
    "İncelenemeyen sayfalar için açık “Karar verilemedi” sonucu",
    "TLP işaretli, yazdırılabilir tehdit istihbaratı brifingi",
    "Analist izin ve engel listeleri",
]


def site_url() -> str:
    """Yapilandirilmis genel adres ('https://ornek.com', sonda '/' yok) ya da bos dizge."""
    value = (getattr(settings, "PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if not value:
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.path or parts.query or parts.fragment \
            or parts.username or any(ch in value for ch in "<>\"' \t\r\n"):
        return ""
    return value


def indexable() -> bool:
    return bool(site_url())


def is_private_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in PRIVATE_PREFIXES)


def structured_data(base: str) -> dict:
    """schema.org: WebSite + WebApplication. Puan / yorum gibi dogrulanamayan alanlar bilincli olarak yoktur."""
    return {
        "@context": "https://schema.org",
        "@graph": [
            {"@type": "WebSite", "@id": base + "/#website", "url": base + "/", "name": SITE_NAME,
             "description": DESCRIPTION, "inLanguage": "tr"},
            {"@type": "WebApplication", "@id": base + "/#app", "name": SITE_NAME, "url": base + "/",
             "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "JavaScript",
             "inLanguage": "tr", "isAccessibleForFree": True, "description": DESCRIPTION, "featureList": FEATURES,
             "image": base + "/og-image.png", "isPartOf": {"@id": base + "/#website"}},
        ],
    }


def head_tags() -> str:
    """index.html basligina eklenen etiketler (robots, canonical, og:url / og:image, JSON-LD)."""
    base = site_url()
    if not base:
        return '<meta name="robots" content="noindex, nofollow" />'
    esc = html.escape(base, quote=True)
    data = json.dumps(structured_data(base), ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    return "\n    ".join([
        '<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1" />',
        f'<link rel="canonical" href="{esc}/" />',
        f'<meta property="og:url" content="{esc}/" />',
        f'<meta property="og:image" content="{esc}/og-image.png" />',
        '<meta property="og:image:width" content="1200" />',
        '<meta property="og:image:height" content="630" />',
        f'<meta name="twitter:image" content="{esc}/og-image.png" />',
        f'<script type="application/ld+json">{data}</script>',
    ])


def render_index(text: str) -> str:
    return text.replace(HEAD_PLACEHOLDER, head_tags())


def robots_txt() -> str:
    base = site_url()
    if not base:
        return "User-agent: *\nDisallow: /\n"
    lines = ["# Mihenk: genel sayfa taranabilir; API uç noktaları ve yönetim taranmaz.", "User-agent: *", "Allow: /"]
    lines += [f"Disallow: {p}" for p in PRIVATE_PREFIXES]
    lines += ["", f"Sitemap: {base}/sitemap.xml", ""]
    return "\n".join(lines)


def sitemap_xml(lastmod: float | None = None) -> str | None:
    base = site_url()
    if not base:
        return None
    stamp = datetime.fromtimestamp(lastmod, timezone.utc).strftime("%Y-%m-%d") if lastmod else None
    entry = f"  <url>\n    <loc>{html.escape(base)}/</loc>\n" + (f"    <lastmod>{stamp}</lastmod>\n" if stamp else "") + "  </url>\n"
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + entry + "</urlset>\n")


def llms_txt() -> str | None:
    """Dil modelleri icin kisa ozet (llms.txt onerisi). Google Arama bu dosyayi kullanmaz; bazi yapay zeka araclari okur."""
    base = site_url()
    if not base:
        return None
    features = "\n".join(f"- {f}" for f in FEATURES)
    return (f"# {SITE_NAME}\n\n> {DESCRIPTION}\n\n"
            "Mihenk, oltalama (phishing) bağlantılarını değerlendiren bir tehdit istihbaratı platformudur. Kullanıcı bir URL "
            "ya da alan adı girer; platform sayfayı JavaScript çalıştırmadan indirir, taklit edilen kurumu, bilgi toplayan "
            "formları ve yönlendirmeleri inceler ve gerekçeleriyle birlikte bir risk skoru üretir. Düşük skor, adresin "
            "güvenli olduğu anlamına gelmez; incelenemeyen sayfalar “Karar verilemedi” olarak bildirilir.\n\n"
            f"## Özellikler\n\n{features}\n\n## Bağlantılar\n\n- [Gösterge analizi]({base}/): URL ve alan adı sorgulama\n")


NOT_FOUND_HTML = ("<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\">"
                  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Sayfa bulunamadı — Mihenk</title>"
                  "</head><body><h1>Sayfa bulunamadı</h1><p>Aradığınız adres bu sitede yok.</p>"
                  "<p><a href=\"/\">Mihenk ana sayfasına dön</a></p></body></html>")
