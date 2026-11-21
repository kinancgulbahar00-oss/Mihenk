"""SEO: robots.txt, sitemap.xml, llms.txt, index.html basligi, gercek 404 ve dizine eklenme denetimi."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core import seo
from backend.main import FRONTEND_DIST, app

BASE = "https://mihenk.example.com"
needs_dist = pytest.mark.skipif(not (FRONTEND_DIST / "index.html").is_file(), reason="frontend derlenmemis")


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def public(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", BASE + "/", raising=False)


@pytest.mark.parametrize("value", ["", "mihenk.example.com", "ftp://x.com", "https://x.com/yol", "https://x.com?a=1",
                                   "https://u:p@x.com", "https://x.com\"><script>", "https://"])
def test_invalid_or_missing_base_url_means_not_indexable(monkeypatch, value):
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", value, raising=False)
    assert seo.site_url() == "" and not seo.indexable()
    assert seo.robots_txt() == "User-agent: *\nDisallow: /\n"
    assert seo.sitemap_xml() is None and seo.llms_txt() is None
    assert seo.head_tags() == '<meta name="robots" content="noindex, nofollow" />'


def test_private_install_is_never_indexed(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "", raising=False)
    r = client.get("/robots.txt")
    assert r.status_code == 200 and "Disallow: /\n" in r.text and "Sitemap" not in r.text
    assert client.get("/sitemap.xml").status_code == 404 and client.get("/llms.txt").status_code == 404
    assert client.get("/health").headers["x-robots-tag"] == "noindex, nofollow"


def test_public_robots_sitemap_and_llms(client, public):
    r = client.get("/robots.txt")
    assert r.headers["content-type"].startswith("text/plain")
    assert "Allow: /" in r.text and f"Sitemap: {BASE}/sitemap.xml" in r.text
    for path in ("/admin", "/analyze", "/ioc", "/campaign", "/lists", "/brands"):
        assert f"Disallow: {path}\n" in r.text
    r = client.get("/sitemap.xml")
    assert r.status_code == 200 and "xml" in r.headers["content-type"]
    assert re.findall(r"<loc>(.*?)</loc>", r.text) == [BASE + "/"]
    r = client.get("/llms.txt")
    assert r.status_code == 200 and r.text.startswith("# Mihenk") and BASE + "/" in r.text


def test_host_header_never_reaches_absolute_urls(client, public):
    for path in ("/robots.txt", "/sitemap.xml", "/llms.txt", "/"):
        r = client.get(path, headers={"Host": "saldirgan.example"})
        assert "saldirgan.example" not in r.text


def test_api_responses_are_never_indexed_even_when_public(client, public):
    assert client.get("/health").headers["x-robots-tag"] == "noindex, nofollow"
    assert client.get("/brands").headers.get("x-robots-tag") == "noindex, nofollow"


@needs_dist
def test_index_carries_seo_tags_in_initial_html(client, public):
    r = client.get("/")
    assert r.status_code == 200 and "x-robots-tag" not in r.headers and r.headers["cache-control"] == "no-cache"
    text = r.text
    assert seo.HEAD_PLACEHOLDER not in text
    assert '<meta name="robots" content="index, follow' in text
    assert f'<link rel="canonical" href="{BASE}/" />' in text
    assert f'<meta property="og:image" content="{BASE}/og-image.png" />' in text
    assert re.search(r"<title>[^<]{30,65}</title>", text)
    description = re.search(r'name="description"\s+content="([^"]+)"', text).group(1)
    assert 120 <= len(description) <= 260
    data = json.loads(re.search(r'<script type="application/ld\+json">(.*?)</script>', text, re.S).group(1))
    types = {node["@type"] for node in data["@graph"]}
    assert types == {"WebSite", "WebApplication"}
    # Dogrulanamayan puan / yorum alani uretilmez
    assert "aggregateRating" not in json.dumps(data) and "review" not in json.dumps(data).lower()
    # Ilk HTML, JavaScript calismadan da sayfanin ne oldugunu anlatir: tek <h1> ve aciklayici metin
    body = text.split("<body", 1)[1]
    assert len(re.findall(r"<h1[\s>]", body)) == 1 and "Nasıl çalışır?" in body and "Karar verilemedi" in body


@needs_dist
def test_index_is_noindex_without_public_url(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_BASE_URL", "", raising=False)
    r = client.get("/")
    assert '<meta name="robots" content="noindex, nofollow" />' in r.text and 'rel="canonical"' not in r.text
    assert r.headers["x-robots-tag"] == "noindex, nofollow"


@needs_dist
def test_unknown_path_is_a_real_404_not_the_app_shell(client, public):
    for path in ("/olmayan-sayfa", "/wp-login.php", "/analiz/eski"):
        r = client.get(path)
        assert r.status_code == 404 and 'content="noindex"' in r.text and "/src/main" not in r.text and "assets/index" not in r.text
    assert client.get("/index.html").status_code == 200


@needs_dist
def test_static_assets_and_icons(client, public):
    for path in ("/logo.jpg", "/og-image.png", "/site.webmanifest"):
        assert client.get(path).status_code == 200, path
    asset = next((FRONTEND_DIST / "assets").glob("*.js"))
    r = client.get(f"/assets/{asset.name}")
    assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
