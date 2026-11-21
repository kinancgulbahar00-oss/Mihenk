"""Guvenlik zafiyet raporu (v1.1) bulgulari icin regresyon testleri. Ag erisimi gerektirmez.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import os

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core.analyzer_interface import InvalidTargetError, analyze_url_pipeline, parse_url_components
from backend.core.cache import BoundedCache
from backend.core.netguard import BlockedAddressError, is_public_ip, resolve_public
from backend.core.security import hash_password, verify_password

PASSWORD = os.environ["ADMIN_PASSWORD"]
LEGACY_STATIC_TOKEN = "cti-admin-secure-token-2026"


@pytest.fixture()
def client():
    from backend.main import app
    from backend.api import routes_auth, routes_analyze

    routes_auth._login_failures._events.clear()
    routes_analyze._rate_limiter._events.clear()
    with TestClient(app) as c:
        yield c


def login(client, password=PASSWORD):
    return client.post("/admin/login", json={"password": password})


# --- F-05: URL ayristirma farki -------------------------------------------------

@pytest.mark.parametrize("raw, host", [
    # Tarayici '\\' karakterini yol ayiricisi sayar: gercek sunucu '@' oncesidir
    ("https://oltalama-sunucusu.example\\@garantibbva.com.tr/giris", "oltalama-sunucusu.example"),
    ("oltalama-sunucusu.example\\@garantibbva.com.tr", "oltalama-sunucusu.example"),
    ("https:\\\\oltalama-sunucusu.example", "oltalama-sunucusu.example"),
    ("http:oltalama-sunucusu.example/x", "oltalama-sunucusu.example"),
    # '@' oncesi kullanici bilgisidir: gercek sunucu '@' sonrasidir
    ("https://garantibbva.com.tr@oltalama-sunucusu.example/", "oltalama-sunucusu.example"),
    ("http://garantibbva.com.tr%2f@oltalama-sunucusu.example/", "oltalama-sunucusu.example"),
    # Alan adindaki yuzde kodlari ve tam genislikli karakterler tarayicida cozulur
    ("http://oltalama%2dsunucusu.example/", "oltalama-sunucusu.example"),
    ("http://ｇａｒａｎｔｉ.example/", "garanti.example"),
    # Sayisal IPv4 bicimleri
    ("http://2130706433/", "127.0.0.1"),
    ("http://0x7f.1/", "127.0.0.1"),
    ("http://0177.0.0.1/", "127.0.0.1"),
    ("HTTPS://GarantiBBVA.com.TR.:443/a?b#c", "garantibbva.com.tr"),
])
def test_parser_matches_browser_host(raw, host):
    assert parse_url_components(raw)["domain"] == host


@pytest.mark.parametrize("raw", [
    "javascript:alert(1)",
    "ftp://example.com/",
    "data:text/html,hi",
    "http://exa mple.com/",
    "http://example.com:99999/",
    "http://exa%20mple.com/",
    "http://0x1ff.1.1.1/",
])
def test_parser_rejects_ambiguous_input(raw):
    with pytest.raises(InvalidTargetError):
        parse_url_components(raw)


def test_tab_and_newline_are_stripped_like_browsers():
    """B-11: tarayici adresteki sekme/satir sonunu atar; 'example.com<TAB>.evil' example.com.evil'e gider.
    Ayni kural uygulanir ve adres gizleme bayragi tasinir (reddedilmez, karar verilir)."""
    parsed = parse_url_components("http://example.com\t.evil/")
    assert parsed["domain"] == "example.com.evil" and parsed["stripped_whitespace"]


def test_userinfo_disables_whitelist_and_official_discount():
    from backend.core.scoring import collect_signals

    plain = parse_url_components("https://garantibbva.com.tr/")
    _, mitigations, _ = collect_signals({**plain, "url": "https://garantibbva.com.tr/"}, {"resolved": True, "page": {}})
    assert any(m["key"] == "official" for m in mitigations), "on kosul: resmi adres indirimi normalde uygulanir"

    tricked = parse_url_components("https://oltalama.example@garantibbva.com.tr/")
    assert tricked["userinfo"] is True
    _, mitigations, _ = collect_signals({**tricked, "url": "https://x"}, {"resolved": True, "page": {}})
    assert not any(m["key"] == "official" for m in mitigations)


# --- F-06: SSRF -------------------------------------------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "172.16.0.1",
                                "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1", "fc00::1"])
def test_private_addresses_are_not_public(ip):
    assert not is_public_ip(ip)
    with pytest.raises(BlockedAddressError):
        resolve_public(ip)


def test_public_address_allowed():
    assert is_public_ip("1.1.1.1")
    assert resolve_public("1.1.1.1") == "1.1.1.1"


def test_localhost_name_blocked():
    with pytest.raises(BlockedAddressError):
        resolve_public("localhost")


@pytest.mark.parametrize("raw", ["http://169.254.169.254/latest/meta-data/", "10.0.0.5", "http://2130706433/",
                                 "http://[::1]/", "localhost"])
def test_pipeline_rejects_internal_targets_before_connecting(raw, monkeypatch):
    import backend.core.analyzer_interface as ai

    def fail(*a, **k):
        raise AssertionError("ic ag hedefine baglanti denenmemeli")

    monkeypatch.setattr(ai, "probe_tls", fail)
    monkeypatch.setattr(ai, "probe_page", fail)
    monkeypatch.setattr(ai, "lookup_domain_registration", fail)
    with pytest.raises(InvalidTargetError):
        analyze_url_pipeline(raw, db=None)


def test_analyze_endpoint_returns_400_for_internal_target(client):
    r = client.post("/analyze/url", json={"url": "http://169.254.169.254/"})
    assert r.status_code == 400
    assert "İç ağ" in r.json()["detail"]


# --- F-08: girdi boyutu, hiz siniri, onbellek ---------------------------------------

def test_analyze_rejects_oversized_input(client):
    r = client.post("/analyze/url", json={"url": "a" * 3000 + ".com"})
    assert r.status_code == 422


def test_analyze_rate_limited(client):
    from backend.api import routes_analyze

    limit = routes_analyze._rate_limiter.limit
    codes = [client.post("/analyze/url", json={"url": "http://10.0.0.1/"}).status_code for _ in range(limit + 1)]
    assert codes[:limit] == [400] * limit
    assert codes[-1] == 429


def test_bounded_cache_evicts():
    cache = BoundedCache(maxsize=100)
    for i in range(5000):
        cache[f"k{i}"] = (0, i)
    assert len(cache) == 100


# --- F-01, F-03, F-09: kimlik dogrulama ----------------------------------------

def test_legacy_static_token_rejected(client):
    for headers in ({"X-Admin-Token": LEGACY_STATIC_TOKEN}, {"Authorization": f"Bearer {LEGACY_STATIC_TOKEN}"}):
        assert client.get("/admin/verify", headers=headers).status_code == 401
    client.cookies.set("mihenk_admin", LEGACY_STATIC_TOKEN)
    assert client.get("/admin/verify").status_code == 401


def test_login_issues_random_httponly_session_and_logout_revokes(client):
    r = login(client)
    assert r.status_code == 200
    assert "token" not in r.json()
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    token = client.cookies.get("mihenk_admin")
    assert token and len(token) >= 40

    assert client.get("/admin/verify").status_code == 200
    assert client.post("/admin/logout").status_code == 204

    client.cookies.set("mihenk_admin", token)
    assert client.get("/admin/verify").status_code == 401


def test_sessions_are_unique_per_login(client):
    login(client)
    first = client.cookies.get("mihenk_admin")
    client.cookies.clear()
    login(client)
    assert client.cookies.get("mihenk_admin") != first


def test_default_and_dotless_i_passwords_rejected(client):
    assert login(client, "yıldızdanselamlar").status_code == 401
    assert login(client, "yildizdanselamlar").status_code == 401


def test_login_bruteforce_throttled(client):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert login(client, "wrong-password").status_code == 401
    r = login(client)  # dogru parola bile sinir dolunca reddedilir
    assert r.status_code == 429
    assert "retry-after" in r.headers


def test_startup_refuses_missing_or_weak_password(monkeypatch):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "ADMIN_PASSWORD_HASH", "")
    for bad in ("", "yıldızdanselamlar", "short"):
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", bad)
        with pytest.raises(routes_auth.SecurityConfigError):
            routes_auth.configure_admin_credentials()


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("correct horse battery stapl", encoded)
    assert "correct" not in encoded


def test_cross_origin_state_change_rejected(client):
    login(client)
    r = client.post("/lists", json={"list_type": "whitelist", "pattern": "evil.example"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


# --- F-07, F-15: yetkilendirme ------------------------------------------------------

@pytest.mark.parametrize("path", ["/admin/stats", "/lists", "/lists?list_type=whitelist", "/ioc/1",
                                  "/ioc/1/related", "/campaign/1"])
def test_sensitive_endpoints_require_admin(client, path):
    assert client.get(path).status_code == 401


def test_admin_can_manage_lists(client):
    login(client)
    r = client.post("/lists", json={"list_type": "blacklist", "pattern": "kotu-ornek.example"})
    assert r.status_code == 201
    assert any(i["pattern"] == "kotu-ornek.example" for i in client.get("/lists").json())
    assert client.delete(f"/lists/{r.json()['id']}").status_code == 204
    assert client.get("/admin/stats").status_code == 200


def test_unknown_campaign_returns_404(client):
    login(client)
    assert client.get("/campaign/999999").status_code == 404


# --- F-02: dizin asimi ------------------------------------------------------------

@pytest.mark.parametrize("path", ["/%2e%2e/backend/config.py", "/..%2fbackend%2fconfig.py",
                                  "/%2e%2e/%2e%2e/etc/passwd", "/%2e%2e/.env", "/assets/..%2f..%2fbackend/main.py"])
def test_spa_route_does_not_escape_dist(client, path):
    from backend.main import FRONTEND_DIST

    r = client.get(path)
    assert "BaseSettings" not in r.text and "root:" not in r.text and "FastAPI" not in r.text
    if FRONTEND_DIST.is_dir() and r.status_code == 200:
        assert r.text == (FRONTEND_DIST / "index.html").read_text(encoding="utf-8")


# --- F-10, F-12, F-14: CORS, hata mesajlari, basliklar -----------------------------

def test_cors_does_not_reflect_foreign_origin(client):
    r = client.options("/admin/verify", headers={"Origin": "https://evil.example",
                                                  "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers
    r = client.get("/brands", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_security_headers_and_docs_disabled(client):
    r = client.get("/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "referrer-policy" in r.headers
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = client.get(path)
        assert r.status_code in (404, 200)
        assert "swagger" not in r.text.lower() and '"openapi"' not in r.text


def test_internal_errors_are_not_leaked(client, monkeypatch):
    import backend.api.routes_analyze as ra

    def boom(*a, **k):
        raise RuntimeError("SELECT secret_column FROM iocs -- psycopg2 detay")

    monkeypatch.setattr(ra, "analyze_url_pipeline", boom)
    r = client.post("/analyze/url", json={"url": "example.com"})
    assert r.status_code == 500
    assert "SELECT" not in r.text and "psycopg2" not in r.text
    assert "Olay kimliği" in r.json()["detail"]
