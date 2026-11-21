"""Guvenlik zafiyet raporu (2) — Y-01..Y-09 icin regresyon testleri. Ag erisimi gerektirmez.

Calistirma:  py -3.11 -m pytest backend/tests -q
"""

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import settings
from backend.core.analyzer_interface import (
    InvalidTargetError, analyze_url_pipeline, check_list_match, extract_host, parse_url_components,
)
from backend.core.brands import owner_brand, catalog, homograph_of, official_brand
from backend.core.hostnames import InvalidHostError, to_ascii
from backend.core.scoring import collect_signals, score_signals

PASSWORD = os.environ["ADMIN_PASSWORD"]
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def client():
    from backend.main import app
    from backend.api import routes_auth, routes_analyze

    routes_auth._login_failures._events.clear()
    routes_auth._login_global._events.clear()
    routes_analyze._rate_limiter._events.clear()
    with TestClient(app) as c:
        yield c


def login(client, password=PASSWORD):
    return client.post("/admin/login", json={"password": password})


def score_of(raw, page=None, age=None):
    parsed = parse_url_components(raw)
    url = f"{parsed['scheme'] or 'https'}://{parsed['authority']}{parsed['rest']}"
    signals, mitigations, context = collect_signals(
        {**parsed, "url": url}, {"resolved": True, "page": page or {}, "age_days": age})
    score, level, reasons = score_signals(signals, mitigations)
    return score, level, reasons, context


PHISHING_PAGE = {
    "status": "ok", "title": "Türkiye İş Bankası - İnternet Şubesi",
    "identity": ["Türkiye İş Bankası - İnternet Şubesi"], "logos": [], "text": "İşCep giriş",
    "password_input": True, "card_input": True, "tckn_input": True,
    "fields": ["Şifre", "Kart bilgisi", "T.C. kimlik no"],
}


# --- Y-01: benzer harfli alan adlari resmi adres sayilmamali -------------------

@pytest.mark.parametrize("raw", [
    "http://işbank.com/giris",
    "http://akbánk.com/giris",
    "http://аkbank.com/giris",          # Kiril 'а'
    "https://garantıbbva.com.tr/",       # noktasiz ı
    "https://login.işbank.com/",
])
def test_homograph_is_not_official_and_is_critical(raw):
    page = dict(PHISHING_PAGE, final_host=parse_url_components(raw)["domain"])
    score, level, reasons, context = score_of(raw, page=page)
    assert not any("resmi alan adı" in r["rule_name"] for r in reasons)
    assert any("Benzer harfle resmi adres taklidi" in r["rule_name"] for r in reasons)
    assert score > 75 and level == "CRITICAL"
    assert context["target_brand"]


def test_homograph_without_page_still_critical():
    score, level, reasons, _ = score_of("http://işbank.com/giris")
    assert score > 75
    assert parse_url_components("http://işbank.com/giris")["domain"] == "xn--ibank-jdb.com"


def test_homograph_domain_shown_as_punycode_and_punycode_signal_fires():
    _, _, reasons, _ = score_of("http://akbánk.com/")
    assert any(r["rule_name"] == "Punycode (IDN) alan adı" for r in reasons)


VARIANTS = {"a": ["á", "а"], "e": ["é", "е"], "o": ["ö", "о"], "i": ["ı", "í"], "u": ["ü"],
            "c": ["ç", "с"], "s": ["ş"], "g": ["ğ"], "p": ["р"]}


def _variants(domain):
    label, _, rest = domain.partition(".")
    for i, ch in enumerate(label):
        for fake in VARIANTS.get(ch, []):
            yield label[:i] + fake + label[i + 1:] + "." + rest


def test_no_lookalike_of_any_catalog_domain_is_official():
    from backend.core.brands import is_restricted

    checked = 0
    for brand in catalog()["brands"]:
        for domain in brand["domains"]:
            # .gov.tr gibi kisitli uzantilarda alan adini yalnizca yetkili kurum kaydedebilir
            if is_restricted(domain):
                continue
            for variant in list(_variants(domain))[:4]:
                a = to_ascii(variant)
                assert official_brand(a) is None, (variant, a)
                assert official_brand(variant) is None, variant
                assert homograph_of(a) is not None, (variant, a)
                checked += 1
    assert checked > 300


def test_real_official_domains_stay_official():
    for brand in catalog()["brands"]:
        for domain in brand["domains"]:
            # B-06: kullanici icerigi barindiran platformlarda guven yalnizca listelenen adlara verilir;
            # digerlerinin sahibi yine bilinir
            if brand.get("trusted_hosts") is None:
                assert official_brand(domain) is not None, domain
            else:
                assert owner_brand(domain) is not None, domain
            assert homograph_of(domain) is None, domain
        for host in brand.get("trusted_hosts") or []:
            if "*" not in host:
                assert official_brand(host) is not None, host


def test_fake_gov_suffix_with_lookalike_letter():
    # Kiril 'о' ile 'gоv.tr': kisitli uzanti taklidi
    score, _, reasons, _ = score_of("https://e-devlet.gоv.tr/giris")
    assert score > 75
    assert not any(r["rule_name"] == "Kısıtlı resmi uzantı" for r in reasons)


# --- Y-06: 'ß' tarayicidaki gibi korunmali -------------------------------------

def test_sharp_s_is_kept_like_browsers():
    assert parse_url_components("https://sunexpreß.com/")["domain"] == "xn--sunexpre-xya.com"
    assert extract_host("sunexpreß.com") == "xn--sunexpre-xya.com"
    assert to_ascii("faß.de") == "xn--fa-hia.de"
    assert to_ascii("ΣΊΣΥΦΟΣ.com").startswith("xn--")


def test_uts46_canonicalization_matches_browser_rules():
    assert to_ascii("EXAMPLE.com") == "example.com"
    assert to_ascii("foo_bar.example.com") == "foo_bar.example.com"   # tarayici kabul eder
    for bad in ("xn--zz.com", "a..b", "xn--abc-.com"):
        with pytest.raises(InvalidHostError):
            to_ascii(bad)
    with pytest.raises(InvalidTargetError):
        parse_url_components("http://xn--zz.com/")


def test_sharp_s_does_not_inherit_whitelist():
    from backend.models.database import SessionLocal, init_db
    from backend.models.list_model import ListModel

    init_db()
    db = SessionLocal()
    try:
        rule = ListModel(list_type="whitelist", entry_type="domain", pattern="sunexpress.com")
        db.add(rule)
        db.commit()
        try:
            parsed = parse_url_components("https://sunexpreß.com/")
            assert check_list_match(db, parsed["domain"], parsed["authority"] + parsed["rest"], "whitelist") is None
            parsed = parse_url_components("https://www.sunexpress.com/")
            assert check_list_match(db, parsed["domain"], parsed["authority"] + parsed["rest"], "whitelist") is not None
        finally:
            db.delete(rule)
            db.commit()
    finally:
        db.close()


# --- Y-02: yavas hedef analiz hizmetini kilitlememeli -------------------------

class _SlowServer:
    """Her baglantida baslik ya da govdeyi cok yavas gonderen yerel sunucu."""

    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.recv(4096)
            if self.mode == "body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n")
                payload = b"<"
            else:
                payload = b"H"
            while not self.stop.is_set():
                conn.sendall(payload)
                time.sleep(0.3)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()


@pytest.mark.parametrize("mode", ["body", "headers"])
def test_slow_target_is_cut_at_deadline(mode, monkeypatch):
    from backend.core import netguard, page_probe

    server = _SlowServer(mode)
    monkeypatch.setattr(page_probe, "resolve_public", lambda host, timeout=4: "127.0.0.1")
    monkeypatch.setattr(netguard, "is_public_ip", lambda ip: True)
    monkeypatch.setattr(page_probe, "ALLOWED_PORTS", (None, 80, 443, server.port))
    try:
        started = time.monotonic()
        # Sure dolunca ya hata ya da o ana kadar gelen kismi icerik doner; onemli olan
        # cagrinin butceyi asmamasi (eskiden 32 KB dolana kadar saatlerce bekliyordu)
        try:
            page_probe._fetch_once(f"http://slow.example:{server.port}/", time.monotonic() + 1.5)
        except page_probe._FetchError:
            pass
        assert time.monotonic() - started < 3.0
    finally:
        server.close()


def test_analysis_timeout_returns_504_and_frees_slot(client, monkeypatch):
    import backend.api.routes_analyze as ra

    def slow(*a, **k):
        time.sleep(1.5)
        raise InvalidTargetError("bitti")

    monkeypatch.setattr(ra, "analyze_url_pipeline", slow)
    monkeypatch.setattr(settings, "ANALYZE_TIMEOUT_SECONDS", 1)
    r = client.post("/analyze/url", json={"url": "example.com"})
    assert r.status_code == 504
    # Yuva is gercekten bitince birakilir
    deadline = time.monotonic() + 3
    while ra._client_inflight and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not ra._client_inflight
    assert ra._concurrency._value == ra._MAX_CONCURRENT


def test_single_client_cannot_hold_all_slots():
    import backend.api.routes_analyze as ra

    assert ra._acquire_client_slot("198.51.100.7")
    assert not ra._acquire_client_slot("198.51.100.7")
    assert ra._acquire_client_slot("198.51.100.8")
    ra._release_client_slot("198.51.100.7")
    ra._release_client_slot("198.51.100.8")
    assert ra._acquire_client_slot("198.51.100.7")
    ra._release_client_slot("198.51.100.7")
    assert not ra._client_inflight


def test_dns_resolution_does_not_touch_global_socket_timeout(monkeypatch):
    from backend.core import netguard

    socket.setdefaulttimeout(None)
    monkeypatch.setattr(netguard.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])
    assert netguard.resolve_public("example.com", timeout=1) == "93.184.216.34"
    assert socket.getdefaulttimeout() is None

    def hang(*a, **k):
        time.sleep(2)
        return []

    monkeypatch.setattr(netguard.socket, "getaddrinfo", hang)
    started = time.monotonic()
    assert netguard.resolve_public("slow-dns.example", timeout=0.3) is None
    assert time.monotonic() - started < 1.0


# --- Y-03: govde boyutu sinirli, 422 girdiyi geri gondermez --------------------

def test_large_body_rejected_with_413(client):
    r = client.post("/analyze/url", content=b'{"url":"' + b"a" * 20_000 + b'"}',
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    r = client.post("/admin/login", content=b"x" * 50_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_chunked_large_body_rejected_with_413(client):
    def gen():
        yield b'{"url":"'
        for _ in range(40):
            yield b"a" * 1024
        yield b'"}'

    r = client.post("/analyze/url", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_validation_error_does_not_echo_input(client):
    marker = "GERI-YANSIMA-" + "b" * 3000
    r = client.post("/analyze/url", json={"url": marker})
    assert r.status_code == 422
    assert "GERI-YANSIMA" not in r.text and '"input"' not in r.text


def test_rate_limit_applies_before_body_validation(client):
    codes = [client.post("/analyze/url", json={"url": "a" * 3000}).status_code for _ in range(25)]
    assert codes[0] == 422
    assert 429 in codes


def test_compose_has_resource_limits_and_caddy_body_limit():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("mem_limit:") >= 3 and compose.count("pids_limit:") >= 3
    caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "request_body" in caddy and "max_size" in caddy


# --- Y-04: imajlar surum + ozetle sabitli --------------------------------------

def test_images_are_pinned_by_digest():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    images = [line.split("image:", 1)[1].strip() for line in compose.splitlines()
              if line.strip().startswith("image:")]
    external = [i for i in images if not i.startswith("mihenk-backend")]
    assert external and all("@sha256:" in i for i in external), external
    assert not any(i.startswith("caddy:2.8") for i in external)
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    froms = [l for l in dockerfile.splitlines() if l.startswith("FROM ")]
    assert froms and all("@sha256:" in l for l in froms)


# --- Y-05: giris sinirlayicisi atomik ------------------------------------------

def test_concurrent_logins_cannot_exceed_limit(client):
    def attempt(_):
        return client.post("/admin/login", json={"password": "yanlis-parola-1234567"}).status_code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(attempt, range(40)))
    assert codes.count(401) <= settings.LOGIN_MAX_FAILURES, codes
    assert codes.count(429) >= 40 - settings.LOGIN_MAX_FAILURES


def test_global_login_limit_independent_of_ip(client, monkeypatch):
    # Z-03 ile degisti: genel esik asildiginda giris REDDEDILMEZ, yavaslatilir. Esik IP'den
    # bagimsiz sayilmaya devam eder; esigi asan denemeler gecikmeli olarak degerlendirilir.
    from backend.api import routes_auth
    from backend.core.security import RateLimiter

    monkeypatch.setattr(routes_auth, "_login_global", RateLimiter(limit=3, window=3600))
    monkeypatch.setattr(routes_auth, "_login_failures", RateLimiter(limit=100, window=900))
    monkeypatch.setattr(settings, "LOGIN_GLOBAL_DELAY_SECONDS", 0.3)
    timings = []
    for _ in range(5):
        started = time.monotonic()
        timings.append((login(client, "yanlis-parola-1234567").status_code, time.monotonic() - started))
    assert [code for code, _ in timings] == [401] * 5
    assert all(elapsed >= 0.3 for _, elapsed in timings[3:])
    assert login(client).status_code == 200


def test_successful_login_still_works_after_failures(client):
    for _ in range(3):
        assert login(client, "yanlis-parola-1234567").status_code == 401
    assert login(client).status_code == 200


# --- Y-07: izin listesi kalip dogrulamasi --------------------------------------

@pytest.mark.parametrize("pattern", ["com.tr", "example", "com", "gov.tr", "github.io", "vercel.app", "co.uk"])
def test_overbroad_patterns_rejected(client, pattern):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "whitelist", "entry_type": "domain", "pattern": pattern})
    assert r.status_code == 422, r.text
    assert isinstance(r.json()["detail"], str)


def test_long_pattern_rejected_not_500(client):
    assert login(client).status_code == 200
    r = client.post("/lists", json={"list_type": "blacklist", "entry_type": "url",
                                    "pattern": "ornek.com/" + "a" * 1100})
    assert r.status_code == 422


def test_valid_patterns_are_canonicalized(client):
    assert login(client).status_code == 200
    created = []
    try:
        for entry_type, pattern, expected in [
            ("domain", "kullanici.github.io", "kullanici.github.io"),
            ("domain", "https://işbank.com/giris", "xn--ibank-jdb.com"),
            ("ip", "203.0.113.9", "203.0.113.9"),
            # Z-06: alan adi kucuk harfe cevrilir, yolun harf buyuklugu korunur
            ("url", "HTTPS://Ornek.com.tr/Kampanya", "ornek.com.tr/Kampanya"),
        ]:
            r = client.post("/lists", json={"list_type": "blacklist", "entry_type": entry_type, "pattern": pattern})
            assert r.status_code == 201, r.text
            assert r.json()["pattern"] == expected
            created.append(r.json()["id"])
    finally:
        for item_id in created:
            client.delete(f"/lists/{item_id}")


# --- Y-08: vekil basliklarina yalnizca vekilden guven --------------------------

def test_proxy_headers_trusted_only_from_proxy():
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert '"--forwarded-allow-ips", "*"' not in dockerfile
    assert "FORWARDED_ALLOW_IPS=127.0.0.1" in dockerfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "FORWARDED_ALLOW_IPS: ${PROXY_IP" in compose
    assert "ipv4_address: ${PROXY_IP" in compose


# --- Y-09: ek gozlemler ---------------------------------------------------------

@pytest.mark.parametrize("weak", ["aaaaaaaaaaaa", "121212121212", "abcdefghijklmn"])
def test_low_entropy_password_refused(weak, monkeypatch):
    from backend.api import routes_auth

    monkeypatch.setattr(settings, "ADMIN_PASSWORD_HASH", "")
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", weak)
    with pytest.raises(routes_auth.SecurityConfigError):
        routes_auth.configure_admin_credentials()
    monkeypatch.setattr(settings, "ADMIN_PASSWORD", PASSWORD)
    routes_auth.configure_admin_credentials()


def test_boundary_length_rejected_before_analysis(monkeypatch):
    import backend.core.analyzer_interface as ai

    monkeypatch.setattr(ai, "resolve_ip", lambda d: pytest.fail("analizden once reddedilmeliydi"))
    raw = "ornek.com/" + "a" * (2048 - len("ornek.com/"))
    assert len(raw) == 2048
    with pytest.raises(InvalidTargetError):
        analyze_url_pipeline(raw)


def test_nonstandard_port_not_fetched(monkeypatch):
    import backend.core.analyzer_interface as ai

    monkeypatch.setattr(ai, "resolve_ip", lambda d: "93.184.216.34")
    monkeypatch.setattr(ai, "lookup_domain_registration",
                        lambda d: {"age_days": None, "registrar": None, "registration_date": None})
    monkeypatch.setattr(ai, "probe_tls", lambda d, ip: "none")
    monkeypatch.setattr(ai, "check_url_reputation", lambda u: {"vt_positives": None, "vt_total": None, "status": "x"})
    monkeypatch.setattr(ai, "check_ip_reputation",
                        lambda ip: {"abuse_score": None, "reports_count": None, "status": "x"})
    monkeypatch.setattr(ai, "probe_page", lambda u: pytest.fail("standart disi port indirilmemeli"))
    # Z-07: '.example' gibi IANA kok bolgesinde olmayan uzantilar artik analiz edilmez
    result = analyze_url_pipeline("http://ornek-site.com:2525/")
    assert result["ioc_details"]["page_status"] == "port_not_allowed"
    assert any(r["rule_name"] == "Standart dışı port" for r in result["reasons"])


def test_history_is_trimmed_per_ioc(monkeypatch):
    from backend.core import retention
    from backend.models.database import SessionLocal, init_db
    from backend.models.ioc_model import AnalysisResultModel, IOCModel

    init_db()
    monkeypatch.setattr(settings, "MAX_RESULTS_PER_IOC", 3)
    db = SessionLocal()
    try:
        ioc = IOCModel(type="url", value="https://retention-test.example/", risk_score=0, risk_level="LOW")
        db.add(ioc)
        db.flush()
        for _ in range(7):
            db.add(AnalysisResultModel(ioc_id=ioc.id, risk_score=0, risk_level="LOW"))
        db.flush()
        retention.trim_history(db, ioc.id)
        db.commit()
        # Son 3 sonuc + ilk analiz (B-08: ilk ve en yuksek skorlu analiz her zaman korunur)
        assert db.query(AnalysisResultModel).filter(AnalysisResultModel.ioc_id == ioc.id).count() == 4
        db.delete(ioc)
        db.commit()
    finally:
        db.close()


def test_hash_password_docs_consistent():
    text = (ROOT / "backend" / "hash_password.py").read_text(encoding="utf-8")
    assert "$$" not in text and "TEK TIRNAK" in text
