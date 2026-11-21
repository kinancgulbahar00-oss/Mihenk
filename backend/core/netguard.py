"""Dis baglantilar icin ortak ag denetimi (SSRF korumasi).

Kural: Sunucu, analiz edilen bir adres adina yalnizca herkese acik (global) IP adreslerine
baglanir. Alan adi bir kez cozumlenir, sonuc denetlenir ve baglanti dogrudan bu IP'ye
sabitlenir; boylece denetim ile baglanti arasinda yeniden cozumleme (DNS rebinding) olmaz.
TLS'de SNI ve sertifika dogrulamasi orijinal alan adiyla yapilir.

Sure sinirlari (Y-02): soket zaman asimi her okumada yeniden baslar; saniyede bir bayt
gonderen bir sunucu zaman asimini hic doldurmaz. Bu yuzden toplam sure, sure doldugunda
soketi kapatan bir bekci (Deadline) ile soket duzeyinde zorlanir. DNS cozumlemesi de
surec genelindeki varsayilan zaman asimi degistirilmeden, sure sinirli bir is parcaciginda yapilir.
"""

import http.client
import ipaddress
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

# getaddrinfo iptal edilemez; takilan cozumlemeler sinirli bir havuzda kalir ve cagiran beklemez
_dns_pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="dns")


class BlockedAddressError(Exception):
    """Hedef ic ag, loopback, link-local veya ozel kullanimli bir adrese cozumleniyor."""


def _unwrap(ip):
    if ip.version == 6:
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            return ip.teredo[1]
    return ip


def is_public_ip(value) -> bool:
    try:
        ip = _unwrap(ipaddress.ip_address(value))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_unspecified


def resolve_public(host: str, timeout: float = 5.0) -> str | None:
    """Alan adini cozumler. Cozumlenmezse None doner.
    Cozumlenen adreslerden herhangi biri herkese acik degilse BlockedAddressError firlatir.
    Donen deger baglanti icin kullanilacak (sabitlenecek) IP adresidir; IPv4 onceliklidir."""
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        if not is_public_ip(host):
            raise BlockedAddressError(host)
        return host

    # socket.setdefaulttimeout() surec geneldir ve getaddrinfo'yu zaten sinirlamaz (Y-09)
    try:
        future = _dns_pool.submit(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
        infos = future.result(timeout=max(0.1, timeout))
    except FutureTimeout:
        future.cancel()
        return None
    except (OSError, UnicodeError, RuntimeError):
        return None

    addresses = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        return None
    if any(not is_public_ip(a) for a in addresses):
        raise BlockedAddressError(host)
    v4 = [a for a in addresses if ipaddress.ip_address(a).version == 4]
    return (v4 or addresses)[0]


def resolve_all_public(host: str, timeout: float = 3.0) -> list:
    """Alan adinin cozumlendigi TUM herkese acik adresler (IP engel kurallari icin; A-14). Cozumlenmezse
    ya da ic ag adresi iceriyorsa bos liste doner; baglanti karari icin resolve_public kullanilir."""
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return [host] if is_public_ip(host) else []
    except ValueError:
        pass
    try:
        future = _dns_pool.submit(socket.getaddrinfo, host, None, proto=socket.IPPROTO_TCP)
        infos = future.result(timeout=max(0.1, timeout))
    except (FutureTimeout, OSError, UnicodeError, RuntimeError):
        return []
    out = []
    for info in infos:
        addr = info[4][0]
        if addr not in out and is_public_ip(addr):
            out.append(addr)
    return out[:16]


def abort_socket(sock) -> None:
    """Baska bir is parcaciginda bloklanmis okuma/el sikismasini aninda sonlandirir.
    SSLSocket.shutdown yerine taban socket.shutdown kullanilir: TLS durumu degistirilmeden
    dosya tanimlayicisi kapatilir ve bekleyen recv() hemen doner."""
    if sock is None:
        return
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except (OSError, ValueError, TypeError):
        pass


class Deadline:
    """Toplam sure dolunca kaydedilen soketleri kapatan bekci (watchdog).

        with Deadline(saniye) as dl:
            sock = ...; dl.watch(sock)
            ...  # sure dolarsa bloklanan cagri OSError/bos okuma ile doner
    """

    def __init__(self, seconds: float):
        self._lock = threading.Lock()
        self._socks = []
        self.expired = False
        self._timer = threading.Timer(max(0.05, seconds), self._fire)
        self._timer.daemon = True

    def __enter__(self):
        self._timer.start()
        return self

    def __exit__(self, *exc):
        self._timer.cancel()
        return False

    def watch(self, sock):
        with self._lock:
            self._socks.append(sock)
            fired = self.expired
        if fired:
            abort_socket(sock)
        return sock

    def _fire(self):
        with self._lock:
            self.expired = True
            socks = list(self._socks)
        for sock in socks:
            abort_socket(sock)


def connect_pinned(ip: str, port: int, timeout: float) -> socket.socket:
    if not is_public_ip(ip):
        raise BlockedAddressError(ip)
    return socket.create_connection((ip, port), timeout=timeout)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Host basligi alan adini tasir, TCP baglantisi onceden denetlenmis IP'ye kurulur."""

    def __init__(self, host, pinned_ip, port=None, timeout=None, deadline=None):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._deadline = deadline

    def connect(self):
        self.sock = connect_pinned(self._pinned_ip, self.port, self.timeout)
        if self._deadline:
            self._deadline.watch(self.sock)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, pinned_ip, port=None, timeout=None, context=None, deadline=None):
        context = context or ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._ssl_context = context
        self._deadline = deadline

    def connect(self):
        sock = connect_pinned(self._pinned_ip, self.port, self.timeout)
        # SNI ve sertifika ad dogrulamasi orijinal alan adiyla. El sikismasi ayri yapilir:
        # yavas el sikismasi da bekci tarafindan kesilebilsin diye soket once kaydedilir.
        ssock = self._ssl_context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
        self.sock = ssock
        if self._deadline:
            self._deadline.watch(ssock)
        ssock.do_handshake()


# --- Hedef basina sinir ve yavas hedef karantinasi (Z-04, D-02, D-03, B-04, B-05) -----------
#
# Sure butcesi istek basinadir; yolu degistirilen her istek ayni yavas sunucuya yeni bir
# yoklama baslatabilir. Bu yuzden sinir HEDEF uzerinden de uygulanir:
#   * ayni kayitli alan adina ayni anda en fazla TARGET_MAX_CONCURRENT yoklama yapilir; katalogdaki
#     buyuk platformlar icin sinir daha yuksektir (B-04). Tek kilit yerine sayac: platformdaki yavas
#     bir adresi surekli analiz ettiren saldirgan, ayni alan adindaki diger sayfalarin incelenmesini
#     engelleyemez. Ayni ADRESE gelen ikinci istek ise suren yoklamanin sonucunu paylasir
#     (page_probe single-flight);
#   * ayni IP adresine ayni anda en fazla IP_MAX_CONCURRENT yoklama yapilir (D-03): her
#     istekte farkli bir ucretsiz alt alan adi (x.duckdns.org) kullanan saldirgan, hepsi ayni
#     sunucuya cozumlense de yuvalarin tamamini o sunucuya baglayamaz;
#   * sure butcesini KENDISI tuketen ADRES karantinaya alinir ("slow_target").
#
# Karantina karari, yavasligi gercekten gozlenen seye yazilir (D-02, B-04):
#   * anahtar tam ad + ilk yol parcasidir (sayfa) ya da tam addir (TLS). Alan adinin tamami ancak
#     birbirinden bagimsiz DOMAIN_ESCALATION_CLIENTS istemcinin DOMAIN_ESCALATION_SCOPES farkli
#     adreste gozledigi zaman asimlariyla ve o alan adinda yakin zamanda basariyla yanit veren
#     baska bir adres yoksa karantinaya alinir; katalogdaki kurumlarin alan adlari hicbir zaman;
#   * bir adim ancak kendisine en az MIN_HOP_SECONDS verilmis ve o bu sureyi doldurmussa
#     zaman asimi sayilir. Onceki adimlarin harcadigi sure yonlendirilen hedefe yazilmaz;
#   * katalogdaki bir kurumun adresi tek bir zaman asimiyla karantinaya alinmaz: kisa surede
#     FARKLI istemcilerden en az iki zaman asimi gerekir ve karantina kisa surer (ALERT kaydi);
#   * IP adresi KARANTINAYA ALINMAZ (B-05): IP adresleri paylasilir. Ayni IP'deki birkac farkli adin
#     zaman asimi IP'yi "kisitli" yapar: o IP'deki siteler incelenmeye devam eder, ancak kisa
#     butceyle ve beklemeden (D-03). Hizli yanit veren paylasimli sunucudaki siteler etkilenmez.
#
# Yavasligin bedelini hedefi gonderen istemci oder (D-03, B-04): son 10 dakikada sure butcesini
# tuketen ya da art arda uzun suren yoklamalar yaptiran istemcinin sonraki yoklamalarina kisa
# butce verilir; yuvalarin cogu doluyken de yeni yoklamalarin butcesi kisalir. Butce, analiz
# hattina ProbeContext ile tasinir.

import contextvars
import logging
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("mihenk.netguard")

SLOW_TARGET_SECONDS = 10 * 60
# Katalogdaki kurum adresleri icin: kisa karantina, en az iki bagimsiz zaman asimi (D-02)
PROTECTED_SLOW_TARGET_SECONDS = 60
PROTECTED_STRIKE_WINDOW = 2 * 60
PROTECTED_MIN_STRIKES = 2
TARGET_WAIT_SECONDS = 2.0
# Ayni kayitli alan adina ayni anda en fazla bu kadar yoklama (B-04); katalogdaki kurumlar icin daha fazla
TARGET_MAX_CONCURRENT = 4
PROTECTED_TARGET_MAX_CONCURRENT = 12
# Alan adinin tamaminin karantinasi icin gereken bagimsiz gozlem (B-04)
DOMAIN_ESCALATION_SCOPES = 3
DOMAIN_ESCALATION_CLIENTS = 3
# Bir adim ancak bu kadar sure verilip bunu kendisi doldurursa "yavas" sayilir (D-02)
MIN_HOP_SECONDS = 5.0
# Ayni IP'ye ayni anda en fazla bu kadar yoklama; bu kadar farkli adin zaman asimi IP'yi kisitlar (D-03, B-05)
IP_MAX_CONCURRENT = 4
IP_SLOW_DISTINCT_NAMES = 3
IP_STRIKE_WINDOW = 10 * 60
IP_DEGRADED_SECONDS = 10 * 60
# Kisitli IP'deki adlar icin butce (B-05): hizli siteler incelenir, yavas adlar yuva tutamaz
DEGRADED_PAGE_BUDGET_SECONDS = 3.0
# Bu sure icinde basariyla yoklanmis ad "bilinen" sayilir ve kisitli IP'de tam butce alir (A-10)
SEEN_OK_SECONDS = 24 * 60 * 60
DEGRADED_TLS_BUDGET_SECONDS = 2.0

# Sure butceleri (saniye). Varsayilan / yuk altinda / yakin zamanda zaman asimi ureten istemci icin
PAGE_BUDGET_SECONDS = 15.0
TLS_BUDGET_SECONDS = 6.0
LOADED_PAGE_BUDGET_SECONDS = 6.0
LOADED_TLS_BUDGET_SECONDS = 4.0
PENALTY_BUDGET_SECONDS = 3.0
# Yuklu sayilma esigi (dolu yuva orani) ve istemci cezasi icin gereken zaman asimi sayisi
LOAD_THRESHOLD = 0.75
CLIENT_STRIKE_WINDOW = 10 * 60
CLIENT_PENALTY_STRIKES = 2
# Butceyi asmayan ama uzun suren yoklama (B-04): bu kadar uzun suren yoklamalardan
# CLIENT_SLOW_PROBES tanesi istemciyi kisa butceye dusurur
SLOW_PROBE_SECONDS = 2.5
CLIENT_SLOW_PROBES = 4

_MAX_TRACKED_TARGETS = 10_000


class TargetBusyError(Exception):
    """Ayni hedefe (veya ayni IP'ye) baska yoklamalar suruyor."""


class SlowTargetError(Exception):
    """Hedef yakin zamanda sure butcesini asti; yeniden yoklanmaz."""


@dataclass
class ProbeContext:
    """Bir analiz isteginin yoklama butcesi ve istemcisi. Analiz hattinin is parcaciklarina
    contextvars ile tasinir; yoklamalar zaman asimini, uzun suren yoklamalari ve baglandiklari
    IP adreslerini buraya yazar."""
    client: str | None = None
    page_budget: float = PAGE_BUDGET_SECONDS
    tls_budget: float = TLS_BUDGET_SECONDS
    reason: str = "default"
    timeouts: list = field(default_factory=list)
    slow: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    # Analiz hattinin basinda dogrulanmis ad -> IP (B-11): sayfa yoklamasi ayni adi yeniden cozumlemez
    pinned: dict = field(default_factory=dict)

    def record_timeout(self, key: str) -> None:
        self.timeouts.append(key)

    def record_slow(self, key: str) -> None:
        self.slow.append(key)

    def record_ip(self, ip: str) -> None:
        if ip and ip not in self.ips and len(self.ips) < 16:
            self.ips.append(ip)


_probe_context: contextvars.ContextVar = contextvars.ContextVar("mihenk_probe_context", default=None)


def current_probe_context() -> ProbeContext | None:
    return _probe_context.get()


def set_probe_context(ctx: ProbeContext | None):
    return _probe_context.set(ctx)


def reset_probe_context(token) -> None:
    _probe_context.reset(token)


def page_budget() -> float:
    ctx = current_probe_context()
    return ctx.page_budget if ctx else PAGE_BUDGET_SECONDS


def tls_budget() -> float:
    ctx = current_probe_context()
    return ctx.tls_budget if ctx else TLS_BUDGET_SECONDS


def _prune(times: deque, window: float, now: float) -> None:
    while times and times[0] < now - window:
        times.popleft()


def _bounded(d: dict) -> None:
    if len(d) >= _MAX_TRACKED_TARGETS:
        d.clear()


class _TargetGuard:
    def __init__(self):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        # karantina: alan adi anahtari ya da "s:" + kapsam (ad/ilk-yol, TLS icin ad)
        self._slow: dict[str, float] = {}
        self._inflight: dict[str, int] = {}
        self._ip_inflight: dict[str, int] = {}
        # alan adi -> [(zaman, istemci, kapsam)], alan adi -> son basarili yoklama
        self._strikes: dict[str, list] = {}
        self._ok: dict[str, float] = {}
        # IP -> {alan adi: (zaman, istemci)}, IP -> kisitlama bitisi
        self._ip_strikes: dict[str, dict] = {}
        self._ip_degraded: dict[str, float] = {}
        self._client_strikes: dict[str, deque] = {}
        self._client_slow: dict[str, deque] = {}

    # --- karantina ---------------------------------------------------------------
    def _is_slow_locked(self, key: str, now: float) -> bool:
        until = self._slow.get(key)
        if until is None:
            return False
        if until < now:
            del self._slow[key]
            return False
        return True

    def is_slow(self, key: str, ip: str | None = None, scope: str | None = None) -> bool:
        """Alan adinin tamami ya da bu adres (kapsam) karantinada mi? IP karantinasi yoktur (B-05);
        `ip` geriye donuk uyumluluk icin kabul edilir."""
        now = time.monotonic()
        with self._lock:
            if self._is_slow_locked(key, now):
                return True
            if scope:
                if self._is_slow_locked("s:" + scope, now):
                    return True
                host = scope.split("/", 1)[0]
                if host != scope and self._is_slow_locked("s:" + host, now):
                    return True
            return False

    def _quarantine_locked(self, key: str, seconds: float, now: float) -> None:
        if len(self._slow) >= _MAX_TRACKED_TARGETS:
            for k in [k for k, v in self._slow.items() if v < now] or list(self._slow)[: _MAX_TRACKED_TARGETS // 10]:
                self._slow.pop(k, None)
        self._slow[key] = max(self._slow.get(key, 0.0), now + seconds)

    def mark_slow(self, key: str, seconds: float = SLOW_TARGET_SECONDS) -> None:
        """Hedefi dogrudan karantinaya alir (testler ve kesin durumlar icin)."""
        with self._lock:
            self._quarantine_locked(key, seconds, time.monotonic())

    def record_success(self, key: str, scope: str | None = None) -> None:
        """Alan adinda basariyla tamamlanan yoklama: alan adinin tamami karantinaya alinmaz (B-04)."""
        with self._lock:
            _bounded(self._ok)
            self._ok[key] = time.monotonic()

    def seen_ok(self, key: str) -> bool:
        """Bu alan adi yakin zamanda (SEEN_OK_SECONDS) basariyla yoklandi mi? Kisitli IP'deki kisa butce
        yalnizca daha once basariyla yanit vermemis adlara uygulanir (A-10)."""
        with self._lock:
            seen = self._ok.get(key)
            return seen is not None and seen >= time.monotonic() - SEEN_OK_SECONDS

    def record_timeout(self, key: str, ip: str | None = None, client: str | None = None,
                       protected: bool = False, scope: str | None = None) -> bool:
        """Hedefin KENDISININ sure butcesini tukettigi bir yoklama (D-02). Karantinaya alindiysa True.
        `scope` verilirse karantina o adrese yazilir (B-04); verilmezse alan adina."""
        now = time.monotonic()
        quarantined = False
        escalated = False
        q_key = ("s:" + scope) if scope else key
        with self._lock:
            _bounded(self._strikes)
            strikes = [s for s in self._strikes.get(key, []) if s[0] >= now - SLOW_TARGET_SECONDS]
            strikes.append((now, client, scope or key))
            self._strikes[key] = strikes
            if protected:
                recent = {c for t, c, sc in strikes if t >= now - PROTECTED_STRIKE_WINDOW and sc == (scope or key)}
                if len(recent) >= PROTECTED_MIN_STRIKES:
                    self._quarantine_locked(q_key, PROTECTED_SLOW_TARGET_SECONDS, now)
                    quarantined = True
            else:
                self._quarantine_locked(q_key, SLOW_TARGET_SECONDS, now)
                quarantined = True
                if scope:
                    scopes = {sc for _, _, sc in strikes}
                    clients = {c for _, c, _ in strikes if c}
                    last_ok = self._ok.get(key)
                    recent_ok = last_ok is not None and last_ok >= now - SLOW_TARGET_SECONDS
                    if (len(scopes) >= DOMAIN_ESCALATION_SCOPES and len(clients) >= DOMAIN_ESCALATION_CLIENTS
                            and not recent_ok):
                        self._quarantine_locked(key, SLOW_TARGET_SECONDS, now)
                        escalated = True

            if ip and not protected:
                _bounded(self._ip_strikes)
                names = {k: v for k, v in self._ip_strikes.get(ip, {}).items() if v[0] >= now - IP_STRIKE_WINDOW}
                names[key] = (now, client)
                self._ip_strikes[ip] = names
                if len(names) >= IP_SLOW_DISTINCT_NAMES:
                    _bounded(self._ip_degraded)
                    self._ip_degraded[ip] = now + IP_DEGRADED_SECONDS
                    logger.info("slow address degraded ip=%s distinct_names=%d budget=%ss", ip, len(names),
                                DEGRADED_PAGE_BUDGET_SECONDS)
        if quarantined:
            if protected:
                logger.warning("ALERT slow catalog address quarantined target=%s seconds=%s",
                               scope or key, PROTECTED_SLOW_TARGET_SECONDS)
            else:
                logger.info("slow target quarantined target=%s", scope or key)
            if escalated:
                logger.info("slow domain quarantined domain=%s (independent clients and addresses)", key)
        elif protected:
            logger.warning("catalog target timed out (not quarantined, single strike) target=%s client=%s",
                           scope or key, client)
        return quarantined

    def ip_degraded(self, ip: str | None) -> bool:
        if not ip:
            return False
        now = time.monotonic()
        with self._lock:
            until = self._ip_degraded.get(ip)
            if until is None:
                return False
            if until < now:
                del self._ip_degraded[ip]
                return False
            return True

    # --- istemci cezasi (D-03, B-04) ---------------------------------------------------
    def _client_events(self, store: dict, client: str | None, count: int) -> None:
        if not client:
            return
        now = time.monotonic()
        with self._lock:
            _bounded(store)
            times = store.setdefault(client, deque(maxlen=16))
            for _ in range(max(1, count)):
                times.append(now)

    def _client_count(self, store: dict, client: str | None) -> int:
        if not client:
            return 0
        now = time.monotonic()
        with self._lock:
            times = store.get(client)
            if not times:
                return 0
            _prune(times, CLIENT_STRIKE_WINDOW, now)
            if not times:
                store.pop(client, None)
            return len(times)

    def record_client_timeout(self, client: str | None, count: int = 1) -> None:
        self._client_events(self._client_strikes, client, count)

    def record_client_slow(self, client: str | None, count: int = 1) -> None:
        self._client_events(self._client_slow, client, count)

    def client_strikes(self, client: str | None) -> int:
        return self._client_count(self._client_strikes, client)

    def client_slow_probes(self, client: str | None) -> int:
        return self._client_count(self._client_slow, client)

    def budget_for(self, client: str | None, load: float = 0.0) -> ProbeContext:
        """Istemcinin bu analizdeki yoklama butcesi: yavasligin bedelini hedefi gonderen odeyecek."""
        if self.client_strikes(client) >= CLIENT_PENALTY_STRIKES:
            return ProbeContext(client, PENALTY_BUDGET_SECONDS, PENALTY_BUDGET_SECONDS, "client_penalty")
        if self.client_slow_probes(client) >= CLIENT_SLOW_PROBES:
            return ProbeContext(client, PENALTY_BUDGET_SECONDS, PENALTY_BUDGET_SECONDS, "client_slow_probes")
        if load >= LOAD_THRESHOLD:
            return ProbeContext(client, LOADED_PAGE_BUDGET_SECONDS, LOADED_TLS_BUDGET_SECONDS, "load")
        return ProbeContext(client)

    # --- yoklama hakki ---------------------------------------------------------------
    def acquire(self, key: str, wait: float | None = None, ip: str | None = None, protected: bool = False,
                scope: str | None = None):
        """Hedef icin yoklama hakki. Kullanim: `with guard.acquire(key, ip=ip, scope=...): ...`"""
        if self.is_slow(key, scope=scope):
            raise SlowTargetError(scope or key)
        wait = TARGET_WAIT_SECONDS if wait is None else wait
        limit = PROTECTED_TARGET_MAX_CONCURRENT if protected else TARGET_MAX_CONCURRENT
        # Katalogdaki kurumlarin IP adresleri saldirganin denetiminde degildir; IP siniri uygulanmaz
        ip = None if protected else ip
        end = time.monotonic() + max(0.0, wait)
        with self._cond:
            while True:
                busy_target = self._inflight.get(key, 0) >= limit
                busy_ip = bool(ip) and self._ip_inflight.get(ip, 0) >= IP_MAX_CONCURRENT
                if not busy_target and not busy_ip:
                    break
                left = end - time.monotonic()
                if left <= 0:
                    raise TargetBusyError(ip if busy_ip and not busy_target else key)
                self._cond.wait(left)
            self._inflight[key] = self._inflight.get(key, 0) + 1
            if ip:
                self._ip_inflight[ip] = self._ip_inflight.get(ip, 0) + 1
        return _Held(self, key, ip)

    def acquire_ip(self, ip: str, wait: float = 0.0):
        """Yalnizca IP siniri (TLS yoklamasi kisitli IP'de; B-05). Doluysa TargetBusyError."""
        end = time.monotonic() + max(0.0, wait)
        with self._cond:
            while self._ip_inflight.get(ip, 0) >= IP_MAX_CONCURRENT:
                left = end - time.monotonic()
                if left <= 0:
                    raise TargetBusyError(ip)
                self._cond.wait(left)
            self._ip_inflight[ip] = self._ip_inflight.get(ip, 0) + 1
        return _Held(self, None, ip)

    def _exit(self, key: str | None, ip: str | None) -> None:
        with self._cond:
            for store, k in ((self._inflight, key), (self._ip_inflight, ip)):
                if not k:
                    continue
                n = store.get(k, 0) - 1
                if n > 0:
                    store[k] = n
                else:
                    store.pop(k, None)
            self._cond.notify_all()

    def reset(self) -> None:
        with self._lock:
            self._slow.clear()
            self._inflight.clear()
            self._ip_inflight.clear()
            self._strikes.clear()
            self._ok.clear()
            self._ip_strikes.clear()
            self._ip_degraded.clear()
            self._client_strikes.clear()
            self._client_slow.clear()


class _Held:
    def __init__(self, guard, key, ip=None):
        self._guard = guard
        self._key = key
        self._ip = ip

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._guard._exit(self._key, self._ip)
        return False


targets = _TargetGuard()
