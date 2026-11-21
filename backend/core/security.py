"""Kimlik dogrulama yardimcilari: parola ozeti, sureli oturumlar ve istek sinirlayici.

Bagimlilik eklememek icin yalnizca standart kutuphane kullanilir:
- Parola ozeti: scrypt (hashlib.scrypt), sabit zamanli karsilastirma.
- Oturumlar: secrets.token_urlsafe(32); sunucuda yalnizca SHA-256 ozeti saklanir,
  sure dolunca veya cikista silinir.
- Sinirlayici: IP basina kayan pencere.

Not: Oturumlar ve sayaclar surec belleginde tutulur; uvicorn tek surec (worker) ile
calistirilmalidir. Birden cok surec gerekiyorsa bu depoyu Redis gibi ortak bir depoya tasiyin.
"""

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
HASH_PREFIX = "scrypt"
MIN_PASSWORD_LENGTH = 12
MIN_DISTINCT_CHARACTERS = 8
# Her scrypt dogrulamasi ~16 MB bellek kullanir; ayni anda calisan dogrulama sayisi sinirlidir (Y-05)
_scrypt_slots = threading.BoundedSemaphore(2)


def password_policy_problem(password: str) -> str | None:
    """Parola politikasi (Y-09): uzunlugun yaninda dusuk entropili degerler de reddedilir
    ('aaaaaaaaaaaa', '121212121212'). Sorun yoksa None doner."""
    password = password or ""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Parola en az {MIN_PASSWORD_LENGTH} karakter olmalı."
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        return f"Parola en az {MIN_DISTINCT_CHARACTERS} farklı karakter içermeli."
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    if classes < 2:
        return "Parola en az iki karakter türü (küçük/büyük harf, rakam, sembol) içermeli."
    return None


# --- Parola ozeti -------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"{HASH_PREFIX}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    with _scrypt_slots:
        return _verify_password(password, encoded)


def _verify_password(password: str, encoded: str) -> bool:
    try:
        prefix, n, r, p, salt, expected = encoded.split("$")
        if prefix != HASH_PREFIX:
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(_unb64(expected)), maxmem=128 * 1024 * 1024)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, _unb64(expected))


def is_valid_hash(encoded: str) -> bool:
    parts = (encoded or "").split("$")
    return len(parts) == 6 and parts[0] == HASH_PREFIX


# --- Ikinci etken: TOTP (RFC 6238) -------------------------------------------

TOTP_DIGITS = 6
TOTP_PERIOD = 30


def _b32decode(secret: str) -> bytes:
    clean = "".join(secret.split()).upper()
    return base64.b32decode(clean + "=" * (-len(clean) % 8))


def is_valid_totp_secret(secret: str) -> bool:
    try:
        return len(_b32decode(secret)) >= 16
    except (ValueError, TypeError):
        return False


def totp_code(secret: str, counter: int) -> str:
    digest = hmac.new(_b32decode(secret), counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


class TotpVerifier:
    """Saat kaymasi icin +/-1 adim tolerans; ayni kod (sayac) ikinci kez kabul edilmez.

    Tekrar kullanim korumasi, kullanilmis sayaclarin kumesiyle yapilir (D-06). "Son sayactan kucuk
    veya esit her kodu reddet" kurali, saati ileride olan dogrulayicinin bir sonraki adimin koduyla
    yapilan giristen sonra yaklasik bir dakika boyunca yeni giris yapilmasini engelliyordu."""

    def __init__(self):
        self._lock = threading.Lock()
        self._used: set[int] = set()

    def verify(self, secret: str, code: str | None, now: float | None = None) -> bool:
        code = (code or "").strip().replace(" ", "")
        if not secret or len(code) != TOTP_DIGITS or not code.isdigit():
            return False
        current = int((now if now is not None else time.time()) // TOTP_PERIOD)
        for counter in (current - 1, current, current + 1):
            if hmac.compare_digest(totp_code(secret, counter), code):
                with self._lock:
                    # Kabul penceresinin disinda kalan sayaclar artik hicbir zaman gecerli olamaz
                    self._used = {c for c in self._used if c >= current - 1}
                    if counter in self._used:
                        return False
                    self._used.add(counter)
                return True
        return False


totp = TotpVerifier()


# --- Oturumlar ----------------------------------------------------------------

class SessionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            self._sessions[self._key(token)] = time.time() + ttl_seconds
        return token

    def is_valid(self, token: str | None) -> bool:
        if not token or len(token) > 256:
            return False
        key = self._key(token)
        with self._lock:
            expires = self._sessions.get(key)
            if expires is None:
                return False
            if expires < time.time():
                del self._sessions[key]
                return False
            return True

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(self._key(token), None)

    def _purge(self):
        now = time.time()
        for key in [k for k, exp in self._sessions.items() if exp < now]:
            del self._sessions[key]


sessions = SessionStore()


# --- Istek sinirlayici --------------------------------------------------------

class RateLimiter:
    """Anahtar (IP) basina, `window` saniyede en fazla `limit` olay."""

    def __init__(self, limit: int, window: float, max_keys: int = 50_000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._events: dict[str, deque] = {}

    def _trim(self, key, now):
        q = self._events.get(key)
        if q is None:
            return None
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            del self._events[key]
            return None
        return q

    def retry_after(self, key: str) -> int:
        """Sinir asildiysa beklenecek saniye; asilmadiysa 0."""
        now = time.time()
        with self._lock:
            q = self._trim(key, now)
            if q is None or len(q) < self.limit:
                return 0
            return max(1, int(q[0] + self.window - now) + 1)

    def hit(self, key: str) -> int:
        """Olayi kaydeder. Sinir asildiysa kaydetmeden beklenecek saniyeyi doner."""
        now = time.time()
        with self._lock:
            q = self._trim(key, now)
            if q is not None and len(q) >= self.limit:
                return max(1, int(q[0] + self.window - now) + 1)
            if q is None:
                if len(self._events) >= self.max_keys:
                    # Bellegi sinirla: en eski anahtarlari at
                    for old in list(self._events)[: self.max_keys // 10]:
                        del self._events[old]
                q = self._events.setdefault(key, deque())
            q.append(now)
            return 0

    def undo(self, key: str) -> None:
        """Son kaydedilen olayi geri alir (basarili giriste genel sayacin dusurulmesi icin)."""
        with self._lock:
            q = self._events.get(key)
            if q:
                q.pop()
                if not q:
                    del self._events[key]

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
