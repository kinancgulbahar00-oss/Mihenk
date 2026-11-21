"""Ayristirma iscileri havuzu (E-01).

Sayfa govdesi ana surecte DEGIL, isci sureclerde ayristirilir:

  * Sure siniri: agac kurma algoritmasi bazi girdilerde (cok derin ic ice ogeler) karesel sure tuketir.
    Sinir asilirsa isci sonlandirilir ve sayfa "incelenemedi" olarak bildirilir; ana surec ve diger
    istekler etkilenmez (ayristirma ana surecin GIL'ini tutmaz).
  * Yalitim: ayristirici C ile yazilmistir. Olasi bir bellek hatasi isciyi dusurur, uygulamayi degil;
    iscide ayar, parola ozeti, oturum ya da veritabani baglantisi bulunmaz ve ana surec iscinin yanitini
    yalnizca JSON olarak okur.

Havuz kucuktur (varsayilan 3 isci); isciler ilk kullanimda baslatilir ve yeniden kullanilir.
"""

import logging
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

from backend.sandbox.worker import MAX_MESSAGE_BYTES, read_message, write_message

logger = logging.getLogger("mihenk.sandbox")

POOL_SIZE = 3
# Tek bir belgenin ayristirilmasi icin ust sure. Olagan 1 MB'lik sayfa ~0,3 sn surer (uc isci ayni anda: ~0,8 sn).
PARSE_TIMEOUT_SECONDS = 2.5
# Butun isciler mesgulken beklenen en uzun sure
ACQUIRE_TIMEOUT_SECONDS = 4.0
# Dusuk oncelikli cagrilar (yakin zamanda ayristirma zaman asimi ureten istemci; G-08) bu kadar isciyi
# kullanamaz: havuzun bir bolumu her zaman diger istemcilere ayrilidir.
RESERVED_WORKERS = 1
# Havuz doluyken (ayrilan isciye sira geldiginde) tek belgeye taninan sure
CONTENDED_TIMEOUT_SECONDS = 1.0
# Isciye aktarilan ortam degiskenleri: yalnizca yorumlayicinin calismasi icin gerekenler
_PASSED_ENV = ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
               "LD_LIBRARY_PATH", "PYTHONHOME", "VIRTUAL_ENV")
_ROOT = str(Path(__file__).resolve().parents[2])
_BOOTSTRAP = "import sys; sys.path.insert(0, sys.argv[1]); from backend.sandbox import worker; worker.main()"


class ParseFailed(Exception):
    """Belge ayristirilamadi: 'timeout', 'crash', 'busy' ya da 'error'."""


class _Worker:
    def __init__(self):
        env = {k: os.environ[k] for k in _PASSED_ENV if k in os.environ}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # -s: kullanici site dizini yok; -S degil (ayristirici kitapligi site-packages'tadir)
        self.process = subprocess.Popen(
            [sys.executable, "-s", "-c", _BOOTSTRAP, _ROOT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, cwd=_ROOT, close_fds=True)
        self.replies = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, name="mihenk-parse-reader", daemon=True)
        self._reader.start()

    def _read_loop(self):
        stream = self.process.stdout
        while True:
            try:
                message = read_message(stream)
            except Exception:
                message = None
            self.replies.put(message)
            if message is None:
                return

    def alive(self):
        return self.process.poll() is None

    def kill(self):
        try:
            self.process.kill()
        except Exception:
            pass
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except Exception:
                pass
        try:
            self.process.wait(1.0)
        except Exception:
            pass


class ParsePool:
    def __init__(self, size=POOL_SIZE):
        self.size = size
        self._idle = queue.LifoQueue()
        self._lock = threading.Lock()
        self._count = 0
        self._busy = 0

    def _acquire(self, timeout):
        deadline = time.monotonic() + max(0.05, timeout)
        worker = None
        try:
            worker = self._idle.get_nowait()
        except queue.Empty:
            pass
        while worker is None:
            with self._lock:
                create = self._count < self.size
                if create:
                    self._count += 1
            if create:
                try:
                    return _Worker()
                except Exception:
                    self._release_slot()
                    raise ParseFailed("crash")
            try:
                # None: sonlandirilan bir iscinin yeri bosaldi; bekleyen cagri yeni isciyi kendisi baslatir (G-08).
                # Onceki surumde bekleyenler bosalan yeri gormuyor, sure dolana kadar bekleyip "busy" aliyordu.
                worker = self._idle.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                raise ParseFailed("busy")
            if worker is None and time.monotonic() >= deadline:
                self._idle.put(None)
                raise ParseFailed("busy")
        return worker

    def _release_slot(self):
        with self._lock:
            self._count -= 1
        self._idle.put(None)

    def _discard(self, worker):
        worker.kill()
        self._release_slot()

    def run(self, html, xml=False, timeout=PARSE_TIMEOUT_SECONDS, low_priority=False):
        with self._lock:
            # Dusuk oncelikli cagri son bos isciyi alamaz ve beklemez (G-08)
            contended = self._busy >= max(1, self.size - RESERVED_WORKERS)
            if low_priority and contended:
                raise ParseFailed("busy")
            self._busy += 1
        if contended:
            # Havuz doluyken alinan is kisa tutulur: olagan sayfa bu surede biter, isciyi mesgul etmek icin
            # hazirlanan belge ise havuzu en fazla bu kadar tutar (G-08)
            timeout = min(timeout, CONTENDED_TIMEOUT_SECONDS)
        try:
            return self._run(html, xml, timeout)
        finally:
            with self._lock:
                self._busy -= 1

    def _run(self, html, xml, timeout):
        # Isci bekleme suresi ayristirma suresinden AYRIDIR: bekleyen cagri sirasi geldiginde tam suresini kullanir
        worker = self._acquire(ACQUIRE_TIMEOUT_SECONDS)
        if not worker.alive():
            self._discard(worker)
            worker = self._acquire(0.5)
        started = time.monotonic()
        try:
            write_message(worker.process.stdin, {"html": html, "xml": bool(xml)})
            remaining = timeout - (time.monotonic() - started)
            reply = worker.replies.get(timeout=max(0.05, remaining))
        except queue.Empty:
            logger.warning("parse worker exceeded %.1fs; terminated (chars=%d)", timeout, len(html))
            self._discard(worker)
            raise ParseFailed("timeout")
        except (OSError, ValueError) as exc:
            logger.warning("parse worker died (%s); restarted", type(exc).__name__)
            self._discard(worker)
            raise ParseFailed("crash") from exc
        if not isinstance(reply, dict):
            logger.warning("parse worker died; restarted (chars=%d)", len(html))
            self._discard(worker)
            raise ParseFailed("crash")
        self._idle.put(worker)
        if not reply.get("ok") or not isinstance(reply.get("facts"), dict):
            raise ParseFailed("error")
        return reply["facts"]

    def shutdown(self):
        while True:
            try:
                worker = self._idle.get_nowait()
            except queue.Empty:
                break
            if worker is not None:
                worker.kill()
                with self._lock:
                    self._count -= 1


_pool = None
_pool_lock = threading.Lock()


def extract(html, xml=False, timeout=None, low_priority=False):
    """Belgeyi isci surecte ayristirir. Basarisizsa ParseFailed firlatir."""
    timeout = PARSE_TIMEOUT_SECONDS if timeout is None else timeout
    global _pool
    if len(html) * 4 > MAX_MESSAGE_BYTES - 1024:
        raise ParseFailed("error")
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ParsePool()
    return _pool.run(html, xml=xml, timeout=timeout, low_priority=low_priority)


def shutdown():
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown()
            _pool = None
