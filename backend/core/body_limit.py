"""Istek govdesi boyut siniri (Y-03).

Saf ASGI ara katmani:
- Content-Length siniri asiyorsa (veya gecersizse) govde hic okunmadan 413 doner.
- Content-Length yoksa (chunked) govde akarken bayt sayilir; sinir asildiginda okuma
  durdurulur ve 413 doner. Boylece buyuk govde hicbir zaman tamamen bellege alinmaz.
- Govde `read_timeout` saniye icinde tamamlanmazsa okuma kesilir ve 408 doner (B-03): yarim
  birakilan istek arka uctaki bellegi ve baglantiyi suresiz tutamaz.
"""

import asyncio
import json
import time

from fastapi import HTTPException

TOO_LARGE_DETAIL = "İstek gövdesi çok büyük."
TIMEOUT_DETAIL = "İstek gövdesi zamanında tamamlanmadı."


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int, read_timeout: float = 10.0):
        self.app = app
        self.max_bytes = max(1, int(max_bytes))
        self.read_timeout = max(0.1, float(read_timeout))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers") or ():
            if name == b"content-length":
                try:
                    length = int(value)
                except ValueError:
                    length = -1
                if length < 0 or length > self.max_bytes:
                    await self._reject(send, 413 if length > self.max_bytes else 400)
                    return
                break

        received = 0
        complete = False
        deadline = None

        async def limited_receive():
            nonlocal received, complete, deadline
            if complete:
                # Govde bitti: istemcinin baglantiyi kapatmasini bekleyen dinleyiciler sure siniri disinda
                return await receive()
            if deadline is None:
                deadline = time.monotonic() + self.read_timeout
            try:
                message = await asyncio.wait_for(receive(), timeout=max(0.01, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                raise HTTPException(status_code=408, detail=TIMEOUT_DETAIL, headers={"Connection": "close"})
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI govde okuma sirasindaki HTTPException'i oldugu gibi iletir
                    raise HTTPException(status_code=413, detail=TOO_LARGE_DETAIL)
                if not message.get("more_body", False):
                    complete = True
            else:
                complete = True
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send, status):
        detail = TOO_LARGE_DETAIL if status == 413 else "Geçersiz Content-Length."
        body = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
                (b"x-content-type-options", b"nosniff"),
                (b"cache-control", b"no-store"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


class ClientRequestGateMiddleware:
    """Durum degistiren isteklerde (POST/PUT/PATCH/DELETE) GOVDE OKUNMADAN uygulanan istemci basina
    sinirlar (A-07):

    - bir istemcinin ayni anda islenen istek sayisi `max_inflight` ile sinirlidir. Govdesi yarim
      birakilan istekler de sayilir; tek bir istemci, uygulama sunucusunun ortak eszamanlilik sinirini
      (uvicorn --limit-concurrency) dolduramaz;
    - `blocked(scope)` True donerse istek govdesi okunmadan 403 alir. Yonetici uc noktalarindaki
      ag kisiti (ADMIN_RESTRICT_TO_TRUSTED) boylece govdeden once uygulanir.
    """

    METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app, max_inflight: int = 6, blocked=None):
        import threading

        self.app = app
        self.max_inflight = max(1, int(max_inflight))
        self.blocked = blocked
        self._lock = threading.Lock()
        self._inflight: dict = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in self.METHODS:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        if self.blocked is not None and self.blocked(scope):
            await self._reject(send, 403, "Yönetici paneline bu ağdan erişilemez.")
            return
        with self._lock:
            n = self._inflight.get(ip, 0)
            allowed = n < self.max_inflight
            if allowed:
                self._inflight[ip] = n + 1
        if not allowed:
            await self._reject(send, 429, "Çok fazla eşzamanlı istek. Lütfen önceki isteklerin bitmesini bekleyin.",
                               retry_after=5)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            with self._lock:
                n = self._inflight.get(ip, 0) - 1
                if n > 0:
                    self._inflight[ip] = n
                else:
                    self._inflight.pop(ip, None)

    @staticmethod
    async def _reject(send, status, detail, retry_after=None):
        body = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
            (b"x-content-type-options", b"nosniff"),
            (b"cache-control", b"no-store"),
        ]
        if retry_after:
            headers.append((b"retry-after", str(retry_after).encode("ascii")))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
