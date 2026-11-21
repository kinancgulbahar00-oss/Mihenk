import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from backend.config import settings
from backend.core import seo
from backend.core.body_limit import BodySizeLimitMiddleware, ClientRequestGateMiddleware
from backend.models.database import init_db
from backend.api.routes_list import audit_list_rules
from backend.api.routes_analyze import AnalyzeRateLimitMiddleware, router as analyze_router
from backend.api.routes_ioc import router as ioc_router
from backend.api.routes_campaign import router as campaign_router
from backend.api.routes_list import router as list_router
from backend.api.routes_brands import router as brands_router
from backend.api.routes_auth import router as auth_router, configure_admin_credentials, configure_security

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("mihenk")

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Guvenli bir yonetici parolasi yoksa servis baslamaz (SecurityConfigError)
    configure_admin_credentials()
    configure_security()
    try:
        init_db()
    except Exception:
        logger.exception("Database initialization error")
    try:
        audit_list_rules()
    except Exception:
        logger.exception("List rule audit failed")
    yield


docs_enabled = settings.ENABLE_API_DOCS
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Kimlik avı kampanyalarını skorlayan, açıklanabilir tehdit istihbaratı REST API'si.",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
    lifespan=lifespan
)

# Yalnizca acikca tanimlanan kokenler; joker koken yok. Arayuz ayni kokenden sunuldugunda CORS gerekmez.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )

# Govde boyutu siniri: buyuk govde bellege alinmadan 413 ile reddedilir (Y-03). Ters vekilde de
# ayni sinir vardir (deploy/Caddyfile); bu katman savunma derinligidir. Asagidaki baslik
# katmanindan ONCE eklenir (uygulamaya daha yakin): akis sirasinda asilan sinirin 413'u
# BaseHTTPMiddleware'in receive sarmalayicisinda baska bir hataya donusmez.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BODY_BYTES,
                   read_timeout=settings.REQUEST_BODY_TIMEOUT_SECONDS)
# Analiz hiz siniri govde okunmadan uygulanir (B-03): yarim birakilan istekler de sayilir
app.add_middleware(AnalyzeRateLimitMiddleware)


def _admin_network_blocked(scope) -> bool:
    """Yonetici uc noktalarindaki ag kisiti govde okunmadan uygulanir (A-07). Istemci adresi, uc noktalarin
    kullandigi islevle (routes_auth.client_ip) belirlenir: iki denetim ayni kaynaga dayanir."""
    if not settings.ADMIN_RESTRICT_TO_TRUSTED:
        return False
    if not scope.get("path", "").startswith(("/admin", "/lists", "/campaign", "/ioc")):
        return False
    from backend.api import routes_auth

    return not routes_auth.is_trusted_admin_ip(routes_auth.client_ip(Request(scope)))


# Istemci basina eszamanli istek siniri, BUTUN durum degistiren uc noktalarda ve govdeden once (A-07):
# yarim birakilan POST /admin/login istekleri uygulama sunucusunun ortak sinirini dolduramaz.
app.add_middleware(ClientRequestGateMiddleware, max_inflight=settings.MAX_INFLIGHT_PER_CLIENT,
                   blocked=_admin_network_blocked)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.url.path.startswith(("/docs", "/redoc")):
        # Swagger arayuzu CDN'den yuklenir; yalnizca ENABLE_API_DOCS=true iken erisilebilir
        headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    else:
        headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if settings.COOKIE_SECURE:
        headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith(("/admin", "/lists", "/ioc", "/campaign", "/analyze")):
        headers.setdefault("Cache-Control", "no-store")
    # SEO: API yanitlari ve yonetim hicbir kosulda dizine eklenmez; PUBLIC_BASE_URL tanimli degilse hicbir sayfa eklenmez
    if seo.is_private_path(request.url.path) or not seo.indexable():
        headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    # Derleme ciktisindaki dosya adlari icerik ozetlidir: uzun sureli onbellek (Core Web Vitals)
    if request.url.path.startswith("/assets/") and response.status_code == 200:
        headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """FastAPI'nin varsayilan 422 yaniti gecersiz girdiyi 'input' alaninda geri gonderir; ayni
    veri yanit icin bir kez daha bellege kopyalanir ve bant genisligi iki katina cikar (Y-03).
    Yanitta yalnizca alan konumu, hata turu ve ileti bulunur."""
    errors = [
        {"loc": [str(part) for part in err.get("loc", ())], "type": str(err.get("type", "")),
         "msg": str(err.get("msg", ""))[:200]}
        for err in exc.errors()[:20]
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


app.include_router(analyze_router)
app.include_router(ioc_router)
app.include_router(campaign_router)
app.include_router(list_router)
app.include_router(brands_router)
app.include_router(auth_router)


@app.get("/robots.txt", include_in_schema=False)
def robots_txt():
    return PlainTextResponse(seo.robots_txt(), headers={"Cache-Control": "public, max-age=3600"})


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    index = FRONTEND_DIST / "index.html"
    body = seo.sitemap_xml(index.stat().st_mtime if index.is_file() else None)
    if body is None:
        return PlainTextResponse("Not Found", status_code=404)
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=3600"})


@app.get("/llms.txt", include_in_schema=False)
def llms_txt():
    body = seo.llms_txt()
    if body is None:
        return PlainTextResponse("Not Found", status_code=404)
    return PlainTextResponse(body, media_type="text/markdown; charset=utf-8", headers={"Cache-Control": "public, max-age=3600"})


@app.get("/health", tags=["Health"], summary="Servis sağlık kontrolü")
def health_check():
    return {"status": "ok"}


if FRONTEND_DIST.is_dir():
    DIST_ROOT = FRONTEND_DIST.resolve()
    assets_dir = DIST_ROOT / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static_assets")

    _index_cache = {}

    def _index_response():
        """index.html, SEO etiketleri eklenmis olarak (robots, canonical, yapilandirilmis veri ilk HTML'dedir)."""
        index = DIST_ROOT / "index.html"
        key = (index.stat().st_mtime, seo.site_url())
        if _index_cache.get("key") != key:
            _index_cache.update(key=key, body=seo.render_index(index.read_text(encoding="utf-8")))
        return HTMLResponse(_index_cache["body"], headers={"Cache-Control": "no-cache"})

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend_spa(full_path: str):
        # Yol cozumlenip dist kokunun icinde kaldigi dogrulanir (dizin asimi engeli)
        if full_path in ("", "index.html"):
            return _index_response()
        try:
            target = (DIST_ROOT / full_path).resolve()
        except (OSError, ValueError):
            target = None
        if target is not None and target.is_relative_to(DIST_ROOT) and target.is_file():
            return FileResponse(target)
        if ".." in full_path or "%2e" in full_path.lower():
            logger.warning("path traversal attempt blocked path=%r", full_path)
        # Uygulama gorunumleri adresin '#' kismindadir; sunucuda baska sayfa yoktur. Bilinmeyen yol icin ana sayfayi
        # 200 ile dondurmek "soft 404" uretir (arama motoru sinirsiz sayida kopya sayfa gorur): gercek 404 doner.
        return HTMLResponse(seo.NOT_FOUND_HTML, status_code=404)
else:
    @app.get("/", include_in_schema=False)
    def frontend_not_built():
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Frontend derlemesi bulunamadı.",
                "hint": "Proje kökünde `npm ci && npm run build` çalıştırın, ardından sunucuyu yeniden başlatın.",
            }
        )


if __name__ == "__main__":
    import uvicorn
    # Yerel gelistirme: yalnizca bu makineden erisilebilir
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False, server_header=False)
