import asyncio
import ipaddress
import logging
import time
from typing import Optional

from starlette.concurrency import run_in_threadpool
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.config import is_known_weak_password, settings
from backend.core.security import (
    RateLimiter,
    hash_password,
    is_valid_hash,
    is_valid_totp_secret,
    password_policy_problem,
    sessions,
    totp,
    verify_password,
)
from backend.models.database import get_db
from backend.models.list_model import ListModel
from backend.models.ioc_model import IOCModel
from backend.models.campaign_model import CampaignModel
from backend.schemas.auth_schema import (
    AdminLoginRequest,
    AdminLoginResponse,
    AdminVerifyResponse,
    AdminStatsResponse,
)

logger = logging.getLogger("mihenk.auth")

router = APIRouter(prefix="/admin", tags=["Admin Operations"])

SESSION_COOKIE = "mihenk_admin"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_admin_hash: Optional[str] = None
_login_failures = RateLimiter(limit=settings.LOGIN_MAX_FAILURES, window=settings.LOGIN_WINDOW_SECONDS)
# IP'den bagimsiz genel esik (Y-05). Esik asildiginda giris REDDEDILMEZ, yavaslatilir (Z-03):
# genel bir kilit, kimligi dogrulanmamis birinin yoneticiyi dogru parolayla bile disarida
# birakmasina izin verirdi. Dagitik kaba kuvvete karsi asil koruma IP basina sinir + ikinci etkendir.
_GLOBAL_KEY = "*"
_login_global = RateLimiter(limit=settings.LOGIN_GLOBAL_MAX_FAILURES, window=60 * 60)
_ALERT_INTERVAL_SECONDS = 60
_last_global_alert = 0.0


class SecurityConfigError(RuntimeError):
    pass


def configure_admin_credentials() -> None:
    """Uygulama acilisinda cagrilir. Guvenli bir parola yoksa sunucu baslamaz."""
    global _admin_hash
    if settings.ADMIN_PASSWORD_HASH:
        if not is_valid_hash(settings.ADMIN_PASSWORD_HASH):
            raise SecurityConfigError(
                "ADMIN_PASSWORD_HASH gecersiz. 'py -3.11 -m backend.hash_password' ile yeniden uretin."
            )
        _admin_hash = settings.ADMIN_PASSWORD_HASH
        return

    password = settings.ADMIN_PASSWORD
    if not password:
        raise SecurityConfigError(
            "Yonetici parolasi tanimli degil. ADMIN_PASSWORD_HASH (onerilen) veya ADMIN_PASSWORD "
            "ortam degiskenini ayarlayin."
        )
    problem = password_policy_problem(password)
    if is_known_weak_password(password) or problem:
        raise SecurityConfigError(
            "ADMIN_PASSWORD zayif veya ifsa olmus bir ornek deger. "
            f"{problem or ''} Uzun ve rastgele bir parola kullanin."
        )
    # Duz metin parola yalnizca bellekte ozetlenir; karsilastirma ozet uzerinden yapilir
    _admin_hash = hash_password(password)


def configure_security() -> None:
    """Acilista: ikinci etken ve guvenilen ag ayarlari dogrulanir (Z-03)."""
    if settings.ADMIN_TOTP_SECRET and not is_valid_totp_secret(settings.ADMIN_TOTP_SECRET):
        raise SecurityConfigError(
            "ADMIN_TOTP_SECRET gecersiz (en az 128 bit Base32). 'py -3.11 -m backend.totp_secret' ile uretin."
        )
    try:
        settings.admin_trusted_networks
    except ValueError as exc:
        raise SecurityConfigError(f"ADMIN_TRUSTED_NETWORKS gecersiz: {exc}")
    if settings.ADMIN_RESTRICT_TO_TRUSTED and not settings.admin_trusted_networks:
        raise SecurityConfigError("ADMIN_RESTRICT_TO_TRUSTED=true icin ADMIN_TRUSTED_NETWORKS tanimlanmali.")
    log_security_state()


def security_state() -> dict:
    """Uygulamanin FIILEN kullandigi guvenlik ayarlari (D-04). Dagitim dosyasi bir ayari
    uygulamaya ulastirmazsa bu deger varsayilanda gorunur."""
    return {
        "second_factor": bool(settings.ADMIN_TOTP_SECRET),
        "trusted_networks": len(settings.admin_trusted_networks),
        "restrict_to_trusted": bool(settings.ADMIN_RESTRICT_TO_TRUSTED),
        "login_max_failures": settings.LOGIN_MAX_FAILURES,
        "login_global_max_failures": settings.LOGIN_GLOBAL_MAX_FAILURES,
        "analyze_rate_per_minute": settings.ANALYZE_RATE_PER_MINUTE,
        "analyze_max_concurrent": settings.ANALYZE_MAX_CONCURRENT,
        "cookie_secure": bool(settings.COOKIE_SECURE),
        "page_fetch": bool(settings.PAGE_FETCH_ENABLED),
    }


def log_security_state() -> None:
    """Acilista fiili guvenlik durumunu tek satirda kayda yazar; ikinci etken kapaliyken uyarir (D-04)."""
    state = security_state()
    logger.info("security state " + " ".join(
        f"{k}={('on' if v else 'off') if isinstance(v, bool) else v}" for k, v in state.items()))
    if not state["second_factor"]:
        if settings.COOKIE_SECURE:
            logger.warning("SECURITY WARNING second factor is OFF on a production (COOKIE_SECURE=true) deployment: "
                           "admin panel is protected by the password only. Set ADMIN_TOTP_SECRET in .env "
                           "(py -3.11 -m backend.totp_secret) and verify it reaches the backend.")
        else:
            logger.info("second factor is off (development setup)")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def is_trusted_admin_ip(ip: str) -> bool:
    """Istemci ADMIN_TRUSTED_NETWORKS araliklarindan birinde mi? (Z-03)"""
    networks = settings.admin_trusted_networks
    if not networks:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in net for net in networks)


def _require_trusted_network(request: Request) -> None:
    if settings.ADMIN_RESTRICT_TO_TRUSTED and not is_trusted_admin_ip(client_ip(request)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Yönetici paneline bu ağdan erişilemez.")


def _check_origin(request: Request) -> None:
    """Durum degistiren isteklerde tarayicinin gonderdigi Origin baslik denetimi (CSRF)."""
    if request.method not in UNSAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if not origin:
        return
    allowed = set(settings.cors_origins)
    host = request.headers.get("host")
    if host:
        # Ters vekil TLS'i sonlandirdiginda arka uc istegi http olarak gorur; sema yerine host esas alinir
        allowed.update({f"https://{host}", f"http://{host}"})
    if origin.rstrip("/") not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="İstek kaynağı doğrulanamadı.")


def is_admin_request(request: Request) -> bool:
    return sessions.is_valid(request.cookies.get(SESSION_COOKIE))


def require_admin(request: Request) -> bool:
    _require_trusted_network(request)
    if not is_admin_request(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bu işlem yalnızca sistem yöneticisi (Admin) tarafından gerçekleştirilebilir. Lütfen Yönetici Paneli üzerinden giriş yapın."
        )
    _check_origin(request)
    return True


def _set_session_cookie(response: Response, token: str, remember: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.ADMIN_SESSION_TTL_MINUTES * 60 if remember else None,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


@router.post("/login", response_model=AdminLoginResponse, summary="Yönetici Girişi")
async def admin_login(payload: AdminLoginRequest, request: Request, response: Response):
    """Olay dongusunde calisir (B-11): genel esik asildiginda uygulanan gecikme ortak is parcacigi
    havuzundan is parcacigi TUTMAZ; parola ozeti dogrulamasi (scrypt) kisa sureli havuz gorevidir."""
    global _last_global_alert
    _check_origin(request)
    _require_trusted_network(request)
    ip = client_ip(request)
    trusted = is_trusted_admin_ip(ip)

    # Deneme, parola dogrulanmadan ONCE ve atomik olarak kaydedilir (Y-05): denetim ile kayit
    # arasinda bosluk kalmaz, eszamanli istekler sinirin uzerinde deneme yapamaz.
    # IP basina sinir yalnizca o IP'yi etkiler; basarili giriste sifirlanir.
    wait = _login_failures.hit(ip)
    if wait:
        logger.warning("admin login blocked (rate limit) scope=ip ip=%s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Çok fazla hatalı giriş denemesi. Lütfen daha sonra tekrar deneyin.",
            headers={"Retry-After": str(wait)},
        )

    # Genel esik: asildiginda giris reddedilmez, yavaslatilir ve uyari uretilir (Z-03).
    # Parola her durumda degerlendirilir; dogru parola baskalarinin hatalari yuzunden reddedilmez.
    global_recorded = _login_global.hit(_GLOBAL_KEY) == 0
    if not global_recorded and not trusted:
        now = time.monotonic()
        if now - _last_global_alert >= _ALERT_INTERVAL_SECONDS:
            _last_global_alert = now
            logger.warning("ALERT admin login global failure threshold exceeded (distributed brute force?) "
                           "threshold=%s/h action=throttle ip=%s", settings.LOGIN_GLOBAL_MAX_FAILURES, ip)
        await asyncio.sleep(max(0.0, settings.LOGIN_GLOBAL_DELAY_SECONDS))

    password_ok = _admin_hash is not None and await run_in_threadpool(verify_password, payload.password, _admin_hash)
    second_factor = bool(settings.ADMIN_TOTP_SECRET)
    otp_ok = not second_factor or (password_ok and totp.verify(settings.ADMIN_TOTP_SECRET, payload.otp))
    if not (password_ok and otp_ok):
        logger.warning("admin login failed ip=%s reason=%s", ip, "otp" if password_ok else "password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=("Hatalı yönetici parolası veya doğrulama kodu." if second_factor else
                    "Hatalı yönetici parolası. Lütfen parolanızı kontrol edip tekrar deneyin.")
        )

    _login_failures.reset(ip)
    if global_recorded:
        _login_global.undo(_GLOBAL_KEY)
    sessions.revoke(request.cookies.get(SESSION_COOKIE))
    token = sessions.create(settings.ADMIN_SESSION_TTL_MINUTES * 60)
    _set_session_cookie(response, token, payload.remember)
    logger.info("admin login succeeded ip=%s", ip)
    return AdminLoginResponse(success=True, role="admin", message="Yönetici girişi başarılı.")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Yönetici Çıkışı")
def admin_logout(request: Request, response: Response, mihenk_admin: Optional[str] = Cookie(None)):
    _check_origin(request)
    sessions.revoke(mihenk_admin)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.COOKIE_SECURE, httponly=True, samesite="strict")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/verify", response_model=AdminVerifyResponse, summary="Yönetici Oturum Doğrulama")
def admin_verify(is_admin: bool = Depends(require_admin)):
    return AdminVerifyResponse(valid=True, role="admin")


@router.get("/stats", response_model=AdminStatsResponse, summary="Platform Yönetici İstatistikleri")
def admin_stats(db: Session = Depends(get_db), _admin: bool = Depends(require_admin)):
    blacklist_count = db.query(ListModel).filter(ListModel.list_type == "blacklist").count()
    whitelist_count = db.query(ListModel).filter(ListModel.list_type == "whitelist").count()
    total_iocs = db.query(IOCModel).count()
    total_campaigns = db.query(CampaignModel).count()

    critical_iocs = db.query(IOCModel).filter(func.lower(IOCModel.risk_level) == "critical").count()
    high_iocs = db.query(IOCModel).filter(func.lower(IOCModel.risk_level) == "high").count()

    db_type = "PostgreSQL" if "postgresql" in settings.DATABASE_URL.lower() else "SQLite"

    vt_active = bool(settings.VIRUSTOTAL_API_KEY and "your_" not in settings.VIRUSTOTAL_API_KEY.lower())
    abuse_active = bool(settings.ABUSEIPDB_API_KEY and "your_" not in settings.ABUSEIPDB_API_KEY.lower())

    return AdminStatsResponse(
        total_iocs=total_iocs,
        total_campaigns=total_campaigns,
        blacklist_count=blacklist_count,
        whitelist_count=whitelist_count,
        critical_iocs=critical_iocs,
        high_iocs=high_iocs,
        database_type=db_type,
        vt_active=vt_active,
        abuse_active=abuse_active,
        second_factor_enabled=bool(settings.ADMIN_TOTP_SECRET),
        trusted_networks=len(settings.admin_trusted_networks),
        restrict_to_trusted=bool(settings.ADMIN_RESTRICT_TO_TRUSTED),
        login_max_failures=settings.LOGIN_MAX_FAILURES,
        analyze_rate_per_minute=settings.ANALYZE_RATE_PER_MINUTE,
    )
