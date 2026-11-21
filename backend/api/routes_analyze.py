import asyncio
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool
from backend.config import settings
from backend.core.retention import maybe_purge, trim_history
from backend.models.database import SessionLocal
from backend.models.ioc_model import IOCModel, DomainModel, IPModel, URLModel, AnalysisResultModel, value_digest
from backend.schemas.analyze_schema import AnalyzeRequest, AnalyzeResponse, IOCDetails, ReasonItem, MitreTechnique, RelatedDomain
from backend.core.analyzer_interface import InvalidTargetError, analyze_url_pipeline
from backend.core.netguard import reset_probe_context, set_probe_context, targets
from backend.core.security import RateLimiter
from backend.api.routes_auth import client_ip

logger = logging.getLogger("mihenk.analyze")

router = APIRouter(prefix="", tags=["Analyze"])

_rate_limiter = RateLimiter(limit=settings.ANALYZE_RATE_PER_MINUTE, window=60)
_MAX_CONCURRENT = max(1, settings.ANALYZE_MAX_CONCURRENT)
_concurrency = threading.BoundedSemaphore(_MAX_CONCURRENT)
# Analiz hatti ayri bir havuzda calisir; havuz boyutu ortak yuva sayisina esittir.
# Yuva, istemciye yanit donunce degil is GERCEKTEN bittiginde birakilir; tum ag islemleri
# soket duzeyinde sure sinirli oldugu icin bu sure de sinirlidir (Y-02).
_executor = ThreadPoolExecutor(max_workers=_MAX_CONCURRENT, thread_name_prefix="analyze")

_client_lock = threading.Lock()
_client_inflight: dict[str, int] = {}
# Dolu ortak yuva sayisi: yuk altinda yeni yoklamalara kisa butce verilir (D-03)
_slots_in_use = 0
# Bos yuva beklenirken is parcacigi tutulmaz (D-06): olay dongusunde kisa araliklarla denenir
SLOT_WAIT_SECONDS = 10
_SLOT_POLL_SECONDS = 0.1


def _acquire_client_slot(ip: str) -> bool:
    """Tek bir istemci ortak yuvalarin tamamini tutamaz (Y-02)."""
    with _client_lock:
        n = _client_inflight.get(ip, 0)
        if n >= max(1, settings.ANALYZE_MAX_CONCURRENT_PER_CLIENT):
            return False
        _client_inflight[ip] = n + 1
        return True


def _release_client_slot(ip: str) -> None:
    with _client_lock:
        n = _client_inflight.get(ip, 0) - 1
        if n > 0:
            _client_inflight[ip] = n
        else:
            _client_inflight.pop(ip, None)


RATE_LIMITED_PATHS = {"/analyze/url"}
_RATE_CHECKED = "mihenk_rate_checked"


class AnalyzeRateLimitMiddleware:
    """Analiz hiz siniri GOVDE OKUNMADAN uygulanir (B-03). FastAPI istek govdesini bagimliliklardan
    once okur; govdesi hic tamamlanmayan (yarim birakilmis) istek bu yuzden bagimlilik olarak calisan
    sinira takilmiyordu. Saf ASGI katmani yalnizca baslik geldiginde sayaci isletir; siniri asan
    istemciye govde beklenmeden 429 doner ve baglanti kapatilir."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") not in RATE_LIMITED_PATHS:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        ip = client[0] if client else "unknown"
        wait = _rate_limiter.hit(ip)
        scope.setdefault("state", {})[_RATE_CHECKED] = True
        if wait:
            body = json.dumps({"detail": RATE_LIMIT_DETAIL}, ensure_ascii=False).encode("utf-8")
            await send({"type": "http.response.start", "status": 429, "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", str(wait).encode("ascii")),
                (b"connection", b"close"),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


RATE_LIMIT_DETAIL = "Çok fazla analiz isteği gönderildi. Lütfen biraz bekleyip tekrar deneyin."


def analyze_rate_limit(http_request: Request) -> str:
    """Bagimlilik olarak calisir. Uretimde sinir AnalyzeRateLimitMiddleware tarafindan govde okunmadan
    ONCE uygulanir (B-03); ara katman yoksa (dogrudan yonlendirici kullanimi) burada uygulanir (Y-03)."""
    ip = client_ip(http_request)
    if http_request.scope.get("state", {}).get(_RATE_CHECKED):
        return ip
    wait = _rate_limiter.hit(ip)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_DETAIL,
            headers={"Retry-After": str(wait)},
        )
    return ip


def _slots_load() -> float:
    return _slots_in_use / _MAX_CONCURRENT


def _try_acquire_slot() -> bool:
    global _slots_in_use
    if not _concurrency.acquire(blocking=False):
        return False
    with _client_lock:
        _slots_in_use += 1
    return True


def _release_slot() -> None:
    global _slots_in_use
    with _client_lock:
        _slots_in_use = max(0, _slots_in_use - 1)
    _concurrency.release()


def _pipeline_job(raw_url: str, ip: str = None, load: float = 0.0):
    """Analiz hatti kendi veritabani oturumuyla calisir: istek zaman asimina ugrayip
    istek oturumu kapansa bile ayni oturum iki is parcacigi tarafindan kullanilmaz.

    Yavasligin bedelini hedefi gonderen istemci oder (D-03): son 10 dakikada sure butcesini
    tuketen istemcinin yoklamalarina kisa butce verilir; yuvalarin cogu doluyken de butce kisalir."""
    ctx = targets.budget_for(ip, load)
    if ctx.reason != "default":
        logger.info("probe budget reduced ip=%s reason=%s page=%ss tls=%ss",
                    ip, ctx.reason, ctx.page_budget, ctx.tls_budget)
    token = set_probe_context(ctx)
    db = SessionLocal()
    try:
        return analyze_url_pipeline(raw_url, db=db)
    finally:
        db.close()
        reset_probe_context(token)
        if ctx.timeouts:
            targets.record_client_timeout(ip, len(set(ctx.timeouts)))
            logger.info("probe timeouts charged to client ip=%s count=%d", ip, len(set(ctx.timeouts)))
        if ctx.slow:
            # Butce icinde kalan ama uzun suren yoklamalar (B-04): hedef sayacini yavas adreslerle dolu
            # tutan istemci kayda yazilir ve kisa butceye duser
            targets.record_client_slow(ip, len(ctx.slow))
            logger.info("slow probes charged to client ip=%s count=%d targets=%s", ip, len(ctx.slow),
                        ",".join(sorted(set(ctx.slow)))[:300])


@router.post("/analyze/url", response_model=AnalyzeResponse, status_code=status.HTTP_200_OK,
             summary="URL analiz eder, sonucu kaydeder ve açıklanabilir risk skoru döner")
async def analyze_url_endpoint(request: AnalyzeRequest, ip: str = Depends(analyze_rate_limit)):
    # Uc nokta olay dongusunde calisir: yuva beklemesi ve analiz suresi boyunca ortak is
    # parcacigi havuzundan (giris, liste, saglik uc noktalari da onu kullanir) is parcacigi
    # tutulmaz (D-06). Analiz ayri, sinirli havuzda; veritabani islemleri kisa sureli havuz gorevi.
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL boş olamaz.")

    if not _acquire_client_slot(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Önceki analiziniz henüz tamamlanmadı. Lütfen bitmesini bekleyin.",
            headers={"Retry-After": "5"},
        )
    give_up = time.monotonic() + SLOT_WAIT_SECONDS
    while not _try_acquire_slot():
        if time.monotonic() >= give_up:
            _release_client_slot(ip)
            logger.warning("analysis slots exhausted ip=%s", ip)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analiz servisi şu an yoğun. Lütfen biraz sonra tekrar deneyin.",
                headers={"Retry-After": "10"},
            )
        await asyncio.sleep(_SLOT_POLL_SECONDS)

    def _release(_future):
        _release_slot()
        _release_client_slot(ip)

    try:
        future = _executor.submit(_pipeline_job, request.url, ip, _slots_load())
    except Exception:
        _release(None)
        raise _server_error()
    future.add_done_callback(_release)

    try:
        # shield: istemcinin zaman asimi isi iptal etmez; yuva is GERCEKTEN bitince birakilir
        analysis_result = await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)),
                                                 timeout=max(1, settings.ANALYZE_TIMEOUT_SECONDS))
    except asyncio.TimeoutError:
        logger.warning("analysis timed out ip=%s timeout=%ss", ip, settings.ANALYZE_TIMEOUT_SECONDS)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Analiz süre sınırını aştı. Hedef sunucu çok yavaş yanıt veriyor olabilir.",
        )
    except InvalidTargetError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise _server_error()

    return await run_in_threadpool(_persist_and_purge, analysis_result)


def _persist_and_purge(analysis_result: dict):
    db = SessionLocal()
    try:
        response = _persist(analysis_result, db)
    finally:
        db.close()
    maybe_purge(SessionLocal)
    return response


def _persist(analysis_result: dict, db):
    try:
        url_str = analysis_result["url"]
        risk_score = analysis_result["risk_score"]
        risk_level = analysis_result["risk_level"]
        ioc_det = analysis_result["ioc_details"]
        
        digest = value_digest(url_str)
        existing_ioc = (db.query(IOCModel)
                        .filter(IOCModel.value_hash == digest, IOCModel.value == url_str)
                        .first())
        if existing_ioc:
            ioc_record = existing_ioc
        else:
            # Eszamanli ilk analizler (A-11): tekil dizin ikinci eklemeyi reddeder; kaybeden istek, kazanan
            # istegin kaydini okuyup onun uzerinden devam eder.
            try:
                with db.begin_nested():
                    ioc_record = IOCModel(
                        type="url",
                        value=url_str,
                        value_hash=digest,
                        risk_score=risk_score,
                        risk_level=risk_level
                    )
                    db.add(ioc_record)
                    db.flush()
            except IntegrityError:
                ioc_record = (db.query(IOCModel)
                              .filter(IOCModel.type == "url", IOCModel.value_hash == digest)
                              .first())
                if ioc_record is None:
                    raise

        if ioc_record.url_info:
            ioc_record.url_info.vt_malicious_count = ioc_det.get("vt_positives")
            ioc_record.url_info.vt_total_count = ioc_det.get("vt_total")
            ioc_record.url_info.has_https = ioc_det.get("has_https", False)
        else:
            url_info = URLModel(
                ioc_id=ioc_record.id,
                url=url_str,
                vt_malicious_count=ioc_det.get("vt_positives"),
                vt_total_count=ioc_det.get("vt_total"),
                has_https=ioc_det.get("has_https", False)
            )
            db.add(url_info)

        domain_val = ioc_det.get("domain")
        if domain_val:
            if ioc_record.domain_info:
                ioc_record.domain_info.whois_registrar = ioc_det.get("registrar")
                ioc_record.domain_info.age_days = ioc_det.get("domain_age_days")
                ioc_record.domain_info.created_date = ioc_det.get("domain_registration_date")
            else:
                domain_info = DomainModel(
                    ioc_id=ioc_record.id,
                    domain_name=domain_val,
                    whois_registrar=ioc_det.get("registrar"),
                    age_days=ioc_det.get("domain_age_days"),
                    created_date=ioc_det.get("domain_registration_date")
                )
                db.add(domain_info)

        ip_val = ioc_det.get("ip_address")
        if ip_val:
            if ioc_record.ip_info:
                ioc_record.ip_info.abuseipdb_score = ioc_det.get("abuse_score")
                ioc_record.ip_info.reports_count = ioc_det.get("ip_reports_count")
            else:
                ip_info = IPModel(
                    ioc_id=ioc_record.id,
                    ip_address=ip_val,
                    abuseipdb_score=ioc_det.get("abuse_score"),
                    reports_count=ioc_det.get("ip_reports_count")
                )
                db.add(ip_info)

        analysis_record = AnalysisResultModel(
            ioc_id=ioc_record.id,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons_json=analysis_result.get("reasons", []),
            mitre_json=analysis_result.get("mitre_techniques", []),
            related_domains_json=analysis_result.get("related_domains", [])
        )
        db.add(analysis_record)
        db.flush()
        _update_verdict(db, ioc_record, analysis_result)
        trim_history(db, ioc_record.id)
        db.commit()
        db.refresh(ioc_record)
        return _response(analysis_result, ioc_record.id)
    except Exception:
        # Kayit basarisiz olsa da hesaplanan sonuc kullaniciya doner; hata ayrica kaydedilir (Z-02).
        # Saldirganin denetimindeki bir deger, karari kullanicidan gizleyemez.
        db.rollback()
        incident = uuid.uuid4().hex[:12]
        logger.exception("analysis persist failed incident=%s url=%r", incident, str(analysis_result.get("url"))[:200])
        try:
            return _response(analysis_result, None)
        except Exception:
            raise _server_error()


# Kayitli karar penceresi (B-08): son 30 gundeki en yuksek karar gosterilir
PEAK_WINDOW_DAYS = 30


def _update_verdict(db, ioc_record, analysis_result: dict) -> None:
    """Kayitli karar son analizin degil, son PEAK_WINDOW_DAYS gundeki EN YUKSEK kararin yansimasidir
    (B-08): kimligi dogrulanmamis bir istemci sayfasini gecici olarak zararsiz yapip yeniden analiz
    ettirerek "Zararli" karari dusuremez. Analistin liste karari (izin/engel) dogrudan uygulanir.
    Son analizin sonucu ayrica tutulur; karar dusus yonunde degistiyse kayda yazilir."""
    score, level = analysis_result["risk_score"], analysis_result["risk_level"]
    ioc_record.last_risk_score = score
    ioc_record.last_risk_level = level
    list_status = (analysis_result.get("ioc_details") or {}).get("abuse_status")
    if list_status in ("whitelisted", "blacklisted"):
        ioc_record.risk_score, ioc_record.risk_level = score, level
        return
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=PEAK_WINDOW_DAYS)
    peak = (db.query(AnalysisResultModel.risk_score, AnalysisResultModel.risk_level)
            .filter(AnalysisResultModel.ioc_id == ioc_record.id, AnalysisResultModel.created_at >= cutoff)
            .order_by(AnalysisResultModel.risk_score.desc(), AnalysisResultModel.id.desc())
            .first())
    if peak and peak.risk_score > score:
        if (ioc_record.risk_score or 0) > score:
            logger.info("ioc verdict kept at peak ioc=%s peak=%s latest=%s", ioc_record.id, peak.risk_score, score)
        ioc_record.risk_score, ioc_record.risk_level = peak.risk_score, peak.risk_level
    else:
        ioc_record.risk_score, ioc_record.risk_level = score, level


def _response(analysis_result: dict, ioc_id):
    return AnalyzeResponse(
        id=ioc_id,
        url=analysis_result["url"],
        risk_score=analysis_result["risk_score"],
        risk_level=analysis_result["risk_level"],
        reasons=[ReasonItem(**r) for r in analysis_result.get("reasons", [])],
        ioc_details=IOCDetails(**analysis_result.get("ioc_details", {})),
        mitre_techniques=[MitreTechnique(**m) for m in analysis_result.get("mitre_techniques", [])],
        related_domains=[RelatedDomain(**rd) for rd in analysis_result.get("related_domains", [])]
    )


def _server_error() -> HTTPException:
    incident = uuid.uuid4().hex[:12]
    # Ayrinti yalnizca sunucu kaydina yazilir; istemciye ic hata metni donmez
    logger.exception("analysis failed incident=%s", incident)
    return HTTPException(
        status_code=500,
        detail=f"Analiz işlemi sırasında sunucu hatası oluştu. Olay kimliği: {incident}",
    )
