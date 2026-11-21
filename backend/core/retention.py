"""Kimligi dogrulanmamis analizlerin olusturdugu kayitlar icin saklama siniri (Y-09).

Her analiz kalici kayit olusturur. Sinir olmadan tablo dakikada 20 istekle surekli buyur.
- Gosterge basina en fazla MAX_RESULTS_PER_IOC analiz sonucu tutulur.
- IOC_RETENTION_DAYS gununden eski analiz sonuclari silinir; analizi kalmayan ve bir
  kampanyaya bagli olmayan eski gostergeler de silinir. Temizlik en fazla saatte bir calisir.
- Toplam gosterge sayisi IOC_MAX_ROWS ile sinirlidir (Z-09); asilinca en eski, kampanyaya
  bagli olmayan gostergeler silinir.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, exists

from backend.config import settings
from backend.models.campaign_model import CampaignIOCModel
from backend.models.ioc_model import AnalysisResultModel, DomainModel, IOCModel, IPModel, URLModel

logger = logging.getLogger("mihenk.retention")

PURGE_INTERVAL_SECONDS = 60 * 60
PURGE_BATCH = 1000

_lock = threading.Lock()
_last_purge = 0.0


def protected_result_ids(db, ioc_id: int) -> set:
    """Gecmis sinirindan muaf sonuclar (B-08): gostergenin ILK analizi ve EN YUKSEK skorlu analizi.
    Anonim yeniden analizlerle onceki "Zararli" karar ve gerekceleri silinemez."""
    first = (db.query(AnalysisResultModel.id).filter(AnalysisResultModel.ioc_id == ioc_id)
             .order_by(AnalysisResultModel.id.asc()).first())
    peak = (db.query(AnalysisResultModel.id).filter(AnalysisResultModel.ioc_id == ioc_id)
            .order_by(AnalysisResultModel.risk_score.desc(), AnalysisResultModel.id.asc()).first())
    return {row.id for row in (first, peak) if row}


def trim_history(db, ioc_id: int) -> None:
    """Bir gostergenin son MAX_RESULTS_PER_IOC analiz sonucunu tutar; ilk ve en yuksek skorlu
    analiz her zaman korunur (B-08)."""
    keep = max(1, settings.MAX_RESULTS_PER_IOC)
    protected = protected_result_ids(db, ioc_id)
    old_ids = [
        row.id for row in
        db.query(AnalysisResultModel.id)
        .filter(AnalysisResultModel.ioc_id == ioc_id)
        .order_by(AnalysisResultModel.id.desc())
        .offset(keep)
        .limit(PURGE_BATCH)
        if row.id not in protected
    ]
    if old_ids:
        db.query(AnalysisResultModel).filter(AnalysisResultModel.id.in_(old_ids)).delete(synchronize_session=False)


def purge_expired(db) -> int:
    """Saklama suresi dolan kayitlari siler. Silinen gosterge sayisini doner."""
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, settings.IOC_RETENTION_DAYS))
    db.query(AnalysisResultModel).filter(AnalysisResultModel.created_at < cutoff).delete(synchronize_session=False)

    stale_ids = [
        row.id for row in
        db.query(IOCModel.id)
        .filter(IOCModel.created_at < cutoff)
        .filter(~exists().where(AnalysisResultModel.ioc_id == IOCModel.id))
        .filter(~exists().where(CampaignIOCModel.ioc_id == IOCModel.id))
        .limit(PURGE_BATCH)
    ]
    if stale_ids:
        _delete_iocs(db, stale_ids)
    db.commit()
    return len(stale_ids) + enforce_row_cap(db)


def _delete_iocs(db, ids) -> None:
    db.query(AnalysisResultModel).filter(AnalysisResultModel.ioc_id.in_(ids)).delete(synchronize_session=False)
    for model in (DomainModel, IPModel, URLModel):
        db.query(model).filter(model.ioc_id.in_(ids)).delete(synchronize_session=False)
    db.query(IOCModel).filter(IOCModel.id.in_(ids)).delete(synchronize_session=False)


def enforce_row_cap(db) -> int:
    """Toplam gosterge sayisi IOC_MAX_ROWS'u asarsa kampanyaya bagli olmayan gostergeleri siler (Z-09).
    Silme sirasi degere goredir (B-08): once dusuk riskli, sonra orta/yuksek, en son kritik kayitlar;
    her grupta en eskiden baslanir. Kayit tablosunu yeni adreslerle dolduran istemci boylece
    kritik kayitlari sildiremez. Silinen gosterge sayisini doner."""
    cap = max(1, settings.IOC_MAX_ROWS)
    removed = 0
    while True:
        excess = db.query(IOCModel.id).count() - cap
        if excess <= 0:
            return removed
        ids = [
            row.id for row in
            db.query(IOCModel.id)
            .filter(~exists().where(CampaignIOCModel.ioc_id == IOCModel.id))
            .order_by(case((IOCModel.risk_score >= 75, 2), (IOCModel.risk_score >= 25, 1), else_=0),
                      IOCModel.id.asc())
            .limit(min(excess, PURGE_BATCH))
        ]
        if not ids:
            return removed
        _delete_iocs(db, ids)
        db.commit()
        removed += len(ids)
        logger.warning("ioc row cap reached cap=%d removed_oldest=%d", cap, len(ids))


def maybe_purge(session_factory) -> None:
    """En fazla PURGE_INTERVAL_SECONDS'da bir, kendi oturumuyla temizlik yapar. Hata analizi bozmaz."""
    global _last_purge
    now = time.monotonic()
    with _lock:
        if _last_purge and now - _last_purge < PURGE_INTERVAL_SECONDS:
            return
        _last_purge = now
    db = session_factory()
    try:
        removed = purge_expired(db)
        if removed:
            logger.info("retention purge removed_iocs=%d", removed)
    except Exception:
        db.rollback()
        logger.exception("retention purge failed")
    finally:
        db.close()
