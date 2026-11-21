import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from backend.core.list_rules import InvalidPatternError, canonical_pattern
from backend.models.database import SessionLocal, get_db
from backend.models.list_model import ListModel
from backend.schemas.list_schema import ListCreateRequest, ListItemResponse
from backend.api.routes_auth import client_ip, require_admin

# Kural ekleme/silme islemleri denetim kaydina yazilir: kim (yonetici oturumu), ne zaman, hangi IP (Y-07)
audit = logging.getLogger("mihenk.audit")

router = APIRouter(prefix="/lists", tags=["Whitelist & Blacklist"])
logger = logging.getLogger("mihenk.lists")


def _disabled_reason(item: ListModel) -> Optional[str]:
    try:
        canonical_pattern(item.entry_type, item.pattern)
        return None
    except InvalidPatternError as exc:
        return f"Kural uygulanmıyor: {exc}"


def _with_status(item: ListModel) -> ListItemResponse:
    response = ListItemResponse.model_validate(item)
    response.disabled_reason = _disabled_reason(item)
    return response


def audit_list_rules() -> int:
    """Acilista kayitli kurallari bugunku dogrulamadan gecirir (Z-05). Gecersiz kurallar
    silinmez; eslestirmede uygulanmaz (analyzer_interface._rule_key), burada kayda yazilir
    ve yonetici panelinde nedeniyle gosterilir. Gecersiz kural sayisini doner."""
    db = SessionLocal()
    try:
        invalid = 0
        for item in db.query(ListModel).all():
            reason = _disabled_reason(item)
            if reason:
                invalid += 1
                audit.warning("list rule disabled id=%s list=%s type=%s pattern=%r reason=%s",
                              item.id, item.list_type, item.entry_type, item.pattern, reason)
        return invalid
    finally:
        db.close()

@router.get("", response_model=List[ListItemResponse], summary="Whitelist ve Blacklist kurallarını listeler (Yalnızca Admin)")
@router.get("/", response_model=List[ListItemResponse], include_in_schema=False)
def get_list_entries(
    list_type: Optional[str] = Query(None, description="Filtreleme: 'whitelist' veya 'blacklist'"),
    db: Session = Depends(get_db),
    _admin: bool = Depends(require_admin)
):
    query = db.query(ListModel)
    if list_type:
        if list_type not in ["whitelist", "blacklist"]:
            raise HTTPException(status_code=400, detail="Görünüm türü 'whitelist' veya 'blacklist' olmalıdır.")
        query = query.filter(ListModel.list_type == list_type)
    return [_with_status(item) for item in query.order_by(ListModel.created_at.desc()).all()]

@router.post("", response_model=ListItemResponse, status_code=status.HTTP_201_CREATED, summary="Yeni Whitelist veya Blacklist kuralı ekler (Yalnızca Admin)")
@router.post("/", response_model=ListItemResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_list_entry(
    request: ListCreateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _admin: bool = Depends(require_admin)
):
    # Kalip kaydedilmeden once dogrulanir ve kanonik ASCII bicime getirilir: ust alan adi,
    # genel sonek ve paylasimli barindirma sonekleri reddedilir (Y-07)
    try:
        pattern_clean = canonical_pattern(request.entry_type, request.pattern)
    except InvalidPatternError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    existing = db.query(ListModel).filter(
        ListModel.list_type == request.list_type,
        ListModel.pattern == pattern_clean
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail=f"Bu pattern zaten {request.list_type} listesinde mevcut.")

    new_item = ListModel(
        list_type=request.list_type,
        entry_type=request.entry_type,
        pattern=pattern_clean,
        description=request.description
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    audit.info("list rule added id=%s list=%s type=%s pattern=%r actor=admin ip=%s",
               new_item.id, new_item.list_type, new_item.entry_type, new_item.pattern, client_ip(http_request))
    return _with_status(new_item)

@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Whitelist veya Blacklist kuralını siler (Yalnızca Admin)")
def delete_list_entry(
    item_id: int,
    http_request: Request,
    db: Session = Depends(get_db),
    _admin: bool = Depends(require_admin)
):
    item = db.query(ListModel).filter(ListModel.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Silinecek kural bulunamadı.")
    
    snapshot = (item.id, item.list_type, item.entry_type, item.pattern)
    db.delete(item)
    db.commit()
    audit.info("list rule deleted id=%s list=%s type=%s pattern=%r actor=admin ip=%s",
               *snapshot, client_ip(http_request))
    return None
