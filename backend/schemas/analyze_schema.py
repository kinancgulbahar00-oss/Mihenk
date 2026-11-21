from typing import List, Optional
from pydantic import BaseModel, HttpUrl, Field

class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Analiz edilecek URL veya domain adresi", examples=["https://verify-account-update.com"])

class ReasonItem(BaseModel):
    rule_name: str
    description: str
    severity: str = "medium"
    contribution: Optional[int] = Field(None, description="Bulgunun skora katkisi (puan); eksi deger skoru dusurur")

class IOCDetails(BaseModel):
    domain: Optional[str] = None
    registrar: Optional[str] = None
    domain_age_days: Optional[int] = None
    domain_registration_date: Optional[str] = None
    ip_address: Optional[str] = None
    abuse_score: Optional[int] = None
    ip_reports_count: Optional[int] = None
    abuse_status: Optional[str] = None
    url: Optional[str] = None
    vt_positives: Optional[int] = None
    vt_total: Optional[int] = None
    vt_status: Optional[str] = None
    has_https: bool = False
    tls_status: Optional[str] = Field(None, description="valid | invalid | none | unreachable")
    target_brand: Optional[str] = Field(None, description="Taklit edildigi degerlendirilen kurum")
    target_sector: Optional[str] = None
    page_status: Optional[str] = Field(None, description="ok | not_html | empty | download | error | disabled | unreachable | too_many_redirects | port_not_allowed | target_busy | slow_target")
    page_title: Optional[str] = None
    final_url: Optional[str] = Field(None, description="Yonlendirme sonrasi ulasilan adres")
    page_fields: List[str] = Field(default_factory=list, description="Sayfanin istedigi hassas alanlar")
    page_cached_at: Optional[str] = Field(None, description="Sayfa yoklamasi onbellekten geldiyse yoklamanin yapildigi an (UTC, ISO 8601)")
    inspection_coverage: Optional[str] = Field(None, description="full | partial | none | list: sayfa iceriginin ne olcude incelendigi (B-01, B-02)")
    inspection_gaps: Optional[List[str]] = Field(None, description="Incelenemeyen yapilar: script | frame | truncated | xml_dtd | delayed_refresh (A-01)")
    download: Optional[dict] = Field(None, description="Adres dogrudan dosya indiriyorsa dosya turu, adi ve SHA-256 ozeti (B-10)")

class MitreTechnique(BaseModel):
    id: str
    tactic: str
    technique: str

class RelatedDomain(BaseModel):
    domain: str
    similarity: int

class AnalyzeResponse(BaseModel):
    id: Optional[int] = None
    url: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | SAFE. UNKNOWN: sayfa icerigi tam "
                                             "incelenemedi ve skor dusuk; 'guvenli' anlamina gelmez (A-13)")
    reasons: List[ReasonItem] = []
    ioc_details: IOCDetails
    mitre_techniques: List[MitreTechnique] = []
    related_domains: List[RelatedDomain] = []

class IOCResponse(BaseModel):
    id: int
    type: str
    value: str
    # Kayitli karar: son 30 gundeki en yuksek karar ya da analist liste karari (B-08)
    risk_score: int
    risk_level: str
    last_risk_score: Optional[int] = Field(None, description="Son analizin skoru (B-08)")
    last_risk_level: Optional[str] = None
    first_seen: str
    ioc_details: Optional[IOCDetails] = None
    mitre_techniques: List[MitreTechnique] = []
    related_domains: List[RelatedDomain] = []

class CampaignResponse(BaseModel):
    id: int
    name: str
    confidence: str
    target_brand: Optional[str] = None
    description: Optional[str] = None
    iocs: List[IOCResponse] = []
