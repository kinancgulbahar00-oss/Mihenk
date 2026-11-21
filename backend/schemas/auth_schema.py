from pydantic import BaseModel, Field


class AdminLoginRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256, description="Yönetici erişim parolası")
    remember: bool = Field(False, description="Oturum çerezi tarayıcı kapansa da süre sonuna kadar korunsun")
    otp: str | None = Field(None, max_length=16, description="İkinci etken doğrulama kodu (ADMIN_TOTP_SECRET tanımlıysa zorunlu)")


class AdminLoginResponse(BaseModel):
    # Oturum anahtari yanitta DONMEZ; yalnizca HttpOnly cerezde tasinir
    success: bool
    role: str = "admin"
    message: str = "Giriş başarılı."


class AdminVerifyResponse(BaseModel):
    valid: bool
    role: str = "admin"


class AdminStatsResponse(BaseModel):
    total_iocs: int
    total_campaigns: int
    blacklist_count: int
    whitelist_count: int
    critical_iocs: int
    high_iocs: int
    database_type: str
    vt_active: bool
    abuse_active: bool
    # Fiili guvenlik durumu (D-04): ayarlarin uygulamaya gercekten ulastigi panelde gorulur
    second_factor_enabled: bool = False
    trusted_networks: int = 0
    restrict_to_trusted: bool = False
    login_max_failures: int = 0
    analyze_rate_per_minute: int = 0
