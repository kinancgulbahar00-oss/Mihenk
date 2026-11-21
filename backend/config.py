from pydantic_settings import BaseSettings, SettingsConfigDict

import hashlib

# Depoda, belgelerde veya eski surumlerde yer almis; artik parola olarak kabul edilmeyen
# degerlerin SHA-256 ozetleri (duz metin tekrar yayimlanmasin diye ozet olarak tutulur)
_KNOWN_WEAK_PASSWORD_HASHES = {
    "cde4418522f276a944f5ca7e95b61a3f2927aba273befe628d7d346e172978ce",
    "05fa5533e1d05257453d2fb2075391fd1b1ec833afddc7499750e82d443d595e",
    "057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86",
    "e2186dbdb1bb4193608605e84f33208765b5693b55edd4f730a719a100eeea6f",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
}


def is_known_weak_password(password: str) -> bool:
    normalized = (password or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest() in _KNOWN_WEAK_PASSWORD_HASHES


class Settings(BaseSettings):
    PROJECT_NAME: str = "Phishing Campaign Intelligence Platform"
    VERSION: str = "2.0.0"
    API_V1_STR: str = ""

    DATABASE_URL: str = "sqlite:///./cti_platform.db"

    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # Sayfa icerigi analizi: supheli sayfa JavaScript calistirilmadan indirilir
    PAGE_FETCH_ENABLED: bool = True

    # --- Yonetici (Admin) yetkilendirme -----------------------------------------
    # Kodda varsayilan parola YOKTUR. Ikisinden biri tanimlanmazsa sunucu baslamaz.
    # Onerilen: ADMIN_PASSWORD_HASH (uretmek icin: py -3.11 -m backend.hash_password)
    ADMIN_PASSWORD_HASH: str = ""
    ADMIN_PASSWORD: str = ""
    ADMIN_SESSION_TTL_MINUTES: int = 8 * 60
    # Oturum cerezi yalnizca HTTPS uzerinden gonderilir. Duz HTTP ile yerel gelistirme
    # yapiyorsaniz (http://localhost disinda bir adres) false yapin.
    COOKIE_SECURE: bool = True

    # Giris denemesi siniri (IP basina)
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_WINDOW_SECONDS: int = 15 * 60

    # Tum istemciler icin ortak, saatlik hatali giris esigi (IP'den bagimsiz; Y-05). Esik asildiginda
    # giris REDDEDILMEZ; her deneme LOGIN_GLOBAL_DELAY_SECONDS geciktirilir ve uyari kaydi uretilir.
    # Dogru parola baskalarinin hatali denemeleri yuzunden hicbir zaman reddedilmez (Z-03).
    LOGIN_GLOBAL_MAX_FAILURES: int = 50
    LOGIN_GLOBAL_DELAY_SECONDS: float = 2.0

    # Yonetici erisimi icin guvenilen ag araliklari (virgulle ayrilmis CIDR, or. "10.20.0.0/16,192.0.2.7/32").
    # Bu araliklardan gelen girisler genel esikten etkilenmez (Z-03). ADMIN_RESTRICT_TO_TRUSTED=true ise
    # yonetici girisi ve yonetici uc noktalari YALNIZCA bu araliklardan kullanilabilir.
    ADMIN_TRUSTED_NETWORKS: str = ""
    ADMIN_RESTRICT_TO_TRUSTED: bool = False

    # Ikinci etken (TOTP, RFC 6238). Tanimliysa giriste parola + 6 haneli kod istenir.
    # Uretmek icin: py -3.11 -m backend.totp_secret
    ADMIN_TOTP_SECRET: str = ""

    # Analiz istegi siniri (IP basina, dakikada) ve ayni anda calisan analiz sayisi
    ANALYZE_RATE_PER_MINUTE: int = 20
    # Analiz cogunlukla ag beklemesidir; hedef basina sinir ve yavas hedef karantinasi (Z-04)
    # sayesinde ortak yuvalar tek bir yavas sunucuya baglanamaz
    ANALYZE_MAX_CONCURRENT: int = 12
    # Tek bir istemcinin ayni anda tutabilecegi analiz yuvasi (Y-02)
    ANALYZE_MAX_CONCURRENT_PER_CLIENT: int = 1
    # Analiz hattinin tamami icin ust sure (saniye); asilirsa istemci 504 alir (Y-02)
    ANALYZE_TIMEOUT_SECONDS: int = 45

    # Istek govdesi ust siniri (bayt). En buyuk mesru istek birkac kilobayttir (Y-03)
    MAX_REQUEST_BODY_BYTES: int = 16 * 1024
    # Istek govdesinin tamamlanmasi icin ust sure (saniye). Yarim birakilan govde bellek ve baglanti
    # tutar (B-03); ters vekildeki read_body siniriyla birlikte savunma derinligidir.
    REQUEST_BODY_TIMEOUT_SECONDS: float = 10.0
    # Bir istemcinin ayni anda islenen (govdesi okunmakta olanlar dahil) POST/PUT/PATCH/DELETE istegi
    # siniri (A-07). Uygulama sunucusunun ortak siniri (uvicorn --limit-concurrency) bunun cok ustundedir.
    MAX_INFLIGHT_PER_CLIENT: int = 6

    # Sayfa yoklamasinin kullandigi Chrome ana surumu (User-Agent ve sec-ch-ua basliklari; A-05).
    # Guncel kararli surumle birlikte artirilmalidir; eski surum yoklamayi ayirt edilebilir kilar.
    PROBE_CHROME_MAJOR: int = 156

    # Kimligi dogrulanmamis analizlerin olusturdugu kayitlarin saklama suresi (gun) ve
    # gosterge basina tutulan en fazla analiz sonucu (Y-09)
    IOC_RETENTION_DAYS: int = 90
    MAX_RESULTS_PER_IOC: int = 20
    # Toplam gosterge sayisi ust siniri (Z-09). Asildiginda kampanyaya bagli olmayan en eski
    # gostergeler silinir; tek bir istemci saklama suresi icinde tabloyu sinirsiz buyutemez.
    IOC_MAX_ROWS: int = 200_000

    # Virgulle ayrilmis kokenler. Arayuz arka uc tarafindan ayni kokenden sunuldugunda bos kalabilir.
    CORS_ORIGINS: str = ""

    # Sitenin herkese acik adresi (orn. https://mihenk.example.com). Tanimliysa ana sayfa arama motorlarina acilir:
    # canonical, Open Graph adresi, yapilandirilmis veri, robots.txt ve sitemap.xml bu adresle uretilir. Bos ise
    # (yerel kurulum, ic ag, deneme ortami) butun sayfalar `noindex` olur ve robots.txt taramayi kapatir.
    PUBLIC_BASE_URL: str = ""

    # Swagger / ReDoc / OpenAPI semasi yalnizca acikca istenirse yayinlanir
    ENABLE_API_DOCS: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def admin_trusted_networks(self) -> list:
        import ipaddress

        networks = []
        for item in self.ADMIN_TRUSTED_NETWORKS.split(","):
            item = item.strip()
            if item:
                networks.append(ipaddress.ip_network(item, strict=False))
        return networks

    @property
    def cors_origins(self) -> list[str]:
        origins = [o.strip().rstrip("/") for o in self.CORS_ORIGINS.split(",") if o.strip()]
        # Joker koken kimlik bilgisiyle birlikte hicbir zaman kabul edilmez
        return [o for o in origins if o != "*"]


settings = Settings()
