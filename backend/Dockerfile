# Taban imajlar surum + SHA-256 ozetiyle sabitlidir (Y-04); guncellemeler Dependabot ile
# gelir (.github/dependabot.yml) ve CI'da Trivy ile taranir.

# --- Arayuz derlemesi ---------------------------------------------------------
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.js tailwind.config.js postcss.config.js ./
COPY public ./public
COPY src ./src
COPY docs/logo.jpg ./docs/logo.jpg
RUN npm run build

# --- Arka uc --------------------------------------------------------------------
FROM python:3.11.18-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# Isletim sistemi paketlerinin yayimlanmis guvenlik guncellemeleri
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Surumleri ve SHA-256 ozetleri sabitlenmis bagimliliklar
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --require-hashes -r backend/requirements.txt \
 # Calisma zamaninda gerekmeyen paketleme araclari kaldirilir (Z-08): setuptools icine gomulu
 # wheel ve jaraco.context kayitlari imaj taramasinda YUKSEK olarak cikiyordu.
 && pip uninstall -y setuptools wheel

COPY backend ./backend
COPY --from=frontend /app/dist ./dist

# Yetkisiz kullanici; uygulama dosyalari root'a ait ve salt okunur kalir
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mihenk
USER 10001

EXPOSE 8000
# Tek surec: oturumlar ve istek sayaclari surec belleginde tutulur.
# Vekil basliklarina (X-Forwarded-For) yalnizca FORWARDED_ALLOW_IPS ortam degiskenindeki
# adres(ler)den guvenilir (Y-08). Varsayilan 127.0.0.1'dir; Compose bunu vekilin sabit
# adresine ayarlar. Asla '*' kullanmayin: arka uca ulasabilen her kaynak istemci IP'sini
# belirleyip hiz sinirini ve giris kilidini atlatabilir.
ENV FORWARDED_ALLOW_IPS=127.0.0.1
# B-03 / A-07: ortak eszamanlilik siniri SON savunmadir (asilinca herkes 503 alir); asil sinirlar istemci
# basinadir (MAX_INFLIGHT_PER_CLIENT, analiz hiz siniri) ve vekil govdeyi tamponlar (deploy/Caddyfile).
# Bosta kalan baglanti 5 saniyede kapatilir; govdesi tamamlanmayan istek 10 saniyede 408 alir.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--no-server-header", "--workers", "1", \
     "--limit-concurrency", "1024", "--timeout-keep-alive", "5"]
