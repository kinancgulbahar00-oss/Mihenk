# Dağıtım notları

## İstemci başına bağlantı sınırı (B-03)

`deploy/Caddyfile` başlık ve gövde okuma sürelerini 10 saniyeyle sınırlar; yarım bırakılan istekler
bu sürede kapatılır. Caddy'nin temel sürümü **istemci başına bağlantı sayısını** sınırlayamaz. Hizmet
doğrudan internete açılıyorsa ana makinenin güvenlik duvarında sınır koyun:

```sh
# Tek bir IPv4 adresinden 443/80 portlarına aynı anda en fazla 100 bağlantı
iptables  -I DOCKER-USER -p tcp -m multiport --dports 80,443 --syn \
          -m connlimit --connlimit-above 100 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
# IPv6: /64 önekine göre toplanır (tek bir /64 sınırsız adres üretebilir)
ip6tables -I DOCKER-USER -p tcp -m multiport --dports 80,443 --syn \
          -m connlimit --connlimit-above 100 --connlimit-mask 64 -j REJECT --reject-with tcp-reset
```

`DOCKER-USER` zinciri Docker'ın yayımladığı portlara uygulanır. Hizmet bir CDN/WAF arkasındaysa sınırı
orada tanımlayın ve Caddy'de `trusted_proxies` ayarlayın; aksi halde bütün istemciler CDN adresiyle
görünür ve tek bir kotayı paylaşır.

## Yarım bırakılan istekler (A-07)

Üç katman birlikte çalışır; birini kaldırmayın:

1. `deploy/Caddyfile` → `request_buffers`: vekil istek gövdesini tamamen aldıktan sonra arka uca bağlanır;
   gövdesi yarım bırakılan istek arka uca hiç ulaşmaz (`read_body 10s` sonunda vekil kapatır).
2. Uygulama → `MAX_INFLIGHT_PER_CLIENT` (varsayılan 6): bir istemcinin aynı anda işlenen POST/DELETE isteği
   sınırı, gövde okunmadan uygulanır; yönetici ağ kısıtı da gövdeden önce denetlenir.
3. Uvicorn `--limit-concurrency 1024`: herkes için ortak, **son** savunmadır. Aşılırsa bütün istekler (sağlık
   denetimi dahil) 503 alır; arka uç kaydındaki “Exceeded concurrency limit” satırları için uyarı tanımlayın.

## İstemci adresinin doğruluğu (B-11)

Hız sınırları, giriş sayaçları ve yoklama bütçeleri vekilin bildirdiği istemci adresine dayanır.
Docker Desktop (Windows, macOS) üzerinde ve Linux'ta IPv6 isteklerinin kullanıcı alanı vekiliyle
iletildiği kurulumlarda bütün istemciler tek bir ağ geçidi adresiyle görünür. Üretim için Linux ve
doğrudan port eşlemesi kullanın; açılışta arka uç kaydındaki `client` adreslerinin çeşitlendiğini
denetleyin.

## Sağlık denetimi ve yeniden başlatmalar

Compose dosyasında arka uç (`/health`) ve vekil (Caddy yönetim API'si, yalnızca konteyner içinden)
için sağlık denetimi tanımlıdır. Yeniden başlatma sayısını izleyin:

```sh
docker inspect -f '{{.Name}} restarts={{.RestartCount}} health={{.State.Health.Status}}' \
  cti_caddy_proxy cti_fastapi_backend
```

## Kurum kataloğu (B-07)

Katalogdaki her resmi alan adının kayıtlı ve çözümlenir olduğu haftalık CI işinde denetlenir
(`.github/workflows/security.yml`, `catalog-health`). Elle:

```sh
py -3.11 -m backend.tools.catalog_health
```

Araç `.tr` adlarını TRABİS WHOIS ile, diğerlerini RDAP ile sorar (yaklaşık 5 dakika; `rdap.org` istek hızını
sınırlar). Çıkış kodu yalnızca **hata** sınıfında (kayıtlı değil, askıda, kaydı 30 günden az kalmış) 1 olur;
çözümlenmeyen ya da doğrulanamayan adlar uyarıdır. Kabul edilmiş durumlar `tr_brands.json` içindeki
`health_exceptions` alanına gerekçesiyle yazılır.
