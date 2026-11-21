"""Ayristirma iscisi: ayri bir surecte calisir, yalnizca HTML metni alir ve duz veri dondurur (E-01).

Isci surec uygulama ayarlarini, veritabani baglantisini ve oturum durumunu YUKLEMEZ; ortam degiskenleri
(parola ozeti, veritabani adresi) isciye aktarilmaz. Saldirganin denetimindeki belge burada islenir.
Ayristirici kilitlenirse ya da cokerse ana surec isciyi sonlandirir.

Iletisim: standart girdi/cikti uzerinden, 4 baytlik uzunluk + UTF-8 JSON. Ana surec iscinin ciktisini
yalnizca JSON olarak okur (pickle kullanilmaz): ele gecirilmis bir isci ana surecte kod calistiramaz.
"""

import json
import struct
import sys

MAX_MESSAGE_BYTES = 16 * 1024 * 1024


def _limit_resources():
    try:
        import resource

        # Tek bir belge icin adres alani ust siniri: asiri buyuyen agac bellek hatasiyla sonuclanir.
        # En agir 1 MB'lik belge ~180 MiB kullanir. Uc iscinin sinirlarinin toplami konteyner sinirini
        # (docker-compose.yml: mem_limit) asmamalidir (G-08).
        limit = 640 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:
        pass  # Windows'ta `resource` yoktur; kap siniri (mem_limit) gecerlidir


def read_message(stream):
    header = stream.read(4)
    if len(header) < 4:
        return None
    (size,) = struct.unpack(">I", header)
    if size > MAX_MESSAGE_BYTES:
        return None
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))


def write_message(stream, obj):
    # Tek basina vekil (surrogate) kod noktalari UTF-8'e cevrilemez; JSON kacisi olarak tasinir
    data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    stream.write(struct.pack(">I", len(data)) + data)
    stream.flush()


def main():
    from backend.sandbox import html_extract

    _limit_resources()  # kitapliklar yuklendikten SONRA: sinir yalnizca belge islemeyi kapsar

    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    while True:
        try:
            job = read_message(stdin)
        except Exception:
            return
        if not isinstance(job, dict):
            return
        try:
            result = {"ok": True, "facts": html_extract.extract(job.get("html", ""), bool(job.get("xml")))}
        except MemoryError:
            result = {"ok": False, "error": "memory"}
        except BaseException as exc:  # saldirgan girdisi isciyi dusurmemeli
            result = {"ok": False, "error": type(exc).__name__}
        try:
            write_message(stdout, result)
        except Exception:
            return


if __name__ == "__main__":
    main()
