"""Yonetici girisi icin ikinci etken (TOTP) sirri uretir (Z-03).

Kullanim:  py -3.11 -m backend.totp_secret

Cikan ADMIN_TOTP_SECRET satirini .env dosyasina yazin ve otpauth:// adresini (veya sirri)
bir dogrulayici uygulamaya (Google Authenticator, Microsoft Authenticator, Aegis, 1Password...)
ekleyin. Sir tanimlandiktan sonra giriste parola ile birlikte 6 haneli kod istenir.
Sirri baska bir yere kaydetmeyin; kaybedilirse yenisini uretip .env'i guncelleyin.
"""

import base64
import secrets
from urllib.parse import quote


def main():
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    label = quote("Mihenk:admin")
    print(f"ADMIN_TOTP_SECRET={secret}")
    print(f"otpauth://totp/{label}?secret={secret}&issuer=Mihenk&algorithm=SHA1&digits=6&period=30")


if __name__ == "__main__":
    main()
