"""Yonetici parolasi icin ADMIN_PASSWORD_HASH degeri uretir.

Kullanim:  py -3.11 -m backend.hash_password
Cikan degeri .env dosyasina TEK TIRNAK icinde yazin (deger '$' icerir; tek tirnak hem
Docker Compose'da hem yerel calistirmada degeri oldugu gibi korur):

    ADMIN_PASSWORD_HASH='scrypt$16384$8$1$...'
"""

import getpass
import sys

from backend.config import is_known_weak_password
from backend.core.security import hash_password, password_policy_problem


def main():
    password = getpass.getpass("Yeni yonetici parolasi: ")
    problem = password_policy_problem(password)
    if problem or is_known_weak_password(password):
        sys.exit(problem or "Bu parola bilinen/ifsa olmus bir ornek deger; kullanilamaz.")
    if getpass.getpass("Tekrar: ") != password:
        sys.exit("Parolalar eslesmiyor.")
    print(f"ADMIN_PASSWORD_HASH='{hash_password(password)}'")


if __name__ == "__main__":
    main()
