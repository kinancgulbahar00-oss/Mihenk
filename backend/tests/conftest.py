"""Test ortami: ayarlar modul yuklenirken okundugu icin ortam degiskenleri burada,
herhangi bir backend modulu import edilmeden once tanimlanir. Ag erisimi gerektirmez."""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="mihenk-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.environ.setdefault("ADMIN_PASSWORD", "test-only-Very-Long-Passphrase-42")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("PAGE_FETCH_ENABLED", "false")
os.environ.setdefault("ENABLE_API_DOCS", "false")
os.environ.setdefault("CORS_ORIGINS", "")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_target_guard():
    """Yavas hedef karantinasi ve hedef kilitleri surec geneldir (Z-04); testler birbirini etkilemesin."""
    from backend.core.netguard import targets

    targets.reset()
    yield
    targets.reset()
