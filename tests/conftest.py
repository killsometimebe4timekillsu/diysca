import os

import pytest

from diysca.core import db
from diysca.core.config import settings

# Run the suite against PostgreSQL with: DIYSCA_TEST_DATABASE_URL=postgresql://... pytest
PG_URL = os.environ.get("DIYSCA_TEST_DATABASE_URL", "")


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    monkeypatch.setattr(settings, "db_path", str(tmp_path / "t.db"))
    monkeypatch.setattr(settings, "database_url", PG_URL)
    monkeypatch.setattr(settings, "inventories", [])
    monkeypatch.setattr(settings, "nvd_enabled", False)
    monkeypatch.setattr(settings, "kev_enabled", False)
    monkeypatch.setattr(settings, "repo_fetch", "off")
    monkeypatch.setattr(settings, "scan_interval_hours", 0)
    from diysca.core import security
    security.limiter.reset()
    db.reset_for_tests()
    db.drop_all_for_tests()
    db.connect()
    yield
    db.reset_for_tests()
