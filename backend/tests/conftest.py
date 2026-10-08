import os
import sys
import tempfile
from pathlib import Path

# Ensure the backend app package is importable when running pytest from
# the backend/ directory (i.e. `cd backend && python -m pytest tests/`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Tests must never read or mutate a developer's local database. Use one fresh
# SQLite file per pytest process; production keeps its configured durable store.
_test_db_dir = tempfile.mkdtemp(prefix="cloudscope-pytest-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{Path(_test_db_dir) / 'cloudscope-tests.sqlite'}")

# Set test environment defaults
os.environ.setdefault("JWT_SECRET", "phase2-test-secret-key-32-chars-long!")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("OIDC_ISSUER_URL", "https://auth.cloudscope.test")
os.environ.setdefault("OIDC_AUDIENCE", "cloudscope-api")
os.environ.setdefault("DEV_AUTH_MODE", "false")


import pytest


@pytest.fixture(autouse=True)
def isolate_published_state_between_tests():
    """Prevent cache/snapshot/database state leaking across test cases."""
    try:
        from app.cache import cache
        from app.services.scanner.snapshot_store import snapshot_store
        from app.persistence.database import get_db_session
        from app.persistence.models import (
            ScanRunModel, ScanSnapshotModel, CurrentSnapshotPointerModel,
            FindingStateModel, AuditEventModel,
        )

        with cache._lock:
            cache.local_cache.clear()
            cache._local_expiry.clear()
        snapshot_store.clear()
        with get_db_session() as session:
            for model in (CurrentSnapshotPointerModel, ScanSnapshotModel, ScanRunModel, FindingStateModel, AuditEventModel):
                session.query(model).delete()
    except Exception:
        # Import-time setup may be incomplete for tests that only inspect source.
        pass
    yield
