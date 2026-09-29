import os
import sys
from pathlib import Path

# Ensure the backend app package is importable when running pytest from
# the backend/ directory (i.e. `cd backend && python -m pytest tests/`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set test environment defaults
os.environ.setdefault("JWT_SECRET", "phase2-test-secret-key-32-chars-long!")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("OIDC_ISSUER_URL", "https://auth.cloudscope.test")
os.environ.setdefault("OIDC_AUDIENCE", "cloudscope-api")
os.environ.setdefault("DEV_AUTH_MODE", "false")
