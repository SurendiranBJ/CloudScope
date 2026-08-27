import sys
from pathlib import Path

# Ensure the backend app package is importable when running pytest from
# the backend/ directory (i.e. `cd backend && python -m pytest tests/`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
