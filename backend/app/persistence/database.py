from app.config import settings
"""
CloudScope Durable Relational Database Configuration.

Provides connection pooling, session lifecycle management, and schema initialization
for SQLite (development) and PostgreSQL (production).
"""

import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_DB_FILE = os.path.join(DATA_DIR, "cloudscope.db")
DATABASE_URL = settings.DATABASE_URL

engine_kwargs = {"echo": False}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # PostgreSQL production pool configuration
    engine_kwargs.update({
        "pool_size": settings.DB_POOL_SIZE if hasattr(settings, "DB_POOL_SIZE") else 10,
        "max_overflow": settings.DB_MAX_OVERFLOW if hasattr(settings, "DB_MAX_OVERFLOW") else 20,
        "pool_timeout": settings.DB_POOL_TIMEOUT if hasattr(settings, "DB_POOL_TIMEOUT") else 30,
        "pool_pre_ping": True,
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    """Create all relational tables if they do not already exist and migrate columns."""
    Base.metadata.create_all(bind=engine)
    try:
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        if "scan_snapshots" in inspector.get_table_names():
            existing_cols = {c["name"] for c in inspector.get_columns("scan_snapshots")}
            new_cols = [
                ("collection_completeness_json", "TEXT DEFAULT '{}'"),
                ("users_json", "TEXT DEFAULT '[]'"),
                ("groups_json", "TEXT DEFAULT '[]'"),
                ("roles_json", "TEXT DEFAULT '[]'"),
                ("policies_json", "TEXT DEFAULT '[]'"),
                ("resources_json", "TEXT DEFAULT '[]'"),
                ("alerts_json", "TEXT DEFAULT '[]'"),
                ("correlated_risks_json", "TEXT DEFAULT '[]'"),
                ("findings_json", "TEXT DEFAULT '[]'"),
                ("risks_json", "TEXT DEFAULT '[]'"),
                ("attack_paths_json", "TEXT DEFAULT '[]'"),
                ("graph_json", "TEXT DEFAULT '[]'"),
                ("effective_access_json", "TEXT DEFAULT '[]'"),
                ("dashboard_json", "TEXT DEFAULT '{}'"),
                ("scan_metadata_json", "TEXT DEFAULT '{}'"),
                ("is_current", "INTEGER DEFAULT 0"),
            ]
            with engine.connect() as conn:
                for col_name, col_def in new_cols:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE scan_snapshots ADD COLUMN {col_name} {col_def}"))
                conn.commit()
    except Exception:
        pass


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session scope."""
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_db_connectivity() -> bool:
    """Quick check for database connectivity."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
