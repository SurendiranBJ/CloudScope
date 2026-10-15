from app.config import settings
"""
CloudScope Durable Relational Database Configuration.

Provides connection pooling, session lifecycle management, and schema initialization
for SQLite (development) and PostgreSQL (production).
"""

import os
import logging
from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger("cloudscope.database")

def resolve_database_url(url: Optional[str] = None) -> str:
    """
    Establish one explicit, predictable database location:
    1. In Docker: /app/storage/cloudscope.db when /app/storage exists.
    2. On host: deterministic location in backend directory so different CWDs never read different SQLite files.
    3. Custom/test URLs (e.g. absolute paths, :memory:, postgresql) are preserved as-is.
    """
    raw_url = url or settings.DATABASE_URL or ""

    # Docker container persistent volume for the application default only.
    # Explicit SQLite paths and non-SQLite URLs must remain user-controlled.
    if os.path.isdir("/app/storage") and raw_url in ("", "sqlite:///./cloudscope.db"):
        os.makedirs("/app/storage", exist_ok=True)
        return "sqlite:////app/storage/cloudscope.db"

    # SQLite relative URL resolution to predictable backend directory
    if raw_url.startswith("sqlite:///"):
        path_part = raw_url[len("sqlite:///"):]
        # Memory or absolute paths stay untouched
        if path_part != ":memory:" and not os.path.isabs(path_part) and not path_part.startswith("/") and not path_part.startswith("\\"):
            backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            normalized_rel = os.path.normpath(path_part)
            abs_db_path = os.path.abspath(os.path.join(backend_dir, normalized_rel))
            os.makedirs(os.path.dirname(abs_db_path), exist_ok=True)
            return f"sqlite:///{abs_db_path.replace(os.sep, '/')}"

    return raw_url if raw_url else "sqlite:///./cloudscope.db"


DATABASE_URL = resolve_database_url(settings.DATABASE_URL)

engine_kwargs = {"echo": False}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30.0}
else:
    # PostgreSQL production pool configuration
    engine_kwargs.update({
        "pool_size": settings.DB_POOL_SIZE if hasattr(settings, "DB_POOL_SIZE") else 10,
        "max_overflow": settings.DB_MAX_OVERFLOW if hasattr(settings, "DB_MAX_OVERFLOW") else 20,
        "pool_timeout": settings.DB_POOL_TIMEOUT if hasattr(settings, "DB_POOL_TIMEOUT") else 30,
        "pool_pre_ping": True,
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)

from sqlalchemy import event

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode, busy timeout, and normal sync for concurrency on SQLite."""
    if DATABASE_URL.startswith("sqlite"):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db() -> None:
    """Create all relational tables if they do not already exist and migrate columns."""
    # Ensure every durable model is registered before create_all (including simulation drafts).
    import app.persistence.models  # noqa: F401
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
                ("project_id", "VARCHAR(36)"),
            ]
            with engine.connect() as conn:
                for col_name, col_def in new_cols:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE scan_snapshots ADD COLUMN {col_name} {col_def}"))
                conn.commit()
        scoped_columns = {
            "scan_runs": [("project_id", "VARCHAR(36)")],
            "current_snapshot_pointer": [("scope_key", "VARCHAR(64) NOT NULL DEFAULT 'global'")],
            "audit_events": [("project_id", "VARCHAR(36)")],
        }
        table_names = set(inspector.get_table_names())
        for table_name, columns in scoped_columns.items():
            if table_name not in table_names:
                continue
            existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
            with engine.connect() as conn:
                for col_name, col_def in columns:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}"))
                conn.commit()
        if "finding_states" in inspector.get_table_names():
            existing_cols = {c["name"] for c in inspector.get_columns("finding_states")}
            with engine.connect() as conn:
                for col_name, col_def in (("assigned_to", "VARCHAR(128)"), ("due_date", "VARCHAR(10)"), ("analyst_notes", "TEXT"), ("project_id", "VARCHAR(36)"), ("source_finding_id", "VARCHAR(256)")):
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE finding_states ADD COLUMN {col_name} {col_def}"))
                conn.commit()
        if "finding_state_history" in inspector.get_table_names():
            existing_cols = {c["name"] for c in inspector.get_columns("finding_state_history")}
            with engine.connect() as conn:
                for col_name, col_def in (("project_id", "VARCHAR(36)"), ("source_finding_id", "VARCHAR(256)")):
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE finding_state_history ADD COLUMN {col_name} {col_def}"))
                conn.commit()
        if "cloud_projects" in inspector.get_table_names():
            existing_cols = {c["name"] for c in inspector.get_columns("cloud_projects")}
            new_cols = [
                ("external_id", "VARCHAR(64)"),
                ("verification_status", "VARCHAR(16) NOT NULL DEFAULT 'NOT_CHECKED'"),
                ("verified_at", "VARCHAR(64)"),
                ("verified_account_id", "VARCHAR(12)"),
                ("verification_error", "VARCHAR(256)"),
            ]
            with engine.connect() as conn:
                for col_name, col_def in new_cols:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE cloud_projects ADD COLUMN {col_name} {col_def}"))
                conn.commit()
    except Exception:
        logger.exception("Relational schema initialization or compatibility migration failed")
        raise


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
