import json
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

@event.listens_for(engine, "connect")
def configure_sqlite_connection(connection, _record):
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize_database(database_engine=engine):
    """Create missing tables and apply safe, additive SQLite column migrations."""
    if not event.contains(database_engine, "connect", configure_sqlite_connection):
        event.listen(database_engine, "connect", configure_sqlite_connection)
    Base.metadata.create_all(bind=database_engine)
    inspector = inspect(database_engine)
    tables = set(inspector.get_table_names())
    run_columns = {column["name"] for column in inspector.get_columns("diagnostic_runs")} if "diagnostic_runs" in tables else set()
    result_columns = {column["name"] for column in inspector.get_columns("diagnostic_results")} if "diagnostic_results" in tables else set()
    with database_engine.begin() as connection:
        if "diagnostic_runs" in tables:
            migrations = {
                "total_tests": "INTEGER NOT NULL DEFAULT 0",
                "selected_tests": "JSON NOT NULL DEFAULT '[]'",
                "request_json": "JSON NOT NULL DEFAULT '{}'",
                "current_test": "VARCHAR(30)",
                "completed_at": "DATETIME",
                "created_at": "DATETIME",
                "summary_json": "JSON",
            }
            added_selected_tests = "selected_tests" not in run_columns
            for name, definition in migrations.items():
                if name not in run_columns:
                    connection.execute(text(f"ALTER TABLE diagnostic_runs ADD COLUMN {name} {definition}"))
            connection.execute(text("UPDATE diagnostic_runs SET created_at = started_at WHERE created_at IS NULL"))
            if added_selected_tests and "diagnostic_results" in tables:
                run_ids = connection.execute(text("SELECT id FROM diagnostic_runs")).scalars().all()
                for run_id in run_ids:
                    kinds = connection.execute(
                        text("SELECT test_type FROM diagnostic_results WHERE run_id = :run_id ORDER BY id"),
                        {"run_id": run_id},
                    ).scalars().all()
                    if kinds:
                        selected = list(dict.fromkeys(kinds))
                        connection.execute(
                            text("UPDATE diagnostic_runs SET selected_tests = :tests WHERE id = :run_id"),
                            {"tests": json.dumps(selected), "run_id": run_id},
                        )
        if "diagnostic_results" in tables:
            if "created_at" not in result_columns:
                connection.execute(text("ALTER TABLE diagnostic_results ADD COLUMN created_at DATETIME"))
                connection.execute(text(
                    "UPDATE diagnostic_results SET created_at = "
                    "(SELECT started_at FROM diagnostic_runs WHERE diagnostic_runs.id = diagnostic_results.run_id)"
                ))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_diagnostic_runs_target ON diagnostic_runs (target)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_diagnostic_runs_status ON diagnostic_runs (status)"))
