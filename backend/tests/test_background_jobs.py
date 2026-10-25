from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models
from app.db.session import Base
from app.models.diagnostic import DiagnosticRun
from app.services import diagnostic_service
from app.services import diagnostic_service


def test_startup_recovery_marks_abandoned_runs_failed_and_preserves_results(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'recovery.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with sessions() as db:
        queued = DiagnosticRun(target="queued.example", status="queued", total_tests=1, selected_tests=["dns"])
        running = DiagnosticRun(target="running.example", status="running", total_tests=2, selected_tests=["dns", "tcp"])
        completed = DiagnosticRun(target="done.example", status="completed", total_tests=1, selected_tests=["dns"],
                                  completed_at=datetime.now(timezone.utc))
        db.add_all([queued, running, completed])
        db.commit()
        queued_id, running_id, completed_id = queued.id, running.id, completed.id

    monkeypatch.setattr(diagnostic_service, "SessionLocal", sessions)
    try:
        assert diagnostic_service.recover_abandoned_runs() == 2
        with sessions() as db:
            rows = {row.id: row for row in db.query(DiagnosticRun).all()}
            assert rows[queued_id].status == "failed"
            assert rows[running_id].status == "failed"
            assert rows[queued_id].completed_at is not None
            assert rows[running_id].summary_json["lifecycle_failure"] is True
            assert rows[completed_id].status == "completed"
    finally:
        engine.dispose()
