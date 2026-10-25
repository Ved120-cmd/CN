from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app import models
from app.db.session import Base, initialize_database
from app.models.diagnostic import DiagnosticResult, DiagnosticRun
from app.schemas.diagnostic import DiagnosticRunOut
from app.services.diagnostic_service import serialize_run, summarize_results


def make_database(path):
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    initialize_database(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, autocommit=False)


def test_runs_and_multiple_actual_results_round_trip(tmp_path):
    engine, sessions = make_database(tmp_path / "round-trip.db")
    try:
        with sessions() as db:
            run = DiagnosticRun(target="example.net", port=443, status="completed", total_tests=3,
                                selected_tests=["dns", "tcp", "traceroute"],
                                started_at=datetime.now(timezone.utc), completed_at=datetime.now(timezone.utc),
                                summary="2 passed, 1 inconclusive")
            db.add(run)
            db.flush()
            db.add_all([
                DiagnosticResult(run_id=run.id, test_type="dns", status="success", duration_ms=1.234,
                                 result_json='{"resolved_ips":["8.8.8.8"]}'),
                DiagnosticResult(run_id=run.id, test_type="tcp", status="failed", duration_ms=3.456,
                                 result_json='{"reason":"Connection refused"}', error_message="refused"),
                DiagnosticResult(run_id=run.id, test_type="traceroute", status="inconclusive", duration_ms=None,
                                 result_json='{"hops":[],"destination_reached":false}'),
            ])
            db.commit()
            stored = db.query(DiagnosticRun).filter_by(id=run.id).one()
            encoded = serialize_run(stored)
            DiagnosticRunOut.model_validate(encoded)
            assert encoded["selected_tests"] == ["dns", "tcp", "traceroute"]
            assert encoded["completed_at"].endswith("Z")
            assert encoded["results"][0]["result"]["resolved_ips"] == ["8.8.8.8"]
            assert encoded["results"][1]["error_message"] == "refused"
            assert encoded["results"][2]["duration_ms"] is None
    finally:
        engine.dispose()


def test_summary_is_deterministic_and_does_not_score_statuses():
    statuses = [{"status": "success"}, {"status": "warning"}, {"status": "inconclusive"}]
    first = summarize_results(statuses, ["dns", "tls", "traceroute"])
    second = summarize_results(statuses, ["dns", "tls", "traceroute"])
    assert first == second
    assert first["assessment"] == "warning"
    assert first["counts"] == {"success": 1, "warning": 1, "inconclusive": 1}
    assert "score" not in first
    assert "outage" in first["message"]


def test_failed_result_write_rolls_back_without_erasing_run(tmp_path):
    engine, sessions = make_database(tmp_path / "rollback.db")
    try:
        with sessions() as db:
            db.add(DiagnosticRun(target="example.net", status="queued", total_tests=1, selected_tests=["dns"]))
            db.commit()
            run_id = db.query(DiagnosticRun.id).scalar()
            db.add(DiagnosticResult(run_id=run_id, test_type="dns", status=None, result_json="{}"))
            with pytest.raises(IntegrityError):
                db.commit()
            db.rollback()
            assert db.query(DiagnosticRun).filter_by(id=run_id).count() == 1
            assert db.query(DiagnosticResult).filter_by(run_id=run_id).count() == 0
    finally:
        engine.dispose()


def test_additive_migration_keeps_existing_data_and_infers_selected_tests(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}", connect_args={"check_same_thread": False})
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE diagnostic_runs (id INTEGER PRIMARY KEY, target VARCHAR(253) NOT NULL, port INTEGER, status VARCHAR(30), started_at DATETIME, summary TEXT)"))
        connection.execute(text("CREATE TABLE diagnostic_results (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, test_type VARCHAR(30), status VARCHAR(30), duration_ms FLOAT, result_json TEXT, error_message TEXT)"))
        connection.execute(text("INSERT INTO diagnostic_runs (id,target,port,status,started_at,summary) VALUES (1,'legacy.example',443,'completed','2026-01-01 00:00:00','legacy')"))
        connection.execute(text("INSERT INTO diagnostic_results (id,run_id,test_type,status,duration_ms,result_json) VALUES (1,1,'dns','success',1.25,'{\"ips\":[]}')"))
    try:
        initialize_database(engine)
        with sessionmaker(bind=engine)() as db:
            stored = db.query(DiagnosticRun).filter_by(id=1).one()
            assert stored.target == "legacy.example"
            assert stored.selected_tests == ["dns"]
            assert stored.total_tests == 0
            assert stored.results[0].created_at is not None
    finally:
        engine.dispose()
