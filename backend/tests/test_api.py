import time
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.db.session import Base, get_db
from app.models.diagnostic import DiagnosticRun

client=TestClient(app)
def test_health():
    response=client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_invalid_target_rejected():
    response=client.post("/api/v1/diagnostics", json={"target":"example..com","tests":["dns"]})
    assert response.status_code == 422

def test_invalid_port_timeout_and_test_name_rejected():
    base = {"target": "example.com", "tests": ["dns"]}
    assert client.post("/api/v1/diagnostics", json={**base, "port": 0}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={**base, "port": 65536}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={**base, "timeout_seconds": 0}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={"target": "example.com", "tests": ["unsupported"]}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={**base, "latency_probe_count": 2}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={**base, "latency_warning_ms": 0}).status_code == 422
    assert client.post("/api/v1/diagnostics", json={**base, "traceroute_max_hops": 21}).status_code == 422

def test_history_rejects_invalid_pagination_and_lifecycle_filter():
    assert client.get("/api/v1/history?limit=0").status_code == 422
    assert client.get("/api/v1/history?offset=-1").status_code == 422
    assert client.get("/api/v1/history?status=unknown").status_code == 422

def test_diagnostic_runs_as_background_job(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'diagnostics.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    test_session_local = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = test_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.services.diagnostic_service.SessionLocal", test_session_local)
    monkeypatch.setattr("app.api.router.SessionLocal", test_session_local)
    events = []

    async def capture_event(run_id, event):
        events.append(event)

    def fake_run_test(kind, *args):
        if kind == "dns":
            return {"status": "success", "duration_ms": 1, "result": {"count": 1}}
        if kind == "tcp":
            raise RuntimeError("internal test detail must not reach the client")
        return {"status": "success", "duration_ms": 3, "result": {"tls_version": "TLSv1.3"}}

    monkeypatch.setattr("app.services.diagnostic_service.run_test", fake_run_test)
    monkeypatch.setattr("app.services.diagnostic_service.connection_manager.broadcast", capture_event)

    try:
        with TestClient(app) as test_client:
            response = test_client.post("/api/v1/diagnostics", json={"target": "example.com", "tests": ["dns", "tcp", "tls"]})

            assert response.status_code == 202
            accepted = response.json()
            assert accepted["status"] == "queued"
            assert accepted["run_id"] > 0
            assert accepted["status_url"] == f"/api/v1/diagnostics/{accepted['run_id']}"
            assert accepted["websocket_url"] == f"/api/v1/diagnostics/{accepted['run_id']}/ws"

            deadline = time.monotonic() + 3
            completed_response = test_client.get(accepted["status_url"])
            while completed_response.json()["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
                time.sleep(0.01)
                completed_response = test_client.get(accepted["status_url"])
            completed_run = completed_response.json()
            assert completed_run["status"] == "completed"
            assert len(completed_run["results"]) == 3
            assert completed_run["completed_tests"] == 3
            assert completed_run["selected_tests"] == ["dns", "tcp", "tls"]
            assert completed_run["completed_at"] is not None
            assert completed_run["summary_json"]["assessment"] == "issues_detected"
            analysis_response = test_client.get(f"/api/v1/diagnostics/{accepted['run_id']}/analysis")
            assert analysis_response.status_code == 200
            assert analysis_response.json()["overall_status"] == "issue_detected"
            assert analysis_response.json()["issues"][0]["code"] == "TCP_CONNECTION_FAILED"
            report_response = test_client.get(f"/api/v1/reports/{accepted['run_id']}")
            assert report_response.status_code == 200
            assert report_response.headers["content-type"].startswith("text/html")
            assert f'filename="netdoctor-report-{accepted["run_id"]}.html"' in report_response.headers["content-disposition"]
            assert "NetDoctor diagnostic report" in report_response.text
            assert test_client.get("/api/v1/diagnostics/999999/analysis").status_code == 404
            assert test_client.get("/api/v1/reports/999999").status_code == 404
            assert [event["event"] for event in events] == ["run_started", "test_started", "test_completed", "test_started", "test_completed", "test_started", "test_completed", "run_completed"]
            assert events[1]["test_type"] == "dns"
            assert events[2]["test_status"] == "success"
            assert events[4]["test_status"] == "failed"
            assert events[4]["completed_tests"] == 2
            assert events[5]["test_type"] == "tls"
            assert events[6]["test_status"] == "success"

            with test_client.websocket_connect(f"/api/v1/diagnostics/{accepted['run_id']}/ws") as websocket:
                snapshot = websocket.receive_json()
            assert snapshot["event"] == "snapshot"
            assert snapshot["completed_tests"] == snapshot["total_tests"] == 3
            assert snapshot["run"]["status"] == "completed"

            history_detail = test_client.get(f"/api/v1/history/{accepted['run_id']}")
            assert history_detail.status_code == 200
            assert history_detail.json()["results"][0]["result"] == {"count": 1}
            results = test_client.get(f"/api/v1/diagnostics/{accepted['run_id']}/results")
            assert results.status_code == 200
            assert [item["test_type"] for item in results.json()] == ["dns", "tcp", "tls"]
            assert test_client.get("/api/v1/history/999999").status_code == 404

            with test_session_local() as history_db:
                history_db.add_all([
                    DiagnosticRun(target="other.example", port=443, status="failed", total_tests=1,
                                  selected_tests=["tcp"], summary="Diagnostic job failed"),
                    DiagnosticRun(target="example.net", port=443, status="completed", total_tests=1,
                                  selected_tests=["tls"], summary="TLS warning"),
                ])
                history_db.commit()
            filtered = test_client.get("/api/v1/history?target=example.com&status=completed&limit=5").json()
            assert [item["id"] for item in filtered] == [accepted["run_id"]]
            page = test_client.get("/api/v1/history?limit=1&offset=1").json()
            assert len(page) == 1
            assert page[0]["id"] != accepted["run_id"]
    finally:
        app.dependency_overrides.clear()
        test_engine.dispose()
