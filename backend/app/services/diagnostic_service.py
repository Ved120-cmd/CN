import json
import logging
import asyncio
from datetime import datetime, timezone
from collections.abc import Callable
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.diagnostic import DiagnosticRun, DiagnosticResult
from app.schemas.diagnostic import DiagnosticRequest
from app.network.diagnostics import run_test

logger = logging.getLogger(__name__)


def summarize_results(results, selected_tests: list[str] | None = None) -> dict:
    """Create a stable health assessment from returned test results, never a score."""
    statuses = [result.status if hasattr(result, "status") else result.get("status", "inconclusive") for result in results]
    order = ("success", "failed", "warning", "partial", "inconclusive", "unsupported")
    counts = {status: statuses.count(status) for status in order if status in statuses}
    if not statuses:
        assessment = "inconclusive"
    elif counts.get("failed", 0):
        assessment = "issues_detected"
    elif counts.get("warning", 0) or counts.get("partial", 0):
        assessment = "warning"
    elif counts.get("inconclusive", 0) or counts.get("unsupported", 0):
        assessment = "inconclusive"
    else:
        assessment = "healthy"
    passed = counts.get("success", 0)
    failures = counts.get("failed", 0)
    cautions = counts.get("warning", 0) + counts.get("partial", 0)
    uncertain = counts.get("inconclusive", 0) + counts.get("unsupported", 0)
    message = (f"{passed} passed, {failures} failed, {cautions} warning or partial, "
               f"{uncertain} inconclusive or unavailable out of {len(selected_tests or statuses)} selected checks.")
    if failures:
        message += " A failed probe identifies a check result, not by itself a general network outage."
    elif cautions:
        message += " Review the cautions; they do not by themselves establish an outage."
    elif uncertain:
        message += " Some selected checks did not provide conclusive evidence."
    return {"assessment": assessment, "counts": counts,
            "selected_tests": list(selected_tests or []), "completed_results": len(statuses), "message": message}

async def run_diagnostic_job(run_id: int) -> None:
    db = SessionLocal()
    try:
        run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
        if run is None:
            logger.error("Diagnostic run %s disappeared before its job started", run_id)
            return
        if run.status != "queued":
            logger.info("Diagnostic run %s is %s; duplicate execution was ignored", run_id, run.status)
            return

        payload = DiagnosticRequest.model_validate(run.request_json)

        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        run.summary = "Diagnostics in progress"
        run.completed_at = None
        db.commit()
        db.refresh(run)
        await broadcast_run_update(run, "run_started")

        for kind in payload.tests:
            existing = db.query(DiagnosticResult).filter(
                DiagnosticResult.run_id == run_id,
                DiagnosticResult.test_type == kind,
            ).first()
            if existing is not None:
                continue
            run.current_test = kind
            db.commit()
            db.refresh(run)
            await broadcast_run_update(run, "test_started", test_type=kind)
            try:
                item = await run_in_threadpool(
                    run_test,
                    kind,
                    payload.target,
                    payload.port,
                    payload.timeout_seconds,
                    payload.latency_probe_count,
                    payload.latency_warning_ms,
                    payload.traceroute_max_hops,
                    3,
                    payload.tls_expiry_warning_days,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Unexpected error while running %s for diagnostic %s", kind, run_id)
                item = {
                    "status": "failed", "duration_ms": None,
                    "result": {"test_type": kind, "reason": "Diagnostic test failed unexpectedly"},
                    "error_message": "Diagnostic test failed unexpectedly",
                }
            db.add(DiagnosticResult(
                run_id=run.id,
                test_type=kind,
                status=item["status"],
                duration_ms=item.get("duration_ms"),
                result_json=json.dumps(item.get("result", {}), allow_nan=False),
                error_message=item.get("error_message"),
            ))
            db.flush()
            completed_count = db.query(DiagnosticResult).filter(DiagnosticResult.run_id == run_id).count()
            run.current_test = None
            run.summary = f"{completed_count} of {run.total_tests} checks completed. Diagnostics in progress."
            db.commit()
            db.expire(run, ["results"])
            db.refresh(run)
            result_row = db.query(DiagnosticResult).filter(
                DiagnosticResult.run_id == run_id,
                DiagnosticResult.test_type == kind,
            ).first()
            await broadcast_run_update(
                run, "test_completed", test_type=kind,
                test_status=result_row.status if result_row else item["status"],
                duration_ms=result_row.duration_ms if result_row else item.get("duration_ms"),
                result=json.loads(result_row.result_json) if result_row else item.get("result", {}),
                error_message=result_row.error_message if result_row else item.get("error_message"),
            )

        db.refresh(run)
        run.status = "completed" if len(run.results) >= run.total_tests else "partially_completed"
        summary = summarize_results(run.results, payload.tests)
        run.summary_json = summary
        run.summary = summary["message"]
        run.current_test = None
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(run)
        await broadcast_run_update(run, "run_completed")
    except asyncio.CancelledError:
        db.rollback()
        _mark_run_interrupted(db, run_id)
        run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
        if run is not None:
            await broadcast_run_update(run, "run_failed", error_message=run.summary)
    except Exception:
        db.rollback()
        logger.exception("Diagnostic job %s failed", run_id)
        _mark_run_interrupted(db, run_id, "Diagnostic job failed unexpectedly. Check the server log for details.")
        run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
        if run is not None:
            await broadcast_run_update(run, "run_failed", error_message=run.summary)
    finally:
        db.close()


def _mark_run_interrupted(db: Session, run_id: int, message: str = "Run interrupted during application shutdown.") -> None:
    run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
    if run is None or run.status not in {"queued", "running"}:
        return
    run.status = "failed"
    run.current_test = None
    run.completed_at = datetime.now(timezone.utc)
    run.summary = message
    summary = summarize_results(run.results, run.selected_tests)
    summary["lifecycle_failure"] = True
    run.summary_json = summary
    db.commit()
    db.refresh(run)

def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decode_json(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def serialize_result(result: DiagnosticResult) -> dict:
    return {"id": result.id, "test_type": result.test_type, "status": result.status,
            "duration_ms": result.duration_ms, "result": _decode_json(result.result_json),
            "error_message": result.error_message}


def serialize_run(run: DiagnosticRun) -> dict:
    selected_tests = run.selected_tests or list(dict.fromkeys(result.test_type for result in run.results))
    return {"id": run.id, "target": run.target, "port": run.port, "status": run.status,
            "total_tests": run.total_tests, "completed_tests": len(run.results),
            "selected_tests": selected_tests, "current_test": run.current_test,
            "started_at": _iso_utc(run.started_at) or "", "completed_at": _iso_utc(run.completed_at),
            "created_at": _iso_utc(run.created_at), "summary": run.summary,
            "summary_json": run.summary_json,
            "results": [serialize_result(result) for result in run.results]}

async def broadcast_run_update(run: DiagnosticRun, event_name: str, **fields) -> None:
    payload = serialize_run(run)
    await connection_manager.broadcast(run.id, {
        "event": event_name,
        "run_id": run.id,
        "status": run.status,
        "completed_tests": payload["completed_tests"],
        "total_tests": run.total_tests,
        "run": payload,
        **fields,
    })

class ConnectionManager:
    def __init__(self) -> None:
        self.connections: dict[int, set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, run_id: int, websocket: WebSocket, snapshot: Callable[[], dict]) -> dict | None:
        await websocket.accept()
        async with self.lock:
            total_connections = sum(len(clients) for clients in self.connections.values())
            run_connections = self.connections.get(run_id, set())
            if total_connections >= 100 or len(run_connections) >= 20:
                await websocket.close(code=4429, reason="Too many live diagnostic listeners")
                return None
            self.connections.setdefault(run_id, set()).add(websocket)
            initial = snapshot()
            if initial is None:
                self.disconnect(run_id, websocket)
                await websocket.close(code=4404, reason="Diagnostic run not found")
                return None
            await websocket.send_json(initial)
            return initial

    def disconnect(self, run_id: int, websocket: WebSocket) -> None:
        clients = self.connections.get(run_id)
        if clients is None:
            return
        clients.discard(websocket)
        if not clients:
            self.connections.pop(run_id, None)

    async def broadcast(self, run_id: int, message: dict) -> None:
        async with self.lock:
            clients = self.connections.get(run_id, set()).copy()
            for websocket in clients:
                try:
                    await websocket.send_json(message)
                except (RuntimeError, OSError, WebSocketDisconnect):
                    self.disconnect(run_id, websocket)

connection_manager = ConnectionManager()


class DiagnosticJobManager:
    """Bounded in-process jobs; the database remains the durable run/result store."""

    def __init__(self, max_concurrent: int = 2, max_queued: int = 20) -> None:
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.max_queued = max_queued
        self.tasks: dict[int, asyncio.Task] = {}
        self.lock = asyncio.Lock()
        self.closing = False

    async def schedule(self, run_id: int) -> bool:
        async with self.lock:
            existing = self.tasks.get(run_id)
            if existing is not None and not existing.done():
                return True
            if self.closing or len(self.tasks) >= self.max_queued:
                return False
            task = asyncio.create_task(self._execute(run_id), name=f"netdoctor-run-{run_id}")
            self.tasks[run_id] = task
            task.add_done_callback(lambda completed, key=run_id: self._discard(key, completed))
            return True

    def _discard(self, run_id: int, task: asyncio.Task) -> None:
        if self.tasks.get(run_id) is task:
            self.tasks.pop(run_id, None)
        if not task.cancelled():
            error = task.exception()
            if error is not None:
                logger.error("Unhandled background diagnostic task failure for run %s: %s", run_id, error)

    async def _execute(self, run_id: int) -> None:
        try:
            async with self.semaphore:
                await run_diagnostic_job(run_id)
        except asyncio.CancelledError:
            db = SessionLocal()
            try:
                _mark_run_interrupted(db, run_id)
                run = db.query(DiagnosticRun).filter(DiagnosticRun.id == run_id).first()
                if run is not None:
                    await broadcast_run_update(run, "run_failed", error_message=run.summary)
            finally:
                db.close()

    async def shutdown(self) -> None:
        self.closing = True
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def startup(self) -> None:
        self.closing = False


job_manager = DiagnosticJobManager()


def recover_abandoned_runs() -> int:
    """Mark runs lost to a prior process as interrupted rather than completed."""
    db = SessionLocal()
    try:
        runs = db.query(DiagnosticRun).filter(DiagnosticRun.status.in_(("queued", "running"))).all()
        for run in runs:
            _mark_run_interrupted(db, run.id, "Run was interrupted by an application restart and was not resumed.")
        return len(runs)
    finally:
        db.close()
