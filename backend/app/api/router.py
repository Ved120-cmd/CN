from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session, selectinload
from app.core.config import API_PREFIX
from app.db.session import SessionLocal, get_db
from app.models.diagnostic import DiagnosticRun
from app.schemas.diagnostic import DiagnosticAcceptedOut, DiagnosticAnalysisOut, DiagnosticRequest, DiagnosticResultOut, DiagnosticRunOut
from app.services.diagnostic_service import connection_manager, job_manager, serialize_result, serialize_run
from app.services.analysis_service import analyze_run
from app.services.report_service import render_html_report

router=APIRouter()
@router.get("/health")
def health(): return {"status":"ok","service":"netdoctor-api"}

@router.post("/diagnostics", response_model=DiagnosticAcceptedOut, status_code=status.HTTP_202_ACCEPTED)
async def create_diagnostic(payload: DiagnosticRequest, db: Session = Depends(get_db)):
    run = DiagnosticRun(
        target=payload.target,
        port=payload.port,
        status="queued",
        total_tests=len(payload.tests),
        selected_tests=list(payload.tests),
        request_json=payload.model_dump(mode="json"),
        summary="Diagnostic job queued",
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    if not await job_manager.schedule(run.id):
        run.status = "failed"
        run.completed_at = datetime.now(timezone.utc)
        run.summary = "Diagnostic queue is full or shutting down; this run was not started."
        run.summary_json = {"assessment": "inconclusive", "counts": {}, "selected_tests": list(payload.tests),
                            "completed_results": 0, "message": run.summary, "lifecycle_failure": True}
        db.commit()
        raise HTTPException(status_code=429, detail={"message": run.summary, "run_id": run.id})
    return {"run_id": run.id, "status": run.status,
            "status_url": f"{API_PREFIX}/diagnostics/{run.id}",
            "websocket_url": f"{API_PREFIX}/diagnostics/{run.id}/ws"}

@router.get("/diagnostics/{run_id}", response_model=DiagnosticRunOut)
def get_diagnostic(run_id: int, db: Session = Depends(get_db)):
    run=db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
    if not run: raise HTTPException(status_code=404, detail="Diagnostic run not found")
    return serialize_run(run)


@router.get("/diagnostics/{run_id}/analysis", response_model=DiagnosticAnalysisOut,
            summary="Analyze saved diagnostic results",
            description="Applies deterministic rules to persisted results only. It does not rerun network checks.")
def get_diagnostic_analysis(run_id: int, db: Session = Depends(get_db)):
    run = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")
    return analyze_run(serialize_run(run))


@router.get("/reports/{run_id}", response_class=HTMLResponse,
            summary="Download a printable HTML diagnostic report",
            description="Builds a printable report from saved run and result records; no diagnostic is executed.")
def download_report(run_id: int, db: Session = Depends(get_db)):
    run = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")
    saved = serialize_run(run)
    analysis = analyze_run(saved)
    return HTMLResponse(content=render_html_report(saved, analysis), headers={
        "Content-Disposition": f'attachment; filename="netdoctor-report-{run_id}.html"',
    })

@router.websocket("/diagnostics/{run_id}/ws")
async def diagnostic_progress(websocket: WebSocket, run_id: int):
    def latest_snapshot():
        db = SessionLocal()
        try:
            run = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
            if run is None:
                return None
            data = serialize_run(run)
            return {"event": "snapshot", "run_id": run.id, "status": run.status,
                    "completed_tests": data["completed_tests"], "total_tests": run.total_tests, "run": data}
        finally:
            db.close()

    try:
        initial = await connection_manager.connect(run_id, websocket, latest_snapshot)
        if initial is None:
            return
        if initial["status"] in {"completed", "partially_completed", "failed"}:
            connection_manager.disconnect(run_id, websocket)
            await websocket.close(code=1000)
            return
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        connection_manager.disconnect(run_id, websocket)

@router.get("/history", response_model=list[DiagnosticRunOut])
def history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    target: str | None = Query(default=None, min_length=1, max_length=253),
    status: Literal["queued", "running", "completed", "partially_completed", "failed"] | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results))
    if target:
        query = query.filter(DiagnosticRun.target.ilike(f"%{target.strip()}%"))
    if status:
        query = query.filter(DiagnosticRun.status == status)
    runs = query.order_by(DiagnosticRun.started_at.desc(), DiagnosticRun.id.desc()).offset(offset).limit(limit).all()
    return [serialize_run(r) for r in runs]


@router.get("/history/{run_id}", response_model=DiagnosticRunOut)
def history_detail(run_id: int, db: Session = Depends(get_db)):
    run = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")
    return serialize_run(run)


@router.get("/diagnostics/{run_id}/results", response_model=list[DiagnosticResultOut])
def diagnostic_results(run_id: int, db: Session = Depends(get_db)):
    run = db.query(DiagnosticRun).options(selectinload(DiagnosticRun.results)).filter(DiagnosticRun.id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Diagnostic run not found")
    return [serialize_result(result) for result in run.results]
