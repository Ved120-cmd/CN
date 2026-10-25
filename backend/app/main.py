import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import APP_TITLE, API_PREFIX
from app.db.session import initialize_database
from app import models  # register ORM models
from app.api.router import router
from app.services.diagnostic_service import job_manager, recover_abandoned_runs

initialize_database()

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(_app):
    job_manager.startup()
    recovered = recover_abandoned_runs()
    if recovered:
        logger.warning("Marked %s abandoned diagnostic runs as interrupted", recovered)
    try:
        yield
    finally:
        await job_manager.shutdown()

app=FastAPI(title=APP_TITLE, version="1.0.0", description="Evidence-based network diagnostics API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173","http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["GET","POST"], allow_headers=["*"])
app.include_router(router, prefix=API_PREFIX)
@app.get("/")
def root(): return {"message":"NetDoctor API is running","docs":"/docs"}
