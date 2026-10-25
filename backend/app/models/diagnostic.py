from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base

def utcnow(): return datetime.now(timezone.utc)

class DiagnosticRun(Base):
    __tablename__ = "diagnostic_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, default=443)
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False, index=True)
    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    selected_tests: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    request_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    current_test: Mapped[str | None] = mapped_column(String(30), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    results: Mapped[list["DiagnosticResult"]] = relationship(back_populates="run", cascade="all, delete-orphan")

class DiagnosticResult(Base):
    __tablename__ = "diagnostic_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("diagnostic_runs.id"), index=True)
    test_type: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    duration_ms: Mapped[float | None] = mapped_column(nullable=True)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=True)
    run: Mapped[DiagnosticRun] = relationship(back_populates="results")
