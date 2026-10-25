import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, field_validator

TestName = Literal["dns", "tcp", "latency", "traceroute", "tls"]
class DiagnosticRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    tests: list[TestName] = Field(default_factory=lambda: ["dns", "tcp", "latency", "traceroute", "tls"], min_length=1)
    port: int = Field(default=443, strict=True, ge=1, le=65535)
    timeout_seconds: float = Field(default=3, ge=1, le=8, description="Per-connection timeout in seconds")
    latency_probe_count: int = Field(default=5, ge=3, le=10, description="Number of TCP connection timing probes")
    latency_warning_ms: float = Field(default=150, gt=0, le=5000, description="Heuristic median TCP connect warning threshold")
    traceroute_max_hops: int = Field(default=20, ge=1, le=20, description="Maximum traceroute hops")
    tls_expiry_warning_days: int = Field(default=14, ge=1, le=90, description="Warn when the verified TLS certificate expires within this many days")

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        value = value.strip()
        # Accept pasted Markdown links as well as hostnames and URLs.
        markdown_link = re.fullmatch(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", value, re.IGNORECASE)
        if markdown_link:
            value = markdown_link.group(2)
        if re.match(r"^https?://", value, re.IGNORECASE):
            value = urlsplit(value).hostname or ""
        value = value.strip().rstrip(".")
        if not value or any(ch.isspace() for ch in value) or "/" in value or "\\" in value or ":" in value:
            raise ValueError("Enter a valid hostname, such as example.com.")
        if len(value) > 253:
            raise ValueError("Hostname is too long")
        value = value.lower()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError("Enter a hostname, not an IP address.")
        try:
            ascii_host = value.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("Enter a valid DNS hostname.") from error
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if not re.fullmatch(rf"{label}(?:\.{label})*", ascii_host) or len(ascii_host) > 253:
            raise ValueError("Enter a valid DNS hostname using letters, numbers, and internal hyphens.")
        return ascii_host

    @field_validator("tests")
    @classmethod
    def unique_tests(cls, value: list[TestName]) -> list[TestName]:
        if len(value) != len(set(value)):
            raise ValueError("Each diagnostic test can be selected only once")
        return value

class DiagnosticResultOut(BaseModel):
    id: int
    test_type: str
    status: str
    duration_ms: float | None
    result: dict
    error_message: str | None


class DiagnosticRunOut(BaseModel):
    id: int
    target: str
    port: int
    status: str
    total_tests: int
    completed_tests: int
    selected_tests: list[str]
    current_test: str | None = None
    started_at: str
    completed_at: str | None
    created_at: str | None = None
    summary: str
    summary_json: dict | None = None
    results: list[DiagnosticResultOut]

class DiagnosticAcceptedOut(BaseModel):
    run_id: int
    status: str
    status_url: str
    websocket_url: str


class AnalysisIssueOut(BaseModel):
    code: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    test_types: list[str]
    evidence_refs: list[int | None]
    evidence_strength: str


class AnalysisCauseOut(BaseModel):
    issue_code: str
    hypothesis: str
    confidence: str


class AnalysisRecommendationOut(BaseModel):
    priority: Literal["high", "medium", "low"]
    action: str
    reason: str
    related_issue_code: str | None
    kind: Literal["user_action", "follow_up_diagnostic"]


class AnalysisEvidenceOut(BaseModel):
    result_id: int | None
    test_type: str
    status: str
    duration_ms: float | None
    measurements: dict


class DiagnosticAnalysisOut(BaseModel):
    run_id: int
    lifecycle_status: str
    overall_status: Literal["healthy", "degraded", "issue_detected", "inconclusive", "partially_tested"]
    summary: str
    preliminary: bool
    issues: list[AnalysisIssueOut]
    possible_causes: list[AnalysisCauseOut]
    recommendations: list[AnalysisRecommendationOut]
    evidence: list[AnalysisEvidenceOut]
    limitations: list[str]
    generated_at: str
