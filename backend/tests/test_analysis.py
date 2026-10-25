from copy import deepcopy

from app.schemas.diagnostic import DiagnosticAnalysisOut
from app.services.analysis_service import analyze_run
from app.services.report_service import render_html_report


def result(test_type, status, detail=None, error=None, result_id=1, duration=2.5):
    return {"id": result_id, "test_type": test_type, "status": status, "duration_ms": duration,
            "result": detail or {}, "error_message": error}


def run(results, selected=None, status="completed"):
    return {"id": 14, "target": "fixture.example", "port": 443, "status": status,
            "total_tests": len(selected if selected is not None else results),
            "selected_tests": selected if selected is not None else [row["test_type"] for row in results],
            "created_at": "2026-10-25T12:00:00Z", "summary_json": {}, "results": results}


def test_dns_failure_classification_and_schema():
    output = analyze_run(run([result("dns", "failed", {"resolved_ips": [], "reason": "Hostname does not exist", "error_message": "getaddrinfo failed"}, "getaddrinfo failed")], ["dns"]))
    assert output["overall_status"] == "issue_detected"
    assert output["issues"][0]["code"] == "DNS_RESOLUTION_FAILED"
    assert "misspelled" in output["possible_causes"][0]["hypothesis"]
    assert "approved alternate resolver" in output["recommendations"][0]["action"]
    DiagnosticAnalysisOut.model_validate(output)


def test_tcp_refusal_and_timeout_are_distinguished():
    refused = analyze_run(run([result("tcp", "failed", {"reason": "Connection refused by the destination"})], ["tcp"]))
    timed_out = analyze_run(run([result("tcp", "failed", {"reason": "Connection timed out; this does not prove the network is down"})], ["tcp"]))
    assert refused["issues"][0]["code"] == "TCP_CONNECTION_REFUSED"
    assert timed_out["issues"][0]["code"] == "TCP_CONNECTION_TIMEOUT"
    assert "does not prove" in timed_out["issues"][0]["description"]


def test_latency_warning_uses_measured_tcp_threshold_and_priority():
    output = analyze_run(run([
        result("latency", "warning", {"measurement_method": "tcp_connect", "median_latency_ms": 240.0, "warning_threshold_ms": 150.0}),
        result("tcp", "failed", {"reason": "Connection refused"}, result_id=2),
    ], ["latency", "tcp"]))
    assert output["overall_status"] == "issue_detected"
    assert [item["code"] for item in output["issues"]] == ["TCP_CONNECTION_REFUSED", "TCP_CONNECT_TIME_HIGH"]
    assert [item["priority"] for item in output["recommendations"]] == ["high", "medium"]
    assert "TCP connection time" in output["issues"][1]["description"]


def test_tls_verification_and_expiry_are_separate_findings():
    invalid = analyze_run(run([result("tls", "failed", {"reason": "TLS certificate chain or hostname verification failed"}, "certificate verify failed")], ["tls"]))
    expiring = analyze_run(run([result("tls", "warning", {"days_until_expiry": 5, "expiry_warning_days": 14,
                                                              "certificate_expires_at": "2026-10-30T00:00:00Z"})], ["tls"]))
    assert invalid["issues"][0]["code"] == "TLS_VERIFICATION_FAILED"
    assert expiring["issues"][0]["code"] == "TLS_CERTIFICATE_EXPIRING"
    assert expiring["overall_status"] == "degraded"


def test_incomplete_trace_is_not_classified_as_outage():
    output = analyze_run(run([result("traceroute", "partial", {"destination_reached": False,
                                                                   "hops": [{"responded": False}]})], ["traceroute"]))
    assert output["issues"][0]["code"] == "TRACEROUTE_INCOMPLETE"
    assert output["overall_status"] == "inconclusive"
    assert "do not establish an outage" in output["issues"][0]["description"]


def test_partial_empty_and_failed_lifecycle_are_never_healthy():
    partial = analyze_run(run([result("dns", "success", {"resolved_ips": ["203.0.113.2"]})], ["dns", "tcp"]))
    empty = analyze_run(run([], ["dns"], status="queued"))
    failed = analyze_run(run([result("dns", "success")], ["dns"], status="failed"))
    failed_check = analyze_run(run([result("tls", "failed", {"reason": "TLS handshake failed"})], ["tls"]))
    assert partial["overall_status"] == "partially_tested" and partial["preliminary"]
    assert empty["overall_status"] == "inconclusive" and empty["evidence"] == []
    assert failed["overall_status"] != "healthy"
    assert failed_check["overall_status"] == "issue_detected"


def test_duplicate_findings_are_prevented_and_analysis_is_repeatable():
    fixture = run([
        result("tcp", "failed", {"reason": "Connection refused"}, result_id=1),
        result("tcp", "failed", {"reason": "Connection refused"}, result_id=2),
    ], ["tcp"])
    first, second = analyze_run(fixture), analyze_run(deepcopy(fixture))
    assert len(first["issues"]) == 1
    assert first["issues"][0]["evidence_refs"] == [1, 2]
    assert first["issues"] == second["issues"]
    assert first["recommendations"] == second["recommendations"]
    assert first["evidence"] == second["evidence"]


def test_report_contains_saved_data_and_escapes_untrusted_markup():
    fixture = run([result("dns", "failed", {"reason": "<script>alert(1)</script>", "resolved_ips": [],
                                               "password": "not-for-report", "debug": "Traceback (most recent call last): secret"})], ["dns"])
    fixture["target"] = '<img src=x onerror="alert(1)">'
    analysis = analyze_run(fixture)
    report = render_html_report(fixture, analysis)
    assert "NetDoctor diagnostic report" in report
    assert "TCP" not in report or "TCP connection setup" in report
    assert "&lt;script&gt;" in report and "&lt;img" in report
    assert "<script>alert(1)</script>" not in report
    assert "<img src=x" not in report
    assert "not-for-report" not in report and "Traceback (most recent call last)" not in report
    assert "[redacted]" not in report or "omitted from report" in report
