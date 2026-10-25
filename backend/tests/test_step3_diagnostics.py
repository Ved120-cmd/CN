import socket
import ssl
import subprocess
import time
from io import StringIO
import pytest
from pydantic import ValidationError

from app.network import diagnostics, traceroute
from app.schemas.diagnostic import DiagnosticRequest


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_latency_success_records_probe_statistics(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8", "1.1.1.1"])
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *args, **kwargs: FakeSocket())
    result = diagnostics.run_test("latency", "example.net", 443, 1, probe_count=3)
    detail = result["result"]
    assert result["status"] == "success"
    assert detail["measurement_method"] == "tcp_connect"
    assert detail["selected_address"] == "1.1.1.1"
    assert detail["attempts"] == detail["successful_attempts"] == 3
    assert detail["failed_attempts"] == 0
    assert len(detail["individual_latencies_ms"]) == 3
    assert detail["median_latency_ms"] is not None


def test_latency_partial_and_all_failures(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8"])
    outcomes = iter([FakeSocket(), "timeout", FakeSocket()])

    def connect(*args, **kwargs):
        outcome = next(outcomes)
        if outcome == "timeout":
            raise socket.timeout("slow")
        return outcome

    monkeypatch.setattr(diagnostics.socket, "create_connection", connect)
    partial = diagnostics.run_test("latency", "example.net", 443, 1, probe_count=3)
    assert partial["status"] == "warning"
    assert partial["result"]["successful_attempts"] == 2
    assert partial["result"]["failed_attempts"] == 1
    assert partial["result"]["failure_rate_percent"] == 33.33

    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError("refused")))
    failed = diagnostics.run_test("latency", "example.net", 443, 1, probe_count=3)
    assert failed["status"] == "failed"
    assert failed["result"]["median_latency_ms"] is None
    assert failed["result"]["individual_latencies_ms"] == []


def test_latency_threshold_warning(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8"])
    def slow_connect(*args, **kwargs):
        time.sleep(0.002)
        return FakeSocket()

    monkeypatch.setattr(diagnostics.socket, "create_connection", slow_connect)
    # A threshold below any measured nonnegative sample deterministically exercises the warning path.
    result = diagnostics.run_test("latency", "example.net", 443, 1, probe_count=3, latency_warning_ms=0.000001)
    assert result["status"] == "warning"
    assert result["result"]["median_latency_ms"] > result["result"]["warning_threshold_ms"]


class FakeTLSConnection(FakeSocket):
    def getpeercert(self):
        return {
            "subject": ((('commonName', 'example.net'),),),
            "issuer": ((('organizationName', 'Test CA'),),),
            "notAfter": "Dec 31 23:59:59 2099 GMT",
        }

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class FakeTLSContext:
    def wrap_socket(self, raw, server_hostname):
        assert server_hostname == "example.net"
        return FakeTLSConnection()


def test_tls_verified_handshake_and_certificate_details(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(diagnostics.ssl, "create_default_context", FakeTLSContext)
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: FakeSocket())
    result = diagnostics.run_test("tls", "example.net", 443, 1)
    detail = result["result"]
    assert result["status"] == "success"
    assert detail["hostname_verified"] is True
    assert detail["tls_version"] == "TLSv1.3"
    assert detail["certificate_issuer"]["organizationName"] == "Test CA"
    assert detail["days_until_expiry"] > 14
    assert detail["handshake_duration_ms"] is not None


def test_tls_hostname_verification_failure_is_not_retried(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8"])

    class InvalidContext:
        def wrap_socket(self, raw, server_hostname):
            raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(diagnostics.ssl, "create_default_context", InvalidContext)
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: FakeSocket())
    result = diagnostics.run_test("tls", "example.net", 443, 1)
    assert result["status"] == "failed"
    assert result["result"]["hostname_verified"] is None
    assert result["result"]["certificate_subject"] is None


def test_tls_near_expiry_warning_and_timeout(monkeypatch):
    from datetime import datetime, timedelta, timezone

    class NearExpiry(FakeTLSConnection):
        def getpeercert(self):
            expiry = datetime.now(timezone.utc) + timedelta(days=7)
            return {"subject": (), "issuer": (), "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}

    class NearExpiryContext:
        def wrap_socket(self, raw, server_hostname):
            return NearExpiry()

    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["8.8.8.8"])
    monkeypatch.setattr(diagnostics.ssl, "create_default_context", NearExpiryContext)
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: FakeSocket())
    assert diagnostics.run_test("tls", "example.net", 443, 1)["status"] == "warning"

    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(socket.timeout("slow")))
    timed_out = diagnostics.run_test("tls", "example.net", 443, 1)
    assert timed_out["status"] == "failed"
    assert "timed out" in timed_out["result"]["reason"].lower()


def test_traceroute_parses_unix_windows_and_missing_probes():
    unix = " 1  192.0.2.1  1.2 ms  *  2.1 ms\n 2  example.net (8.8.8.8)  4 ms  5 ms  6 ms"
    hops, reached = traceroute.parse_traceroute_output(unix, {"8.8.8.8"})
    assert reached is True
    assert hops[0]["ip_address"] == "192.0.2.1"
    assert hops[0]["probe_times_ms"] == [1.2, None, 2.1]
    windows = "  1     1 ms  <1 ms     *     192.0.2.1"
    hops, reached = traceroute.parse_traceroute_output(windows, {"8.8.8.8"})
    assert reached is False
    assert hops[0]["probe_times_ms"] == [1.0, 0.99, None]


def test_traceroute_missing_utility_and_bounded_invocation(monkeypatch):
    monkeypatch.setattr(traceroute.platform, "system", lambda: "Linux")

    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(traceroute.subprocess, "Popen", missing)
    unavailable = traceroute.run_traceroute("8.8.8.8", {"8.8.8.8"}, 3, 20, 3)
    assert unavailable["status"] == "unsupported"

    seen = {}

    class Completed:
        stdout = StringIO(" 1  8.8.8.8  2.0 ms  2.1 ms  2.3 ms")
        returncode = 0

        def wait(self, timeout=None):
            seen["timeout"] = timeout
            return self.returncode

    def run(command, **kwargs):
        seen["command"] = command
        seen.update(kwargs)
        return Completed()

    monkeypatch.setattr(traceroute.subprocess, "Popen", run)
    result = traceroute.run_traceroute("8.8.8.8", {"8.8.8.8"}, 3, 99, 99)
    assert result["status"] == "success"
    assert seen["shell"] is False
    assert "-m" in seen["command"] and seen["command"][seen["command"].index("-m") + 1] == "20"
    assert seen["timeout"] == traceroute.TOTAL_TIMEOUT_SECONDS
    assert seen["shell"] is False


def test_traceroute_output_capture_is_capped(monkeypatch):
    monkeypatch.setattr(traceroute.platform, "system", lambda: "Linux")

    class LargeOutput:
        stdout = StringIO("x" * (traceroute.MAX_OUTPUT_CHARS + 5000))
        returncode = 0

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(traceroute.subprocess, "Popen", lambda *args, **kwargs: LargeOutput())
    output, code = traceroute._execute_bounded(["traceroute"])
    assert code == 0
    assert len(output) == traceroute.MAX_OUTPUT_CHARS


def test_traceroute_unsupported_platform_and_timeout(monkeypatch):
    monkeypatch.setattr(traceroute.platform, "system", lambda: "Plan9")
    unsupported = traceroute.run_traceroute("8.8.8.8", {"8.8.8.8"}, 3)
    assert unsupported["status"] == "unsupported"

    monkeypatch.setattr(traceroute.platform, "system", lambda: "Linux")

    class Hanging:
        stdout = StringIO("")

        def __init__(self):
            self.wait_calls = 0
            self.killed = False

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                assert timeout == traceroute.TOTAL_TIMEOUT_SECONDS
                raise subprocess.TimeoutExpired("traceroute", timeout)
            return -9

        def kill(self):
            self.killed = True

    process = Hanging()
    monkeypatch.setattr(traceroute.subprocess, "Popen", lambda *a, **k: process)
    timed_out = traceroute.run_traceroute("8.8.8.8", {"8.8.8.8"}, 3)
    assert process.killed
    assert timed_out["status"] == "inconclusive"


def test_step3_request_options_have_safe_bounds():
    request = DiagnosticRequest(target="example.net", tests=["latency", "tls", "traceroute"])
    assert request.latency_probe_count == 5
    assert request.latency_warning_ms == 150
    assert request.traceroute_max_hops == 20
    assert request.tls_expiry_warning_days == 14
    for options in (
        {"latency_probe_count": 2},
        {"latency_probe_count": 11},
        {"latency_warning_ms": 0},
        {"traceroute_max_hops": 21},
        {"tls_expiry_warning_days": 91},
        {"tests": ["unsupported"]},
    ):
        with pytest.raises(ValidationError):
            DiagnosticRequest(target="example.net", **options)
