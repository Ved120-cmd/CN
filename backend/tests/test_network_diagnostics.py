import socket

from app.network import diagnostics


def test_dns_success_returns_real_resolver_values(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
    ])
    result = diagnostics.run_test("dns", "host.example", 443, 1)
    assert result["status"] == "success"
    assert result["result"]["resolved_ips"] == ["2001:db8::1", "203.0.113.10"]
    assert result["duration_ms"] >= 0


def test_dns_failure_keeps_resolver_reason(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(diagnostics.socket, "getaddrinfo", fail)
    result = diagnostics.run_test("dns", "missing.example", 443, 1)
    assert result["status"] == "failed"
    assert "does not exist" in result["result"]["reason"]
    assert result["result"]["error_message"]


def test_tcp_success_connects_to_resolved_public_address(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["203.0.113.10"])

    class Connected:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def connect(address, timeout):
        assert address == ("203.0.113.10", 443)
        assert timeout == 2
        return Connected()

    monkeypatch.setattr(diagnostics.socket, "create_connection", connect)
    result = diagnostics.run_test("tcp", "host.example", 443, 2)
    assert result["status"] == "success"
    assert result["result"]["reason"] == "TCP connection established"


def test_tcp_refusal_and_timeout_are_distinguished(monkeypatch):
    monkeypatch.setattr(diagnostics, "resolve_public_addresses", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError("refused")))
    refused = diagnostics.run_test("tcp", "host.example", 443, 2)
    assert "refused" in refused["result"]["reason"].lower()

    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(socket.timeout("timed out")))
    timed_out = diagnostics.run_test("tcp", "host.example", 443, 2)
    assert "does not prove" in timed_out["result"]["reason"]
