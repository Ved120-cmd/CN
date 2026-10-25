import socket

import pytest
from pydantic import ValidationError

from app.network import diagnostics, safety
from app.schemas.diagnostic import DiagnosticRequest


@pytest.mark.parametrize("target", [
    "127.0.0.1", "10.0.0.4", "169.254.1.2", "224.0.0.1", "192.0.2.1",
    "https://example.com", "example.com:443", "bad host.example", "-bad.example", "bad-.example",
])
def test_request_rejects_ip_literals_urls_and_malformed_hostnames(target):
    with pytest.raises(ValidationError):
        DiagnosticRequest(target=target, tests=["dns"])


def test_request_normalizes_hostname_and_rejects_invalid_port_types():
    assert DiagnosticRequest(target="Example.COM.", tests=["dns"]).target == "example.com"
    with pytest.raises(ValidationError):
        DiagnosticRequest(target="example.com", tests=["dns"], port=True)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.2", "192.168.1.4", "169.254.10.2",
    "224.0.0.1", "0.0.0.0", "192.0.2.10", "::1", "fe80::1", "ff02::1",
])
def test_resolver_rejects_non_global_address_classes(monkeypatch, address):
    monkeypatch.setattr(safety.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
    ])
    with pytest.raises(ValueError):
        safety.resolve_public_addresses("fixture.example")


def test_resolver_rejects_mixed_public_and_private_answers(monkeypatch):
    monkeypatch.setattr(safety.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ])
    with pytest.raises(ValueError):
        safety.resolve_public_addresses("rebound.example")


def test_resolved_addresses_are_pinned_for_actual_connections(monkeypatch):
    resolver_calls = []
    connected_to = []
    addresses = iter([["8.8.8.8"], ["127.0.0.1"]])

    def resolve(host):
        resolver_calls.append(host)
        return next(addresses)

    class Connected:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def connect(address, timeout):
        connected_to.append(address[0])
        return Connected()

    monkeypatch.setattr(diagnostics, "resolve_public_addresses", resolve)
    monkeypatch.setattr(diagnostics.socket, "create_connection", connect)
    response = diagnostics.run_test("tcp", "rebound.example", 443, 1)
    assert response["status"] == "success"
    assert resolver_calls == ["rebound.example"]
    assert connected_to == ["8.8.8.8"]


def test_resolver_caps_large_address_sets(monkeypatch):
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"8.8.{index // 256}.{index % 256}", 0))
               for index in range(safety.MAX_RESOLVED_ADDRESSES + 1)]
    monkeypatch.setattr(safety.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(ValueError, match="more than"):
        safety.resolve_public_addresses("many.example")
