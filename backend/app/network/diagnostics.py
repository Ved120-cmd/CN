import errno
import socket
import ssl
import statistics
import time
from datetime import datetime, timezone

from app.network.safety import resolve_public_addresses
from app.network.traceroute import run_traceroute

LATENCY_WARNING_MS = 150.0


def _failure(kind: str, started: float, reason: str, error: str | None = None,
             status: str = "failed", details: dict | None = None) -> dict:
    result = {"test_type": kind, "reason": reason, "error_message": error}
    result.update(details or {})
    return {"status": status, "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "result": result, "error_message": error}


def run_test(kind: str, host: str, port: int, timeout: float, probe_count: int = 5,
             latency_warning_ms: float = LATENCY_WARNING_MS, max_hops: int = 20,
             probes_per_hop: int = 3, tls_expiry_warning_days: int = 14) -> dict:
    started = time.perf_counter()
    handshake_started = None
    try:
        if kind == "dns":
            try:
                records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                ips = sorted({record[4][0] for record in records})
                if not ips:
                    return _failure(kind, started, "Resolver returned no addresses")
                return {"status": "success", "duration_ms": round((time.perf_counter()-started)*1000, 2),
                        "result": {"test_type": "dns", "hostname": host, "resolved_ips": ips,
                                   "addresses": ips, "count": len(ips),
                                   "reason": "Hostname resolved successfully", "error_message": None}}
            except socket.gaierror as error:
                reason = "Hostname does not exist or has no usable address records" if error.errno == socket.EAI_NONAME else "DNS resolver error"
                return _failure(kind, started, reason, str(error), details={"hostname": host, "resolved_ips": []})

        # All connection-based checks pin the same publicly resolved address for the
        # entire check, avoiding a second DNS lookup between policy validation and connect.
        addresses = sorted(resolve_public_addresses(host))
        if kind == "tcp":
            last_error = None
            for address in addresses:
                try:
                    with socket.create_connection((address, port), timeout=timeout):
                        pass
                    return {"status": "success", "duration_ms": round((time.perf_counter()-started)*1000, 2),
                            "result": {"test_type": "tcp", "address": address, "port": port,
                                       "reachable": True, "reason": "TCP connection established", "error_message": None}}
                except OSError as error:
                    last_error = error
            if isinstance(last_error, (socket.timeout, TimeoutError)):
                reason = "Connection timed out; this does not prove the network is down"
            elif isinstance(last_error, ConnectionRefusedError) or getattr(last_error, "errno", None) == errno.ECONNREFUSED:
                reason = "Connection refused by the destination or an intervening firewall"
            else:
                reason = "TCP connection failed"
            message = str(last_error) if last_error else "No usable address was available"
            return _failure(kind, started, reason, message, details={"port": port})

        if kind == "latency":
            address = addresses[0]
            probes, successful = [], []
            for number in range(1, probe_count + 1):
                probe_started = time.perf_counter()
                try:
                    with socket.create_connection((address, port), timeout=timeout):
                        pass
                    elapsed = round((time.perf_counter() - probe_started) * 1000, 2)
                    successful.append(elapsed)
                    probes.append({"probe": number, "status": "success", "duration_ms": elapsed, "error_message": None})
                except OSError as error:
                    probes.append({"probe": number, "status": "failed", "duration_ms": None,
                                   "error_message": str(error)})
            failed = probe_count - len(successful)
            detail = {
                "test_type": "latency", "measurement_method": "tcp_connect", "target": host,
                "port": port, "selected_address": address, "address_selection": "first address in sorted public DNS results",
                "attempts": probe_count, "successful_attempts": len(successful), "failed_attempts": failed,
                "probes": probes, "individual_latencies_ms": successful,
                "failure_rate_percent": round(failed / probe_count * 100, 2),
                "min_latency_ms": round(min(successful), 2) if successful else None,
                "median_latency_ms": round(statistics.median(successful), 2) if successful else None,
                "mean_latency_ms": round(statistics.mean(successful), 2) if successful else None,
                "max_latency_ms": round(max(successful), 2) if successful else None,
                "warning_threshold_ms": latency_warning_ms,
            }
            if not successful:
                return _failure(kind, started, "All TCP connection timing probes failed; no latency measurement is available.",
                                probes[0]["error_message"] if probes else None, details=detail)
            median = detail["median_latency_ms"]
            if failed or median > latency_warning_ms:
                reason = (f"Median TCP connection time exceeds the {latency_warning_ms:g} ms heuristic threshold."
                          if median > latency_warning_ms else "Some TCP timing probes failed; failures do not establish packet loss or a general outage.")
                return _failure(kind, started, reason, status="warning", details=detail)
            return {"status": "success", "duration_ms": round((time.perf_counter()-started)*1000, 2),
                    "result": {**detail, "reason": "TCP connection timings measured successfully.", "error_message": None}}

        if kind == "tls":
            address = addresses[0]
            context = ssl.create_default_context()  # certificate chain and hostname verification stay enabled
            raw = socket.create_connection((address, port), timeout=timeout)
            with raw:
                handshake_started = time.perf_counter()
                with context.wrap_socket(raw, server_hostname=host) as tls_socket:
                    certificate = tls_socket.getpeercert()
                    expiry_raw = certificate.get("notAfter")
                    expiry = datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if expiry_raw else None
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).total_seconds() / 86400 if expiry else None
                    subject = {key: value for group in certificate.get("subject", ()) for key, value in group}
                    issuer = {key: value for group in certificate.get("issuer", ()) for key, value in group}
                    detail = {"test_type": "tls", "tls_version": tls_socket.version(),
                              "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                              "certificate_subject": subject, "certificate_issuer": issuer,
                              "certificate_expires_at": expiry.isoformat() if expiry else None,
                              "days_until_expiry": round(days_left, 2) if days_left is not None else None,
                              "hostname_verified": True, "address": address,
                              "handshake_duration_ms": round((time.perf_counter() - handshake_started) * 1000, 2),
                              "expiry_warning_days": tls_expiry_warning_days}
                    if days_left is None:
                        return _failure(kind, started, "TLS handshake succeeded, but certificate expiry was unavailable.",
                                        status="warning", details=detail)
                    if days_left is not None and days_left <= tls_expiry_warning_days:
                        reason = f"TLS certificate expires within the {tls_expiry_warning_days}-day warning window."
                        return _failure(kind, started, reason, status="warning", details=detail)
                    return {"status": "success", "duration_ms": round((time.perf_counter()-started)*1000, 2),
                            "result": {**detail, "reason": "Verified TLS handshake and certificate hostname.", "error_message": None}}

        if kind == "traceroute":
            return run_traceroute(addresses[0], set(addresses), timeout, max_hops, probes_per_hop)
        return _failure(kind, started, f"Unsupported diagnostic: {kind}")
    except ssl.SSLCertVerificationError as error:
        # Verification errors may not expose a trustworthy peer certificate. Never retry insecurely.
        return _failure(kind, started, "TLS certificate chain or hostname verification failed.", str(error),
                        details={"tls_version": None, "cipher": None, "certificate_subject": None,
                                 "certificate_issuer": None, "certificate_expires_at": None,
                                 "days_until_expiry": None, "hostname_verified": None,
                                 "handshake_duration_ms": round((time.perf_counter() - handshake_started) * 1000, 2) if handshake_started is not None else None})
    except ssl.SSLError as error:
        return _failure(kind, started, "TLS handshake failed or the server does not support TLS.", str(error),
                        details={"handshake_duration_ms": round((time.perf_counter() - handshake_started) * 1000, 2) if handshake_started is not None else None})
    except (socket.timeout, TimeoutError) as error:
        return _failure(kind, started, "Connection timed out; this does not prove the network is down.", str(error))
    except socket.gaierror as error:
        reason = "Hostname could not be resolved" if error.errno == socket.EAI_NONAME else "DNS resolver error"
        return _failure(kind, started, reason, str(error))
    except ConnectionRefusedError as error:
        return _failure(kind, started, "TCP connection was refused before a TLS handshake could begin.", str(error))
    except OSError as error:
        return _failure(kind, started, "Connection failed due to a network or operating-system error.", str(error))
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) else "Diagnostic could not be completed"
        return _failure(kind, started, reason, str(error))
