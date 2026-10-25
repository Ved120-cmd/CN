"""Bounded wrappers and parsers for native Windows/Unix traceroute tools."""

from __future__ import annotations

import platform
import re
import subprocess
import threading
import time
from typing import Any

MAX_OUTPUT_CHARS = 128_000
TOTAL_TIMEOUT_SECONDS = 30


def _execute_bounded(command: list[str]) -> tuple[str, int]:
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        errors="replace", shell=False,
    )
    chunks: list[str] = []
    remaining = MAX_OUTPUT_CHARS

    def drain_output() -> None:
        nonlocal remaining
        if process.stdout is None:
            return
        while True:
            chunk = process.stdout.read(4096)
            if not chunk:
                break
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                remaining -= len(kept)

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=TOTAL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        reader.join(timeout=1)
        raise
    reader.join(timeout=1)
    return "".join(chunks), return_code


def parse_traceroute_output(output: str, destination_addresses: set[str], probes_per_hop: int = 3) -> tuple[list[dict[str, Any]], bool]:
    """Normalize common tracert/traceroute rows. Missing probes remain None."""
    hops: list[dict[str, Any]] = []
    destination_reached = False
    for line in output[:MAX_OUTPUT_CHARS].splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not match:
            continue
        hop_number = int(match.group(1))
        rest = match.group(2)
        # Keep a slot per probe so a timeout is represented as None, never as zero.
        time_tokens = re.findall(r"\*|<\s*1|(?<![\w.])\d+(?:\.\d+)?\s*ms", rest, re.I)
        times: list[float | None] = []
        for token in time_tokens[:probes_per_hop]:
            if token == "*":
                times.append(None)
            elif token.lstrip().startswith("<"):
                times.append(0.99)
            else:
                times.append(float(re.search(r"\d+(?:\.\d+)?", token).group(0)))
        times.extend([None] * max(0, probes_per_hop - len(times)))
        address_match = re.search(r"\(([^()]+)\)", rest)
        address = address_match.group(1) if address_match else None
        if address is None:
            # An IP token is preferred over a name in output such as "host (ip)".
            ip_match = re.search(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F:]{3,}(?:%\w+)?(?![\w:])", rest)
            if ip_match:
                address = ip_match.group(0)
        hostname = None
        if address and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+(?:%\w+)?", address):
            hostname = address
            address = None
        responded = address is not None or hostname is not None or any(value is not None for value in times)
        hop = {
            "hop_number": hop_number,
            "ip_address": address,
            "hostname": hostname,
            "probe_times_ms": times,
            "responded": responded,
        }
        hops.append(hop)
        if address in destination_addresses:
            destination_reached = True
    return hops, destination_reached


def _command(system: str, target_ip: str, max_hops: int, probes_per_hop: int, timeout: float) -> list[str] | None:
    wait_seconds = min(2.0, max(1.0, timeout))
    if system == "windows":
        # tracert sends three probes per hop and has no option to change that count.
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(int(wait_seconds * 1000)), target_ip]
    if system in {"linux", "darwin"}:
        return ["traceroute", "-n", "-m", str(max_hops), "-q", str(probes_per_hop), "-w", str(wait_seconds), target_ip]
    return None


def run_traceroute(target_ip: str, destination_addresses: set[str], timeout: float,
                   max_hops: int = 20, probes_per_hop: int = 3) -> dict:
    started = time.perf_counter()
    max_hops = min(20, max(1, int(max_hops)))
    probes_per_hop = min(3, max(1, int(probes_per_hop)))
    system = platform.system().lower()
    command = _command(system, target_ip, max_hops, probes_per_hop, timeout)
    if command is None:
        return _result("unsupported", started, max_hops, probes_per_hop, [], False,
                       f"Traceroute is not supported on {platform.system()}.")
    try:
        output, return_code = _execute_bounded(command)
    except FileNotFoundError:
        return _result("unsupported", started, max_hops, probes_per_hop, [], False,
                       "The system traceroute utility is unavailable. Install the platform utility to enable this check.")
    except subprocess.TimeoutExpired:
        return _result("inconclusive", started, max_hops, probes_per_hop, [], False,
                       "Traceroute exceeded the 30-second execution limit.", "Execution timed out")
    hops, reached = parse_traceroute_output(output, destination_addresses, probes_per_hop)
    if not hops:
        return _result("inconclusive", started, max_hops, probes_per_hop, [], False,
                       "Traceroute output could not be parsed; no route conclusion was made.",
                       f"Traceroute exited with code {return_code}")
    status = "success" if reached else "partial"
    reason = ("Destination reached; intermediate routers may filter probes." if reached else
              "Trace ended before the destination responded. Routers may filter or deprioritize probes; this does not prove an outage.")
    return _result(status, started, max_hops, probes_per_hop, hops, reached, reason,
                   None if return_code == 0 else f"Traceroute exited with code {return_code}")


def _result(status: str, started: float, max_hops: int, probes_per_hop: int,
            hops: list[dict], reached: bool, reason: str, error: str | None = None) -> dict:
    return {
        "status": status,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "result": {
            "test_type": "traceroute", "max_hops": max_hops,
            "probes_per_hop": probes_per_hop, "destination_reached": reached,
            "hops": hops, "reason": reason, "error_message": error,
        },
        "error_message": error,
    }
