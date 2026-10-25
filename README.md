# NetDoctor

A full-stack network diagnostics dashboard built with React + TypeScript and FastAPI. It runs real DNS, TCP-connectivity, TCP-based latency, traceroute, and TLS checks and stores run history in SQLite.

## Requirements
- Python 3.11+
- Node.js 20+
- Git (optional)

## Run the backend
```bash
cd backend
python -m venv .venv
pip install -r requirements.txt
# Windows PowerShell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
# macOS/Linux
# .venv/bin/python -m uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

The frontend defaults to `http://127.0.0.1:8000/api/v1`. To use another API URL, set `VITE_API_URL` in `frontend/.env` (copy `frontend/.env.example`). The URL should include the API prefix.

## SQLite persistence and history

The backend creates missing tables and applies additive, non-destructive column migrations when `app.main` loads. The SQLite database is `backend/netdoctor.db`; `*.db` is excluded by `.gitignore`. Existing runs and results are preserved, and older runs infer their selected checks from stored result rows where possible. No migration tool or additional dependency is required.

The History page loads saved runs from `GET /api/v1/history` in pages of 10 and fetches selected run details from `GET /api/v1/history/{run_id}`. The history endpoint supports `limit` (1–100), `offset`, partial `target`, and lifecycle `status` filters. Full result rows are also available from `GET /api/v1/diagnostics/{run_id}/results`.

To inspect the latest saved runs and results from a terminal at the repository root:

```powershell
python -c "import sqlite3; c=sqlite3.connect('backend/netdoctor.db'); print(c.execute('SELECT id,target,status,selected_tests,summary_json FROM diagnostic_runs ORDER BY id DESC LIMIT 10').fetchall())"
python -c "import sqlite3; c=sqlite3.connect('backend/netdoctor.db'); print(c.execute('SELECT run_id,test_type,status,duration_ms,result_json,error_message FROM diagnostic_results ORDER BY id DESC LIMIT 20').fetchall())"
```

Run summaries are deterministic status counts and a separate assessment (`healthy`, `warning`, `issues_detected`, or `inconclusive`); they are not a numeric score. A failed diagnostic check does not by itself establish a general network outage.

## Background runs and live progress

`POST /api/v1/diagnostics` validates and commits a queued run, then returns HTTP `202 Accepted` with `run_id`, `status_url`, and `websocket_url`. A bounded in-process manager allows at most 2 runs to execute concurrently and 20 accepted/running runs at once. Excess submissions are saved as failed and receive HTTP 429. Each run uses its own SQLAlchemy session and reloads the serialized request configuration from SQLite.

The WebSocket at the returned URL sends a `snapshot` on connection, followed by `run_started`, `test_started`, `test_completed`, and `run_completed` or `run_failed` events. Events include the run ID, lifecycle status, completed/total counts, and a saved run snapshot; test completion events include that test's stored status, duration, and result. Notifications are transient: when no listener is connected, the database retains the status and results. A reconnect receives the latest snapshot, including terminal runs. The dashboard reconnects after socket drops, polls the status URL while disconnected, and restores its last active run from session storage after a page refresh.

This in-process manager is intended for one local server process. It is not a distributed or crash-proof queue. On graceful shutdown, active tasks are cancelled and marked failed while retaining committed results. After an ungraceful process exit, the next startup marks leftover queued/running records as interrupted instead of resuming them. Do not run multiple server instances against this job manager; use a durable external queue for multi-process deployment.

## Deterministic analysis and reports

`GET /api/v1/diagnostics/{run_id}/analysis` evaluates saved result rows only; it never repeats network checks and is regenerated on each request. It returns a distinct network assessment (`healthy`, `degraded`, `issue_detected`, `inconclusive`, or `partially_tested`) alongside the run's execution lifecycle. Specific DNS, TCP refusal/timeout, and TLS verification failures take precedence; measured TCP connection-time and certificate-expiry warnings produce a degraded assessment when no stronger issue is present. Partial coverage, inconclusive probes, and failed runs are disclosed instead of being counted as healthy. Traceroute gaps are not treated as proof of an outage. Possible causes are labeled as hypotheses, and findings link back to saved result IDs.

`GET /api/v1/reports/{run_id}` downloads a printable HTML report assembled from persisted run and result records, including selected and missing checks, actual measurements, analysis, recommendations, and limitations. User-controlled text is HTML escaped. PDF export is not included; use the browser's Print dialog if a PDF copy is needed.

The dashboard requests analysis for the currently selected run, refreshes it as saved test results arrive, and provides **Download report** once at least one result is saved. In Swagger UI at `/docs`, start a run with `POST /api/v1/diagnostics`, then request `/api/v1/diagnostics/{run_id}/analysis` or `/api/v1/reports/{run_id}` using the returned numeric ID. An illustrative analysis response has the form:

```json
{
  "run_id": 14,
  "lifecycle_status": "completed",
  "overall_status": "issue_detected",
  "summary": "One or more selected checks reported a specific failure; this does not automatically establish a general network outage.",
  "preliminary": false,
  "issues": [{"code": "TCP_CONNECTION_REFUSED", "severity": "high", "title": "TCP connection was refused", "evidence_refs": [52]}],
  "possible_causes": [{"issue_code": "TCP_CONNECTION_REFUSED", "hypothesis": "The service may not be listening, the port may be closed, or an intermediary may have rejected the connection.", "confidence": "possible cause; not confirmed"}],
  "recommendations": [{"priority": "high", "action": "Verify the intended port and confirm that the service is listening.", "related_issue_code": "TCP_CONNECTION_REFUSED", "kind": "user_action"}],
  "evidence": [{"result_id": 52, "test_type": "tcp", "status": "failed", "duration_ms": 3.2, "measurements": {"port": 443, "reason": "Connection refused"}}],
  "limitations": ["Not selected and therefore not assessed: dns, latency, tls, traceroute."],
  "generated_at": "2026-10-25T12:00:00Z"
}
```

This example is illustrative only; actual findings and measurements come from the requested saved run.

## Run the frontend (new terminal)
```bash
cd frontend
npm install
npm run dev
```
Open the URL printed by Vite, usually http://localhost:5173.

## Safety notes
Only diagnose hosts you own or have permission to test. The API validates hostnames and rejects loopback/private/reserved IP destinations after DNS resolution to reduce accidental local-network probing. This is a learning project, not a hardened public service. Keep it bound to localhost unless you add authentication, rate limits, and deployment-specific network controls.

Traceroute and ICMP behavior varies by OS and network. A blocked probe is not proof that the destination is down. Latency is measured using TCP connection timing to the selected port, not ICMP echo.

DNS uses the operating system resolver (`socket.getaddrinfo`); that API does not offer a portable per-query timeout, so `timeout_seconds` applies to connection-based probes. TCP uses the configured timeout and connects only to public addresses resolved during that probe. Hostnames resolving to any private, loopback, link-local, or reserved address are rejected for TCP to reduce DNS-rebinding and SSRF risk. DNS lookups themselves do not open a connection.

## Diagnostic request options

In Swagger UI at `/docs`, use `POST /api/v1/diagnostics`. For example:

```json
{
  "target": "example.com",
  "tests": ["latency", "tls", "traceroute"],
  "port": 443,
  "timeout_seconds": 3,
  "latency_probe_count": 5,
  "latency_warning_ms": 150,
  "traceroute_max_hops": 20,
  "tls_expiry_warning_days": 14
}
```

Latency reports TCP connection timings (not ICMP ping), uses the first address in sorted public DNS results for consistency, and treats 150 ms median as a configurable heuristic. A `warning` status means probes were partial or crossed that threshold; it does not mean packet loss. TLS verifies the certificate chain and requested hostname, reports handshake time, and warns within the configurable 14-day certificate expiry window. It does not retry with verification disabled. When verification fails, the result reports the verification error and leaves certificate details unavailable. Traceroute uses `tracert` on Windows and `traceroute` on Linux/macOS when installed, with a 20-hop maximum and a 30-second total execution limit. Windows `tracert` always sends three probes per hop; Unix-like `traceroute` sends three probes per hop. Missing hops can result from router filtering, and do not prove an outage. Missing system utilities or unsupported operating systems are reported as `unsupported`; an unparseable or timed-out trace is `inconclusive`.

Per-check statuses retain the established `success` and `failed` values and also use `warning`, `partial`, `inconclusive`, and `unsupported` when the evidence warrants them. Measurements that were not obtained are returned as `null` or omitted, never as fabricated zeros.
