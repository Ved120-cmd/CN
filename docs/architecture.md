# Architecture

- React + TypeScript renders the dashboard and calls the FastAPI REST API.
- FastAPI validates requests with Pydantic, stores a queued run, and schedules its probes as a background job.
- The diagnostic worker persists each check result and publishes run snapshots and progress over `/api/v1/diagnostics/{run_id}/ws`.
- The React dashboard subscribes to that WebSocket and updates results as each check completes.
- The network layer implements DNS, TCP, TCP timing, traceroute, and TLS inspection.
- SQLAlchemy persists diagnostic runs and per-check results in SQLite.
- Results deliberately separate measured output from interpretation. Traceroute partial output is not treated as proof of an outage.

Background jobs run in the API process and are not durable across process restarts; production deployments should use a managed worker queue. Add authentication, rate limiting, and stricter target authorization before exposing the API publicly.
