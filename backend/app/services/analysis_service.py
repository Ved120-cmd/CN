"""Deterministic analysis of saved diagnostic results; never performs probes."""

from datetime import datetime, timezone

ALL_TESTS = {"dns", "tcp", "latency", "tls", "traceroute"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _issue(code, severity, title, description, test_type, result, strength="strong"):
    return {
        "code": code, "severity": severity, "title": title, "description": description,
        "test_types": [test_type], "evidence_refs": [result["id"]], "evidence_strength": strength,
    }


def analyze_run(run: dict) -> dict:
    """Return explainable findings based only on a serialized, persisted run."""
    results = run.get("results") or []
    selected = list(run.get("selected_tests") or [])
    by_type = {row.get("test_type"): row for row in results}
    issues = []
    causes = []
    recommendations = []
    evidence = []
    limitations = []
    classified_result_ids = set()

    def add(code, severity, title, text, test, result, cause, action, priority="high", strength="strong", next_kind="user_action"):
        issue = _issue(code, severity, title, text, test, result, strength)
        classified_result_ids.add(result.get("id"))
        existing = next((item for item in issues if item["code"] == code), None)
        if existing is None:
            issues.append(issue)
            causes.append({"issue_code": code, "hypothesis": cause, "confidence": "possible cause; not confirmed"})
            recommendations.append({"priority": priority, "action": action, "reason": text,
                                    "related_issue_code": code, "kind": next_kind})
        else:
            existing["evidence_refs"] = list(dict.fromkeys(existing["evidence_refs"] + issue["evidence_refs"]))

    for result in results:
        kind = result.get("test_type")
        detail = result.get("result") if isinstance(result.get("result"), dict) else {}
        evidence.append({"result_id": result.get("id"), "test_type": kind, "status": result.get("status"),
                         "duration_ms": result.get("duration_ms"), "measurements": detail})
        reason = " ".join(str(v) for v in (detail.get("reason"), result.get("error_message"), detail.get("error_message")) if v)
        lowered = reason.lower()

        if kind == "dns" and result.get("status") == "failed" and not (detail.get("resolved_ips") or detail.get("addresses")):
            dns_error = str(detail.get("error_message") or result.get("error_message") or "").lower()
            cause = ("The hostname may be misspelled or have no DNS records." if "does not exist" in lowered or "non-existent" in dns_error or "name or service not known" in dns_error or "no such" in dns_error
                     else "A resolver problem or unavailable DNS record may have prevented resolution.")
            add("DNS_RESOLUTION_FAILED", "high", "Hostname did not resolve",
                reason or "The resolver returned no usable address.", kind, result, cause,
                "Verify the hostname. If authorized, compare its answer with an approved alternate resolver.")

        if kind == "tcp" and result.get("status") == "failed":
            if "refused" in lowered:
                add("TCP_CONNECTION_REFUSED", "high", "TCP connection was refused", reason, kind, result,
                    "The service may not be listening, the port may be closed, or an intermediary may have rejected the connection.",
                    "Verify the intended port and confirm that the service is listening.")
            elif "timed out" in lowered or "timeout" in lowered:
                add("TCP_CONNECTION_TIMEOUT", "high", "TCP connection timed out", reason, kind, result,
                    "Filtering, a silent destination, congestion, or a routing issue may have prevented a response.",
                    "Retry with a bounded timeout and compare reachability using another authorized method.", "medium")
            else:
                add("TCP_CONNECTION_FAILED", "medium", "TCP connection failed", reason or "The connection attempt failed.", kind, result,
                    "A network, host, or intermediary condition may have prevented the connection.",
                    "Verify the target and port, then retry using an authorized method.", "medium", "moderate")

        if kind == "tls" and result.get("status") == "failed" and ("verification" in lowered or "certificate" in lowered):
            add("TLS_VERIFICATION_FAILED", "high", "TLS certificate verification failed", reason, kind, result,
                "The certificate may be expired, mismatched, untrusted, or affected by local trust-store configuration.",
                "Inspect the reported verification error and correct the relevant certificate or trust configuration.")

        if kind == "latency":
            median = detail.get("median_latency_ms")
            threshold = detail.get("warning_threshold_ms")
            if isinstance(median, (int, float)) and not isinstance(median, bool) and isinstance(threshold, (int, float)) and median > threshold:
                add("TCP_CONNECT_TIME_HIGH", "medium", "TCP connection time exceeded its threshold",
                    f"Measured median TCP connection time was {median:g} ms against a configured warning threshold of {threshold:g} ms.",
                    kind, result, "A long network path, congestion, or slow destination connection setup may contribute.",
                    "Repeat the measurement and compare TCP connection times across authorized targets.", "medium", "moderate")

        if kind == "tls":
            days, window = detail.get("days_until_expiry"), detail.get("expiry_warning_days")
            expiry = detail.get("certificate_expires_at")
            if isinstance(days, (int, float)) and not isinstance(days, bool) and isinstance(window, (int, float)) and days <= window and expiry:
                add("TLS_CERTIFICATE_EXPIRING", "medium", "TLS certificate is nearing expiry",
                    f"The saved certificate expiry is {expiry}; measured remaining validity is {days:g} days and the configured warning window is {window:g} days.",
                    kind, result, "The certificate is approaching its recorded expiry date.",
                    "Renew or investigate the certificate before its recorded expiration.", "medium", "strong")

        if kind == "traceroute" and result.get("status") in {"partial", "success"}:
            hops = detail.get("hops") if isinstance(detail.get("hops"), list) else []
            unanswered = sum(
                sum(1 for probe in hop.get("probe_times_ms", []) if probe is None)
                for hop in hops if isinstance(hop, dict) and isinstance(hop.get("probe_times_ms"), list)
            )
            unanswered += sum(1 for hop in hops if isinstance(hop, dict) and not hop.get("responded")
                              and not isinstance(hop.get("probe_times_ms"), list))
            if result.get("status") == "partial" or unanswered:
                trace_text = (f"The destination responded, but {unanswered} trace probe(s) were unanswered."
                              if detail.get("destination_reached") else
                              f"The saved trace contains {len(hops)} hops and {unanswered} unanswered probe(s).")
                if not detail.get("destination_reached"):
                    trace_text += " Missing hops alone do not establish an outage."
                else:
                    trace_text += " Missing intermediate responses alone do not establish an outage."
                add("TRACEROUTE_INCOMPLETE", "low", "Traceroute contains incomplete responses",
                    trace_text, kind, result, "Routers may filter or deprioritize trace probes, or the captured route may be incomplete.",
                    "Compare the trace with TCP connectivity and other available measurements.", "low", "limited")

        if result.get("status") == "failed" and result.get("id") not in classified_result_ids:
            add(f"{str(kind).upper()}_CHECK_FAILED", "medium", f"{str(kind).title()} check failed",
                reason or "The selected check reported a failure; the result alone does not establish a general outage.",
                kind, result, "The check-specific failure may have several causes; available evidence does not isolate one.",
                "Review the saved error detail and repeat this check if appropriate.", "medium", "limited")

    issues.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["code"]))
    recommendations.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item["priority"]], item["related_issue_code"]))
    selected_missing = [kind for kind in selected if kind not in by_type]
    unselected = sorted(ALL_TESTS - set(selected))
    lifecycle = run.get("status", "unknown")
    preliminary = lifecycle in {"queued", "running"} or bool(selected_missing)
    failed_lifecycle = lifecycle == "failed" or bool((run.get("summary_json") or {}).get("lifecycle_failure"))

    if selected_missing:
        limitations.append("Selected checks without a saved result: " + ", ".join(selected_missing) + ".")
    if unselected:
        limitations.append("Not selected and therefore not assessed: " + ", ".join(unselected) + ".")
    if preliminary:
        limitations.append("Analysis is preliminary because the run is queued, running, or missing selected results.")
    if failed_lifecycle:
        limitations.append("The diagnostic run did not finish successfully; findings cover saved results only.")
    if "latency" in by_type:
        limitations.append("Latency is measured as TCP connection setup time, not pure round-trip network latency.")
    if "traceroute" in by_type:
        limitations.append("Traceroute probes may be filtered or deprioritized; missing intermediate hops do not prove an outage.")
    if not results:
        limitations.append("No completed test results are available; no network-health conclusion can be drawn.")

    strong_issues = any(issue["severity"] in {"critical", "high"} for issue in issues)
    any_failed_check = any(row.get("status") == "failed" for row in results)
    degraded = any(issue["code"] in {"TCP_CONNECT_TIME_HIGH", "TLS_CERTIFICATE_EXPIRING"} for issue in issues)
    uncertain_only = any(issue["code"] == "TRACEROUTE_INCOMPLETE" for issue in issues)
    all_selected_complete = bool(selected) and not selected_missing
    full_coverage = all_selected_complete and set(selected) == ALL_TESTS
    if strong_issues or any_failed_check:
        overall = "issue_detected"
    elif degraded:
        overall = "degraded"
    elif failed_lifecycle or not results or lifecycle in {"queued", "running"} or uncertain_only:
        overall = "inconclusive"
    elif not full_coverage or selected_missing:
        overall = "partially_tested"
    elif any(row.get("status") in {"inconclusive", "unsupported"} for row in results):
        overall = "inconclusive"
    else:
        overall = "healthy"

    summaries = {
        "healthy": "No issues were identified in the selected, completed checks. This does not rule out conditions those checks cannot observe.",
        "degraded": "The saved measurements show a performance or certificate-expiry concern that should be reviewed.",
        "issue_detected": "One or more selected checks reported a specific failure; this does not automatically establish a general network outage.",
        "inconclusive": "The saved evidence is insufficient for a reliable overall assessment.",
        "partially_tested": "No higher-priority issue was established, but only part of the available diagnostic coverage was completed.",
    }
    if not issues:
        recommendations.append({"priority": "low", "action": "Run additional relevant checks if you need broader coverage.",
                                "reason": "No issue-specific next action was supported by the saved results.",
                                "related_issue_code": None, "kind": "follow_up_diagnostic"})
    return {
        "run_id": run.get("id"), "lifecycle_status": lifecycle,
        "overall_status": overall, "summary": summaries[overall], "preliminary": preliminary,
        "issues": issues, "possible_causes": causes, "recommendations": recommendations,
        "evidence": evidence, "limitations": list(dict.fromkeys(limitations)),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
