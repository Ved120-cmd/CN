"""Printable HTML export assembled exclusively from persisted run data."""

import html
import json
import re

_PRIVATE_KEYS = {"password", "passwd", "token", "secret", "authorization", "credential", "credentials",
                 "environment", "env", "stack", "stack_trace", "traceback"}


def _e(value) -> str:
    return html.escape("—" if value is None else str(value), quote=True)


def _safe_value(value):
    if isinstance(value, dict):
        return {key: _safe_value(item) for key, item in value.items()
                if not any(private in str(key).lower() for private in _PRIVATE_KEYS)}
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, str):
        if "traceback (most recent call last)" in value.lower() or re.search(r'File\s+["\'].*["\'],\s+line\s+\d+', value):
            return "Diagnostic error details omitted from report."
        value = re.sub(r"(?i)\b(password|passwd|token|secret|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[redacted]", value)
        value = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[redacted]@", value)
    return value


def render_html_report(run: dict, analysis: dict) -> str:
    results = run.get("results") or []
    selected = run.get("selected_tests") or []
    completed = {row.get("test_type") for row in results}
    missing = [kind for kind in selected if kind not in completed]
    result_sections = []
    for row in results:
        detail = row.get("result") if isinstance(row.get("result"), dict) else {}
        # JSON is escaped as text; it is never interpreted as markup or script.
        measurements = _e(json.dumps(_safe_value(detail), ensure_ascii=False, sort_keys=True, indent=2))
        result_sections.append(
            f"<section><h3>{_e(row.get('test_type'))}: {_e(row.get('status'))}</h3>"
            f"<p>Duration: {_e(row.get('duration_ms'))} ms</p><pre>{measurements}</pre></section>"
        )
    issues = "".join(
        f"<li><strong>{_e(item.get('severity'))}: {_e(item.get('title'))}</strong> "
        f"({_e(item.get('code'))})<p>{_e(item.get('description'))}</p></li>"
        for item in analysis.get("issues", [])
    ) or "<li>No rule-based issues identified in the saved results.</li>"
    hypotheses = "".join(
        f"<li><strong>Hypothesis for {_e(item.get('issue_code'))}:</strong> {_e(item.get('hypothesis'))} "
        f"<em>({_e(item.get('confidence'))})</em></li>"
        for item in analysis.get("possible_causes", [])
    ) or "<li>No issue-specific hypotheses are available.</li>"
    actions = "".join(
        f"<li><strong>{_e(item.get('priority'))} priority:</strong> {_e(item.get('action'))} "
        f"<br>{_e(item.get('reason'))}</li>"
        for item in analysis.get("recommendations", [])
    ) or "<li>No recommendations are available.</li>"
    limitations = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("limitations", [])) or "<li>None recorded.</li>"
    missing_html = "".join(f"<li>{_e(item)}: selected but no saved result</li>" for item in missing) or "<li>None</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetDoctor report — run {_e(run.get('id'))}</title><style>
body{{font:16px/1.55 system-ui,Segoe UI,sans-serif;color:#17233a;max-width:900px;margin:32px auto;padding:0 20px}}
h1,h2{{color:#174b9b}}section,article{{border:1px solid #dce4ef;border-radius:10px;padding:16px;margin:14px 0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fb;padding:12px;border-radius:6px;font-size:13px}}
.meta{{color:#52627a}}.assessment{{font-size:1.15rem;font-weight:650}}@media print{{body{{margin:0;max-width:none}}section,article{{break-inside:avoid}}}}
</style></head><body><header><h1>NetDoctor diagnostic report</h1>
<p class="meta">Run #{_e(run.get('id'))} · Target: {_e(run.get('target'))} · Port: {_e(run.get('port'))}</p>
<p class="meta">Created: {_e(run.get('created_at') or run.get('started_at'))} · Execution status: {_e(run.get('status'))}</p>
<p class="assessment">Overall assessment: {_e(analysis.get('overall_status'))}</p><p>{_e(analysis.get('summary'))}</p>
<p>Analysis generated: {_e(analysis.get('generated_at'))}{' · Preliminary' if analysis.get('preliminary') else ''}</p></header>
<article><h2>Selected checks</h2><p>{_e(', '.join(selected) if selected else 'None recorded')}</p>
<p>Completed: {_e(len(results))} of {_e(run.get('total_tests'))}</p><h3>Not completed</h3><ul>{missing_html}</ul></article>
<article><h2>Detected issues</h2><ul>{issues}</ul><h2>Possible causes (hypotheses)</h2><ul>{hypotheses}</ul>
<h2>Prioritized recommendations</h2><ol>{actions}</ol></article>
<article><h2>Saved test results and measurements</h2>{''.join(result_sections) or '<p>No completed results are saved.</p>'}</article>
<article><h2>Limitations</h2><ul>{limitations}</ul>
<p>Latency values are TCP connection setup timings where measured, not pure round-trip latency. Traceroute probes can be filtered or deprioritized; missing hops alone do not prove an outage.</p></article>
</body></html>"""
