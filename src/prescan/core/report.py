"""Report export to JSON and HTML.

JSON is the canonical, round-trippable form (``to_json`` -> ``ScanReport`` with
no loss). The full templated HTML report lands on M4; a minimal HTML rendering
is provided so ``--html`` works end to end from M1.
"""

from __future__ import annotations

from prescan.core.models import ScanReport


def to_json(report: ScanReport) -> str:
    """Serialise a report to indented JSON (round-trips back to ScanReport)."""
    return report.model_dump_json(indent=2)


def from_json(data: str) -> ScanReport:
    """Parse a JSON report back into a ScanReport without loss."""
    return ScanReport.model_validate_json(data)


def to_html(report: ScanReport, *, lang: str = "en") -> str:
    """Render a minimal HTML report. Full Jinja2 template arrives on M4."""
    file_name = report.file.name if report.file else (report.url.original if report.url else "")
    rows = "\n".join(
        f"<li><b>{_escape(s.title_en)}</b> — {_escape(s.severity)} (weight {s.weight})</li>"
        for s in report.signals
    )
    return (
        f"<!doctype html><html lang='{_escape(lang)}'><head><meta charset='utf-8'>"
        f"<title>PreScan report</title></head><body>"
        f"<h1>PreScan report</h1>"
        f"<p>Target: {_escape(file_name)}</p>"
        f"<p>Verdict: <b>{_escape(report.verdict)}</b> "
        f"(risk {report.risk_score}/100)</p>"
        f"<p>{_escape(report.verdict_reason_en)}</p>"
        f"<ul>{rows}</ul>"
        f"<footer><small>PreScan is not an antivirus and does not replace your "
        f"system's protection. The verdict is informational.</small></footer>"
        f"</body></html>"
    )


def _escape(value: object) -> str:
    """Minimal HTML escaping for the interim report."""
    text = str(value)
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
