"""Report export to JSON and HTML.

JSON is the canonical, round-trippable form (``to_json`` -> ``ScanReport`` with
no loss). HTML is rendered from a Jinja2 template with autoescaping, so untrusted
values (filenames, signal details, URLs) cannot inject markup (§9.6).
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from jinja2 import Environment, select_autoescape

from prescan.core.models import ScanReport, Severity, Verdict

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def to_json(report: ScanReport) -> str:
    """Serialise a report to indented JSON (round-trips back to ScanReport)."""
    return report.model_dump_json(indent=2)


def from_json(data: str) -> ScanReport:
    """Parse a JSON report back into a ScanReport without loss."""
    return ScanReport.model_validate_json(data)


@lru_cache(maxsize=1)
def _template_source() -> str:
    return (
        resources.files("prescan.resources")
        .joinpath("report_template.html.j2")
        .read_text(encoding="utf-8")
    )


def to_html(report: ScanReport, *, lang: str = "en") -> str:
    """Render the HTML report via the autoescaping Jinja2 template (§9.6)."""
    env = Environment(autoescape=select_autoescape(["html", "j2"]))
    template = env.from_string(_template_source())
    # Sort signals by severity (desc); ties keep pipeline order (§9.6).
    signals = sorted(report.signals, key=lambda s: _SEVERITY_ORDER[s.severity], reverse=True)
    gauge = "—" if report.verdict is Verdict.UNKNOWN else f"{report.risk_score}/100"
    target_name = report.file.name if report.file else (report.url.original if report.url else "")
    return template.render(
        report=report, signals=signals, gauge=gauge, lang=lang, target_name=target_name
    )
