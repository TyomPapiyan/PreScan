"""PreScan command-line interface.

A first-class public interface, not a test harness (spec §14.1). ``prescan scan``
returns an exit code by verdict (0 SAFE, 1 SUSPICIOUS, 2 DANGEROUS, 3 UNKNOWN,
4 runtime error) so it is scriptable. Output is human-readable with colour on a
TTY, or machine JSON with ``--json``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from prescan import __version__
from prescan.core.config import AppConfig
from prescan.core.models import ScanReport, ScanRequest, TargetKind, Verdict

app = typer.Typer(
    name="prescan",
    help="Pre-execution malware and link scanner.",
    no_args_is_help=True,
    add_completion=False,
)

_EXIT_BY_VERDICT = {
    Verdict.SAFE: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.DANGEROUS: 2,
    Verdict.UNKNOWN: 3,
}
_RUNTIME_ERROR = 4

_VERDICT_COLOR = {
    Verdict.SAFE: typer.colors.GREEN,
    Verdict.SUSPICIOUS: typer.colors.YELLOW,
    Verdict.DANGEROUS: typer.colors.RED,
    Verdict.UNKNOWN: typer.colors.BRIGHT_BLACK,
}


@app.callback()
def main() -> None:
    """PreScan: check a file before you run it, and a link before you download it."""
    from prescan.core.config import configure_logging

    configure_logging()  # activates secret redaction in logs (§10.5)


@app.command()
def version() -> None:
    """Print the PreScan version and exit."""
    typer.echo(f"PreScan {__version__}")


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Path to a file (URL support: M3).")],
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON.")] = False,
    html: Annotated[Path | None, typer.Option("--html", help="Write an HTML report.")] = None,
    no_network: Annotated[bool, typer.Option("--no-network", help="Layer 1 only.")] = False,
    allow_upload: Annotated[
        bool, typer.Option("--allow-upload", help="Permit cloud upload (stage 13).")
    ] = False,
    download: Annotated[
        bool, typer.Option("--download", help="For a URL: fetch and scan the body.")
    ] = False,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore the local cache.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Overall timeout (s).")] = 300.0,
    quiet: Annotated[bool, typer.Option("--quiet", help="Only the verdict line.")] = False,
) -> None:
    """Scan a file or URL and report a verdict. Exit code encodes the verdict."""
    is_url = target.startswith(("http://", "https://"))
    if is_url:
        request = ScanRequest(
            target_kind=TargetKind.URL,
            url=target,
            allow_network=not no_network,
            allow_cloud_upload=allow_upload,
            allow_download=download,
            force_refresh=refresh,
            timeout_s=timeout,
        )
    else:
        path = Path(target)
        if not path.is_file():
            typer.secho(f"Not a file: {target}", fg=typer.colors.RED, err=True)
            raise typer.Exit(_RUNTIME_ERROR)
        request = ScanRequest(
            target_kind=TargetKind.FILE,
            file_path=path,
            allow_network=not no_network,
            allow_cloud_upload=allow_upload,
            allow_download=download,
            force_refresh=refresh,
            timeout_s=timeout,
        )

    try:
        report = asyncio.run(_run_scan(request))
    except Exception as exc:
        typer.secho(f"Scan failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(_RUNTIME_ERROR) from exc

    if html is not None:
        from prescan.core.report import to_html

        html.write_text(to_html(report), encoding="utf-8")

    if json_out:
        from prescan.core.report import to_json

        typer.echo(to_json(report))
    else:
        _print_human(report, quiet=quiet)

    raise typer.Exit(_EXIT_BY_VERDICT.get(report.verdict, _RUNTIME_ERROR))


@app.command()
def engines() -> None:
    """Show the status of the local detection engines."""
    from prescan.core.config import Paths
    from prescan.core.engines import build_engines

    config = AppConfig.load()
    built = build_engines(config, Paths.resolve())

    async def probe() -> list[tuple[str, str, str]]:
        rows = []
        for engine in built:
            availability, detail = await engine.availability()
            rows.append((engine.name, availability.value, detail))
        return rows

    for name, availability, detail in asyncio.run(probe()):
        colour = typer.colors.GREEN if availability == "ready" else typer.colors.YELLOW
        typer.secho(f"{name:<12} {availability:<16}", fg=colour, nl=False)
        typer.echo(detail)


@app.command(name="update-rules")
def update_rules() -> None:
    """Download or update YARA Forge rules into the user data directory."""
    from prescan.core.config import Paths
    from prescan.core.updater import update_yara_rules

    paths = Paths.resolve()
    paths.ensure()
    try:
        count = asyncio.run(update_yara_rules(paths.yara_rules_dir))
    except Exception as exc:
        typer.secho(f"Rule update failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(_RUNTIME_ERROR) from exc
    typer.secho(f"Installed {count} YARA rule file(s).", fg=typer.colors.GREEN)


async def _run_scan(request: ScanRequest) -> ScanReport:
    """Build a pipeline (with cache/history storage) from config and run it."""
    from prescan.core.config import Paths
    from prescan.core.pipeline import Pipeline
    from prescan.core.storage import Storage

    config = AppConfig.load()
    paths = Paths.resolve()
    paths.ensure()
    storage = Storage(paths.db_path)
    return await Pipeline(config, storage).run(request)


@app.command()
def history(
    limit: Annotated[int, typer.Option("--limit", help="How many entries to show.")] = 20,
) -> None:
    """Show recent scans from the local history."""
    from prescan.core.config import Paths
    from prescan.core.storage import Storage

    storage = Storage(Paths.resolve().db_path)
    rows = storage.list_history(limit=limit)
    if not rows:
        typer.echo("No scans yet.")
        return
    for entry in rows:
        stamp = entry.created_at.strftime("%Y-%m-%d %H:%M")
        typer.echo(f"{stamp}  {entry.verdict:<10}  {entry.target}")


def _print_human(report: ScanReport, *, quiet: bool) -> None:
    """Render a human-readable report to stdout."""
    colour = _VERDICT_COLOR[report.verdict]
    gauge = "—" if report.verdict is Verdict.UNKNOWN else f"{report.risk_score}/100"
    typer.secho(f"{report.verdict.value.upper()}  {gauge}", fg=colour, bold=True)
    if quiet:
        return

    if report.file is not None:
        typer.echo(f"{report.file.name} · {report.file.size} bytes · {report.file.detected_type}")
        typer.echo(f"SHA-256: {report.file.sha256}")
    if report.url is not None:
        typer.echo(f"{report.url.normalized}")
        if report.url.final_url and report.url.final_url != report.url.normalized:
            typer.echo(f"final: {report.url.final_url}")
        if report.url.registrable_domain:
            typer.echo(f"domain: {report.url.registrable_domain}")
    typer.echo(report.verdict_reason_en)

    if report.signals:
        typer.echo("\nSignals:")
        for signal in sorted(report.signals, key=lambda s: s.weight, reverse=True):
            typer.echo(f"  [{signal.severity.value:<8}] {signal.title_en} (weight {signal.weight})")

    if report.incomplete:
        typer.secho(
            f"\nIncomplete scan — unavailable: {', '.join(report.unavailable_sources)}",
            fg=typer.colors.YELLOW,
        )
    typer.secho(
        "\nPreScan is not an antivirus and does not replace your system's protection.",
        fg=typer.colors.BRIGHT_BLACK,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
