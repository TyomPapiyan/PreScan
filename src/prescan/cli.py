"""PreScan command-line interface.

A first-class public interface, not a test harness (spec §14.1). ``prescan scan``
returns an exit code by verdict (0 SAFE, 1 SUSPICIOUS, 2 DANGEROUS, 3 UNKNOWN,
4 runtime error) so it is scriptable. Output is human-readable with colour on a
TTY, or machine JSON with ``--json``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from prescan import __version__
from prescan.core.config import AppConfig
from prescan.core.models import ScanReport, ScanRequest, StageStatus, TargetKind, Verdict

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
    target: Annotated[str, typer.Argument(help="Path to a file, or an http(s) URL.")],
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable JSON.")] = False,
    html: Annotated[Path | None, typer.Option("--html", help="Write an HTML report.")] = None,
    no_network: Annotated[bool, typer.Option("--no-network", help="Layer 1 only.")] = False,
    allow_upload: Annotated[
        bool,
        typer.Option(
            "--allow-upload",
            help=(
                "Consent to upload this file to the cloud service configured for "
                "uploads (currently VirusTotal) for a fresh scan when it is unknown "
                "there. Off by default; the file leaves your machine only with this "
                "flag. Also requires turning off 'Never upload files to the cloud' in "
                "Settings. Ignored under --no-network."
            ),
        ),
    ] = False,
    download: Annotated[
        bool, typer.Option("--download", help="For a URL: fetch and scan the body.")
    ] = False,
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore the local cache.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Overall timeout (s).")] = 300.0,
    quiet: Annotated[bool, typer.Option("--quiet", help="Only the verdict line.")] = False,
) -> None:
    """Scan a file or URL and report a verdict. Exit code encodes the verdict."""
    config = AppConfig.load()

    # The persistent lock is the master switch (§6.2, §10.5): only the user can turn
    # it off in Settings. A per-run --allow-upload cannot override it. If consent was
    # given while the lock is closed, refuse loudly and name the setting to change --
    # never silently ignore an explicit request to upload. Nothing is scanned.
    if allow_upload and config.never_upload_files:
        typer.secho(
            "--allow-upload was refused: uploads are locked off. Turn off "
            "'Never upload files to the cloud' in Settings (never_upload_files in "
            "config.toml) to allow it. Nothing was uploaded or scanned.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(_RUNTIME_ERROR)

    # --no-network keeps everything local, so it beats --allow-upload: nothing can
    # leave the machine. Honour the stronger privacy switch and note the override.
    upload_consent = allow_upload and not no_network
    if allow_upload and no_network:
        typer.secho(
            "--allow-upload ignored: --no-network keeps everything local; the file "
            "is not uploaded.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    is_url = target.startswith(("http://", "https://"))
    upload_noun = "downloaded file" if is_url else "file"
    if is_url:
        request = ScanRequest(
            target_kind=TargetKind.URL,
            url=target,
            allow_network=not no_network,
            allow_cloud_upload=upload_consent,
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
            allow_cloud_upload=upload_consent,
            allow_download=download,
            force_refresh=refresh,
            timeout_s=timeout,
        )

    # Announce the permission and the service BEFORE the scan, so both are visible
    # even before any bytes move. The service name comes from the same builder that
    # picks the upload provider (never hardcoded here). Never silenced by --quiet --
    # an upload is exactly the kind of thing the user must always see.
    if upload_consent:
        from prescan.core.providers import upload_provider_name

        service = upload_provider_name()
        typer.secho(
            f"Cloud upload authorized: if the {upload_noun} is unknown to {service}, "
            f"its bytes will be sent there for a fresh scan.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    try:
        report = asyncio.run(_run_scan(request, config))
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

    # Report the upload FACT after the scan, straight from the report -- the single
    # source of truth (uploaded_to / uploaded_at). Honest either way, never silenced
    # by --quiet: the user always learns whether the file left the machine.
    if upload_consent:
        if report.uploaded_to is not None:
            when = _local_time(report.uploaded_at) if report.uploaded_at else "an unknown time"
            typer.secho(
                f"The {upload_noun} was uploaded to {report.uploaded_to} at {when}.",
                fg=typer.colors.YELLOW,
                err=True,
            )
        else:
            typer.secho(
                f"The {upload_noun} was not sent to the cloud.",
                fg=typer.colors.BRIGHT_BLACK,
                err=True,
            )

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


@app.command(name="update-model")
def update_model() -> None:
    """Download the ML classifier (model.onnx) into the user data directory.

    The model is not shipped with the app (spec §3.4/§11.2); it is fetched from a
    GitHub Release and its SHA-256 is verified. Until it is installed the ml stage
    degrades gracefully (§6.1) and scans return UNKNOWN instead of a model verdict.
    """
    from prescan.core.config import Paths
    from prescan.core.updater import update_model as _update_model

    paths = Paths.resolve()
    paths.ensure()
    try:
        model_path = asyncio.run(_update_model(paths.model_path))
    except Exception as exc:
        typer.secho(f"Model download failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(_RUNTIME_ERROR) from exc
    typer.secho(f"Installed model: {model_path}", fg=typer.colors.GREEN)


quarantine_app = typer.Typer(help="Manage the quarantine store.", no_args_is_help=True)
app.add_typer(quarantine_app, name="quarantine")


@quarantine_app.command("list")
def quarantine_list() -> None:
    """List quarantined files."""
    from prescan.core.quarantine import list_entries

    entries = list_entries()
    if not entries:
        typer.echo("Quarantine is empty.")
        return
    for entry in entries:
        typer.echo(f"{entry.entry_id[:16]}  {entry.verdict:<10}  {entry.original_name}")


@quarantine_app.command("restore")
def quarantine_restore(
    entry_id: Annotated[str, typer.Argument(help="Quarantine entry id (SHA-256).")],
    dest: Annotated[Path, typer.Argument(help="Destination directory or file.")],
) -> None:
    """Restore a quarantined file to a destination."""
    from prescan.core.quarantine import QuarantineError, restore

    try:
        out = restore(entry_id, dest)
    except QuarantineError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(_RUNTIME_ERROR) from exc
    typer.secho(f"Restored to {out}", fg=typer.colors.GREEN)


@quarantine_app.command("purge")
def quarantine_purge(
    entry_id: Annotated[str, typer.Argument(help="Quarantine entry id (SHA-256).")],
) -> None:
    """Permanently delete a quarantined file."""
    from prescan.core.quarantine import purge

    purge(entry_id)
    typer.secho("Purged.", fg=typer.colors.GREEN)


@app.command(name="update-clamav")
def update_clamav() -> None:
    """Refresh ClamAV signatures (freshclam) and ask clamd to reload them."""
    from prescan.core.updater import update_clamav_databases

    result = asyncio.run(update_clamav_databases(AppConfig.load()))

    if not result.freshclam_ran:
        typer.secho("freshclam: not found", fg=typer.colors.YELLOW)
    elif result.freshclam_ok:
        typer.secho("freshclam: databases refreshed", fg=typer.colors.GREEN)
    else:
        typer.secho(f"freshclam: failed — {result.freshclam_output}", fg=typer.colors.YELLOW)

    # Never report silent success: warn when clamd did not confirm the reload.
    colour = typer.colors.GREEN if result.reloaded else typer.colors.YELLOW
    typer.secho(result.message, fg=colour)


async def _run_scan(request: ScanRequest, config: AppConfig) -> ScanReport:
    """Build a pipeline (with cache/history storage) from config and run it."""
    from prescan.core.config import Paths
    from prescan.core.pipeline import Pipeline
    from prescan.core.storage import Storage

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


def _local_time(dt: datetime) -> str:
    """Render a stored-UTC instant in the machine's local zone with an explicit offset.

    Times are stored in UTC but shown local, with the offset spelled out, so no one
    mistakes a UTC clock for their own wall time (the report and the UI follow suit).
    """
    return dt.astimezone().isoformat(timespec="seconds")


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
        # Surface *why* each source failed, so a broken provider is never silent.
        failed = [s for s in report.stages if s.status is StageStatus.FAILED and s.error]
        for stage in failed:
            typer.secho(f"    {stage.stage_id}: {stage.error}", fg=typer.colors.YELLOW)
    typer.secho(
        "\nPreScan is not an antivirus and does not replace your system's protection.",
        fg=typer.colors.BRIGHT_BLACK,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
