"""Download of YARA Forge rules into the user data dir.

Rules are never committed (§2.3); they are fetched on demand into the data dir.
With no network the app still starts without a YARA layer and says so. The
download is retried with exponential backoff and extracted through the same
bomb/traversal guards as any untrusted archive (§10.5).

capa rule download is deferred from the first version and not implemented here.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Final

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from prescan.core.archives import safe_extract
from prescan.core.errors import UpdateError

log = structlog.get_logger(__name__)

#: YARA Forge "full" ruleset (permissive licenses only).
YARA_FORGE_FULL_URL: Final = (
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    reraise=True,
)
async def _download(url: str, dest: Path, *, timeout_s: float) -> None:
    """Download ``url`` to ``dest`` with retries; caps redirects and time."""
    timeout = httpx.Timeout(timeout_s, connect=15.0)
    async with (
        httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client,
        client.stream("GET", url) as response,
    ):
        response.raise_for_status()
        with dest.open("wb") as fh:
            async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                fh.write(chunk)


async def update_yara_rules(
    yara_rules_dir: Path,
    *,
    url: str = YARA_FORGE_FULL_URL,
    timeout_s: float = 300.0,
) -> int:
    """Download and install YARA Forge rules. Returns the number of rule files.

    Raises :class:`UpdateError` on any network or extraction failure so the
    caller can report it in the UI without crashing.
    """
    yara_rules_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="prescan-yara-") as tmp:
        tmpdir = Path(tmp)
        archive = tmpdir / "yara-forge.zip"
        try:
            await _download(url, archive, timeout_s=timeout_s)
        except (httpx.HTTPError, OSError) as exc:
            raise UpdateError(f"YARA Forge download failed: {exc}") from exc

        extract_dir = tmpdir / "extracted"
        try:
            safe_extract(archive, extract_dir)
        except Exception as exc:
            raise UpdateError(f"YARA Forge archive could not be extracted: {exc}") from exc

        installed = 0
        for rule_file in sorted(extract_dir.rglob("*.yar")):
            target = yara_rules_dir / rule_file.name
            shutil.copy2(rule_file, target)
            installed += 1

    log.info("yara.rules_installed", count=installed, dir=str(yara_rules_dir))
    return installed
