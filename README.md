# PreScan

**PreScan** checks a file for malware **before you run it**, and inspects a web
link **before you download it**. It is a signal aggregator with an ML score — a
second opinion before execution.

> ⚠️ **PreScan is not an antivirus and does not replace your system's built-in
> protection.** Verdicts are informational. The decision to run a file is
> yours. PreScan never executes the file it inspects — it only reads and parses
> it as data.

Windows and Linux. Desktop GUI (Fluent/WinUI 3) plus a first-class CLI.

## Status

Early development. Built in milestones **M0–M7** (see `PRESCAN-SPEC.md` §12).
Current milestone: **M0 — project skeleton**.

## Requirements

- Python 3.12+
- Optional external tools (each degrades gracefully if absent):
  - **ClamAV** (`clamd`) — install from the official distribution; binaries are
    not bundled (GPL-2.0). See install notes below.
  - **Microsoft Defender** (`MpCmdRun.exe`) — Windows only.
  - **capa** (`flare-capa`) — dev/optional, invoked as an external process.

## Development

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e '.[core,dev]'

# Enable the pre-push hook so the full checklist runs automatically (once):
git config core.hooksPath scripts/hooks

# Run the full local checklist (ruff, ruff format, mypy x2, pytest) any time:
scripts/check.sh
```

## CLI

```
prescan scan <file|url>   # main command
prescan engines           # local engine status
prescan update-rules      # download/update YARA Forge + capa rules
prescan history
prescan quarantine list|restore|purge
prescan version
```

Exit codes for `prescan scan`: `0` SAFE, `1` SUSPICIOUS, `2` DANGEROUS,
`3` UNKNOWN, `4` runtime error.

## Installing ClamAV

<!-- TODO(M7): per-OS install steps + official distribution link. -->

## API keys

Some cloud providers need an API key. Keys are stored in the OS **keyring**,
never in the repository or config files. See `.env.example` for the provider
list.

> **Note:** the Google Safe Browsing and VirusTotal public APIs are free for
> **non-commercial use only**.

<!-- TODO(M2/M3): per-provider key acquisition steps. -->

## License

MIT — see [LICENSE](LICENSE). Third-party component licenses are collected in
[`licenses/`](licenses/) and listed on the About screen (spec §11).

## Roadmap

Not in the first release (spec §15): Downloads-folder monitoring, Explorer /
Nautilus context-menu entry, checksum verification, batch folder scans, and an
optional local **Strelka** (Apache-2.0) or **Assemblyline 4** (MIT) analysis
server reachable over its API.
