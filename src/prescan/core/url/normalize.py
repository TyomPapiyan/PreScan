"""URL normalization: scheme, punycode/IDN, host casing, tracking-param stripping.

Produces a structured view of a URL used by the heuristics, reputation and
inspection stages (§7 stage 1). Detection of IDN/homograph and the registrable
domain feeds the phishing heuristics (§7.1).
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

#: Query parameters stripped as tracking noise (§7 stage 1).
_TRACKING_EXACT: Final = frozenset({"fbclid", "gclid", "yclid", "_openstat"})
_TRACKING_PREFIXES: Final = ("utm_",)

#: Common multi-label public suffixes for a lightweight registrable-domain guess.
#: (A full Public Suffix List is out of scope; this covers frequent cases.)
_MULTI_SUFFIXES: Final = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.nz",
        "com.br",
        "com.cn",
        "co.in",
        "co.kr",
        "com.tr",
    }
)


@dataclass
class NormalizedUrl:
    """Structured, normalized view of a URL."""

    original: str
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    is_ip: bool = False
    is_idn: bool = False
    punycode_host: str | None = None
    registrable_domain: str | None = None
    mixed_scripts: bool = False
    stripped_params: list[str] = field(default_factory=list)


def _strip_tracking(query: str) -> tuple[str, list[str]]:
    """Drop tracking parameters, returning the cleaned query and dropped keys."""
    kept: list[tuple[str, str]] = []
    dropped: list[str] = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in _TRACKING_EXACT or lowered.startswith(_TRACKING_PREFIXES):
            dropped.append(key)
        else:
            kept.append((key, value))
    return urlencode(kept), dropped


def _to_punycode(host: str) -> str | None:
    """Return the ASCII/punycode form of a host, or None on failure."""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def _scripts_of(label: str) -> set[str]:
    """Return the set of alphabet scripts (LATIN/CYRILLIC/GREEK/...) in a label."""
    scripts: set[str] = set()
    for char in label:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HAN"):
            if name.startswith(script):
                scripts.add(script)
                break
    return scripts


def _has_mixed_scripts(host: str) -> bool:
    """True if any single host label mixes alphabets (an IDN-homograph tell)."""
    return any(len(_scripts_of(label)) > 1 for label in host.split("."))


def _registrable_domain(host: str) -> str | None:
    """Best-effort registrable domain (eTLD+1) without a full PSL."""
    labels = host.split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:]) if len(labels) >= 3 else None
    if last_two in _MULTI_SUFFIXES and last_three is not None:
        return last_three
    return last_two


def normalize(url: str) -> NormalizedUrl:
    """Normalize a URL and extract structure for the heuristics stage (§7.1)."""
    raw = url.strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parts = urlsplit(raw)

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    is_idn = any(ord(c) > 127 for c in host)
    punycode_host = _to_punycode(host) if is_idn else None
    mixed = _has_mixed_scripts(host) if is_idn else False
    registrable = None if is_ip else _registrable_domain(host)

    clean_query, dropped = _strip_tracking(parts.query)
    normalized = urlunsplit((scheme, parts.netloc.lower(), parts.path, clean_query, ""))

    return NormalizedUrl(
        original=url,
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path,
        is_ip=is_ip,
        is_idn=is_idn,
        punycode_host=punycode_host,
        registrable_domain=registrable,
        mixed_scripts=mixed,
        stripped_params=dropped,
    )
