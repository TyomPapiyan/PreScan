"""Local phishing heuristics (§7.1).

Runs instantly, offline, with no limits. Brand and hosting lists are constants
here, not external files (§7.1). Each rule maps to a Signal with the severity and
weight fixed by the spec table.
"""

from __future__ import annotations

from typing import Final

from prescan.core.identify import EXECUTABLE_EXTS
from prescan.core.models import Severity, Signal, SourceKind
from prescan.core.url.normalize import NormalizedUrl

#: Brands frequently impersonated in phishing subdomains.
BRANDS: Final = frozenset(
    {
        "paypal",
        "apple",
        "icloud",
        "microsoft",
        "office365",
        "outlook",
        "google",
        "gmail",
        "amazon",
        "netflix",
        "facebook",
        "instagram",
        "whatsapp",
        "linkedin",
        "dhl",
        "fedex",
        "sberbank",
        "tinkoff",
        "binance",
        "coinbase",
    }
)

#: Disposable / anonymous file-hosting hosts abused for payload delivery.
DISPOSABLE_HOSTS: Final = frozenset(
    {
        "anonfiles.com",
        "bayfiles.com",
        "mega.nz",
        "mediafire.com",
        "dosya.co",
        "file.io",
        "gofile.io",
        "transfer.sh",
        "temp.sh",
        "0x0.st",
        "pastebin.com",
        "discordapp.com",
        "cdn.discordapp.com",
    }
)

_SOURCE: Final = "url-heuristics"
_KIND: Final = SourceKind.HEURISTIC


def _sig(
    severity: Severity, weight: int, key: str, title: str, detail: str = "", **data: object
) -> Signal:
    return Signal(
        source=_SOURCE,
        kind=_KIND,
        severity=severity,
        title_key=key,
        title_en=title,
        detail=detail,
        weight=weight,
        data=dict(data),
    )


def _subdomain_labels(nurl: NormalizedUrl) -> set[str]:
    """Return the labels that sit left of the registrable domain."""
    host, reg = nurl.host, nurl.registrable_domain
    if not reg or not host.endswith(reg):
        return set()
    prefix = host[: -(len(reg) + 1)]  # drop ".<registrable>"
    return {label for label in prefix.split(".") if label}


def evaluate(nurl: NormalizedUrl) -> list[Signal]:
    """Return heuristic signals for a normalized URL (§7.1)."""
    signals: list[Signal] = []

    if nurl.is_ip:
        signals.append(
            _sig(Severity.HIGH, 30, "signal.url.ip", "URL uses a bare IP address", nurl.host)
        )

    if nurl.mixed_scripts:
        signals.append(
            _sig(
                Severity.CRITICAL,
                45,
                "signal.url.idn_homograph",
                "IDN homograph: mixed alphabets in the host",
                nurl.punycode_host or nurl.host,
                punycode=nurl.punycode_host,
            )
        )

    sub_labels = _subdomain_labels(nurl)
    reg_main = nurl.registrable_domain.split(".")[0] if nurl.registrable_domain else ""
    impersonated = sorted(BRANDS & sub_labels - {reg_main})
    if impersonated:
        signals.append(
            _sig(
                Severity.HIGH,
                35,
                "signal.url.brand_subdomain",
                f"Brand in subdomain of a foreign domain: {impersonated[0]}",
                impersonated[0],
                brands=impersonated,
            )
        )

    if len(sub_labels) > 4:
        signals.append(
            _sig(Severity.MEDIUM, 12, "signal.url.many_subdomains", "More than 4 subdomains")
        )

    if len(nurl.original) > 200:
        signals.append(_sig(Severity.LOW, 5, "signal.url.long", "URL longer than 200 characters"))

    if nurl.host.count("-") > 3:
        signals.append(
            _sig(Severity.LOW, 5, "signal.url.many_hyphens", "More than 3 hyphens in the domain")
        )

    if nurl.host in DISPOSABLE_HOSTS:
        signals.append(
            _sig(
                Severity.MEDIUM,
                15,
                "signal.url.disposable_host",
                "Disposable / file-hosting host",
                nurl.host,
            )
        )

    if nurl.port is not None and nurl.port not in (80, 443):
        signals.append(
            _sig(Severity.MEDIUM, 10, "signal.url.odd_port", f"Non-standard port {nurl.port}")
        )

    path_is_executable = _path_has_executable_ext(nurl.path)
    if nurl.scheme == "http" and path_is_executable:
        signals.append(
            _sig(
                Severity.MEDIUM,
                12,
                "signal.url.http_executable",
                "Plain http:// link to executable content",
            )
        )

    if path_is_executable:
        signals.append(
            _sig(
                Severity.MEDIUM,
                10,
                "signal.url.executable_link",
                "Direct link to an executable file",
                nurl.path.rsplit("/", 1)[-1],
            )
        )

    return signals


def _path_has_executable_ext(path: str) -> bool:
    """True if the URL path points at a directly-executable file extension."""
    tail = path.rsplit("/", 1)[-1].lower()
    dot = tail.rfind(".")
    if dot < 0:
        return False
    return tail[dot:] in EXECUTABLE_EXTS
