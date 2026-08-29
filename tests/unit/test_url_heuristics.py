"""Table-driven tests for the §7.1 phishing heuristics — one case per rule."""

from __future__ import annotations

import pytest

from prescan.core.models import Severity, Signal
from prescan.core.url.heuristics import evaluate
from prescan.core.url.normalize import normalize


def _signal(url: str, title_key: str) -> Signal | None:
    for sig in evaluate(normalize(url)):
        if sig.title_key == title_key:
            return sig
    return None


# (url, title_key, expected severity, expected weight) — one row per §7.1 rule.
_CASES = [
    ("http://203.0.113.9/x", "signal.url.ip", Severity.HIGH, 30),
    ("https://аpple.com", "signal.url.idn_homograph", Severity.CRITICAL, 45),
    ("https://paypal.com.login-secure.ru/", "signal.url.brand_subdomain", Severity.HIGH, 35),
    ("https://a.b.c.d.e.example.com", "signal.url.many_subdomains", Severity.MEDIUM, 12),
    ("https://example.com/" + "a" * 220, "signal.url.long", Severity.LOW, 5),
    ("https://a-b-c-d-e.com", "signal.url.many_hyphens", Severity.LOW, 5),
    ("https://mega.nz/f", "signal.url.disposable_host", Severity.MEDIUM, 15),
    ("https://site.com:8443/", "signal.url.odd_port", Severity.MEDIUM, 10),
    ("http://site.com/a.exe", "signal.url.http_executable", Severity.MEDIUM, 12),
    ("https://site.com/a.exe", "signal.url.executable_link", Severity.MEDIUM, 10),
]


@pytest.mark.parametrize(("url", "key", "severity", "weight"), _CASES)
def test_heuristic_rule(url: str, key: str, severity: Severity, weight: int) -> None:
    sig = _signal(url, key)
    assert sig is not None, f"expected {key} for {url}"
    assert sig.severity is severity
    assert sig.weight == weight


def test_clean_url_has_no_heuristics() -> None:
    assert evaluate(normalize("https://example.com/page")) == []


def test_idn_homograph_apple_example() -> None:
    sig = _signal("https://аpple.com/login", "signal.url.idn_homograph")
    assert sig is not None
    assert sig.severity is Severity.CRITICAL
    assert sig.data.get("punycode") == "xn--pple-43d.com"
