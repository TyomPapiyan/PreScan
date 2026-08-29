"""Tests for core/url/normalize.py."""

from __future__ import annotations

from prescan.core.url.normalize import normalize


def test_lowercases_host_and_defaults_scheme() -> None:
    n = normalize("Example.COM/Path")
    assert n.scheme == "http"
    assert n.host == "example.com"


def test_strips_tracking_parameters() -> None:
    n = normalize("https://x.com/?utm_source=a&fbclid=b&gclid=c&yclid=d&_openstat=e&keep=1")
    assert set(n.stripped_params) == {"utm_source", "fbclid", "gclid", "yclid", "_openstat"}
    assert "keep=1" in n.normalized
    assert "utm_source" not in n.normalized


def test_detects_ip_host() -> None:
    n = normalize("http://192.168.0.1/x")
    assert n.is_ip is True
    assert n.registrable_domain is None


def test_detects_idn_and_punycode() -> None:
    n = normalize("https://аpple.com")  # cyrillic 'а'
    assert n.is_idn is True
    assert n.mixed_scripts is True
    assert n.punycode_host == "xn--pple-43d.com"


def test_registrable_domain_multi_suffix() -> None:
    assert normalize("https://foo.bar.co.uk").registrable_domain == "bar.co.uk"
    assert normalize("https://a.b.example.com").registrable_domain == "example.com"
