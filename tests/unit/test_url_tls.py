"""Tests for core/url/tls.py certificate parsing helpers (no network)."""

from __future__ import annotations

from prescan.core.url.tls import _cert_time, _from_cert, _issuer


def test_cert_time_parses_openssl_format() -> None:
    parsed = _cert_time("Jun  1 12:00:00 2027 GMT")
    assert parsed is not None
    assert parsed.year == 2027
    assert parsed.month == 6


def test_cert_time_rejects_garbage() -> None:
    assert _cert_time("not a date") is None
    assert _cert_time(None) is None


def test_issuer_prefers_organization() -> None:
    cert = {"issuer": ((("organizationName", "Acme CA"),), (("commonName", "acme"),))}
    assert _issuer(cert) == "Acme CA"


def test_from_cert_builds_valid_result() -> None:
    cert = {
        "issuer": ((("organizationName", "Acme CA"),),),
        "notBefore": "Jun  1 12:00:00 2024 GMT",
        "notAfter": "Jun  1 12:00:00 2027 GMT",
    }
    result = _from_cert(cert, host_match=True)
    assert result.valid is True
    assert result.issuer == "Acme CA"
    assert result.not_after is not None
