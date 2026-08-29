"""Tests for core/signature.py."""

from __future__ import annotations

from pathlib import Path

from prescan.core.models import SignatureInfo
from prescan.core.signature import get_signature, signature_signals
from tests.fixtures.elf import minimal_elf


def test_elf_reports_absent_signature(tmp_path: Path) -> None:
    target = tmp_path / "sample.elf"
    target.write_bytes(minimal_elf())
    info = get_signature(target)
    assert info.present is False


def test_missing_file_never_raises(tmp_path: Path) -> None:
    info = get_signature(tmp_path / "nope.bin")
    assert info.present is False
    assert info.error is not None


def test_trusted_signature_signal_is_negative_and_marked() -> None:
    info = SignatureInfo(present=True, valid=True, trusted_chain=True, subject="CN=Acme")
    signals = signature_signals(info)
    assert len(signals) == 1
    assert signals[0].weight < 0
    assert signals[0].data["valid_trusted_signature"] is True


def test_absent_signature_signal_has_small_positive_weight() -> None:
    signals = signature_signals(SignatureInfo(present=False))
    assert len(signals) == 1
    assert signals[0].weight > 0


def test_present_but_untrusted_signature_does_not_escalate() -> None:
    info = SignatureInfo(present=True, valid=False, trusted_chain=False, error="bad chain")
    signals = signature_signals(info)
    assert signals[0].data.get("valid_trusted_signature") is not True
