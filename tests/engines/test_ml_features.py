"""core/ml/features.py: the EMBER2024 feature-version-3 vector.

The blocking parity check (M6a) compares our pefile-only extractor against the
reference ``thrember`` extractor byte-for-byte -- a silent feature mismatch would
not raise, it would just feed the model wrong probabilities. ``thrember`` is a
dev-only dependency (it pulls scikit-learn + signify); CI installs it on both
Linux and Windows so the parity tests actually run.

Two parity surfaces, because §3.4 bans the runtime ASN.1 parser and our
Authenticode features are a deliberate zero-approximation:

* unsigned / non-PE inputs -- full bit-for-bit equality (Authenticode is zeros on
  both sides). Runs with real signify where available, else a *loud* no-op signify
  stub (see :func:`_import_thrember`);
* a real embedded-signed Windows binary -- equality on every dim *except* the 8
  Authenticode dims, which are pinned as the documented divergence. Runs only with
  real signify (Windows), never the stub.
"""

from __future__ import annotations

import importlib
import os
import sys
import types
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from prescan.core.ml.features import PEFeatureExtractor
from tests.fixtures.pe import minimal_pe


def _import_thrember() -> tuple[Any, bool]:
    """Import thrember; return ``(module, real_signify)``.

    thrember imports ``signify`` at module load for its Authenticode feature. On
    OpenSSL 3.x (the Linux CI runner) signify's ``oscrypto`` dependency fails to
    import, which would make ``importorskip`` error instead of skip. For unsigned /
    non-PE inputs thrember's Authenticode sub-vector is all zeros regardless of
    signify, so we fall back to a no-op stub -- but *loudly*: a ``RuntimeWarning``
    is emitted (visible in pytest's warnings summary) and ``real_signify=False`` is
    returned, so a stubbed signify can never silently stand in for the real one on a
    signed binary (``test_parity_with_thrember_signed_binary`` skips under the stub).
    If real signify imports (Windows runner, or locally) it is used unchanged and
    ``real_signify=True`` is returned.
    """
    try:
        importlib.import_module("signify.authenticode")
    except Exception:  # noqa: BLE001 - any import failure (e.g. oscrypto/OpenSSL 3.x)
        warnings.warn(
            "thrember parity: real signify failed to import; using a no-op signify "
            "stub. Valid ONLY for unsigned / non-PE inputs -- signed-PE parity is "
            "skipped, not run against the stub.",
            RuntimeWarning,
            stacklevel=2,
        )
        sig = types.ModuleType("signify")
        auth = types.ModuleType("signify.authenticode")
        exc = types.ModuleType("signify.exceptions")

        class _SignedPEFile:
            def __init__(self, *_a: object, **_k: object) -> None: ...
            def iter_signed_datas(self) -> list[object]:
                return []

        class _ParseError(Exception): ...

        auth.SignedPEFile = _SignedPEFile  # type: ignore[attr-defined]
        exc.ParseError = _ParseError  # type: ignore[attr-defined]
        exc.SignerInfoParseError = _ParseError  # type: ignore[attr-defined]
        sig.authenticode = auth  # type: ignore[attr-defined]
        sig.exceptions = exc  # type: ignore[attr-defined]
        sys.modules["signify"] = sig
        sys.modules["signify.authenticode"] = auth
        sys.modules["signify.exceptions"] = exc
        return pytest.importorskip("thrember"), False
    return pytest.importorskip("thrember"), True


# A deterministic ~1 MiB buffer: the full byte range (exercises the vectorized
# ByteEntropyHistogram window loop) plus printable runs that hit the string regexes
# (exercises the vectorized string histogram / counting). The small-input parity
# cases would never reach those large-input code paths.
_BIG_PATTERN = bytes(range(256)) + b"GET /index http://a.b/c system32 kernel32.dll password\n"
_BIG_BUFFER = (_BIG_PATTERN * (1_048_576 // len(_BIG_PATTERN) + 1))[:1_048_576]


def test_feature_dim_is_ember_v3() -> None:
    assert PEFeatureExtractor().dim == 2568


def test_vector_shape_and_dtype_on_non_pe() -> None:
    vec = PEFeatureExtractor().feature_vector(b"just some bytes, not a PE " * 64)
    assert vec.shape == (2568,)
    assert vec.dtype == np.float32


@pytest.mark.parametrize(
    "data",
    [
        minimal_pe(imports=True),  # unsigned PE: exercises header/section/imports
        b"MZ",  # not parseable -> pe is None path
        bytes(range(256)) * 8,  # non-PE bytes
        _BIG_BUFFER,  # ~1 MiB: exercises the vectorized large-input paths
        b"",  # empty
    ],
    ids=["pe", "mz", "bytes", "big1mib", "empty"],
)
def test_parity_with_thrember(data: bytes) -> None:
    """Our vector must equal thrember's exactly on the same bytes.

    Every input here is unsigned / non-PE, so thrember's Authenticode sub-vector is
    all zeros whether signify is real or stubbed -- full equality is meaningful in
    both modes (see ``test_parity_with_thrember_signed_binary`` for the signed case).
    """
    thrember, real = _import_thrember()
    print(f"[parity] signify mode: {'REAL' if real else 'STUB'}")
    if not data:
        pytest.skip("thrember divides by zero on empty input; not a real target")
    mine = PEFeatureExtractor().feature_vector(data)
    ref = np.asarray(thrember.PEFeatureExtractor().feature_vector(data), dtype=np.float32)
    assert mine.shape == ref.shape
    assert np.array_equal(mine, ref)


def _entropy_probe_buffer(rng: np.random.RandomState, kind: int, n: int) -> bytes:
    """A 64 KiB buffer with a byte distribution that stresses the entropy binning."""
    if kind == 0:  # uniform
        return rng.randint(0, 256, n, dtype=np.uint8).tobytes()
    if kind == 1:  # heavily skewed toward zero
        a = np.zeros(n, dtype=np.uint8)
        idx = rng.randint(0, n, n // 50)
        a[idx] = rng.randint(0, 256, idx.size)
        return a.tobytes()
    if kind == 2:  # repeating blocks
        blk = rng.randint(0, 256, rng.randint(1, 64), dtype=np.uint8)
        return np.tile(blk, n // blk.size + 1)[:n].tobytes()
    if kind == 3:  # pure printable text
        return rng.randint(0x20, 0x80, n, dtype=np.uint8).tobytes()
    if kind == 4:  # zeros with rare inserts
        a = np.zeros(n, dtype=np.uint8)
        idx = rng.randint(0, n, rng.randint(1, 200))
        a[idx] = rng.randint(1, 256, idx.size)
        return a.tobytes()
    return rng.choice([0, 128, 255], size=n).astype(np.uint8).tobytes()  # bimodal


def test_byte_entropy_reduction_parity_randomized() -> None:
    """The vectorized ByteEntropyHistogram uses terms.sum(axis=1) instead of the
    scalar np.sum over nonzero bins; a 1-ulp float32 difference would flip an
    int(H*2) entropy bin silently. Sweep varied distributions to catch that -- one
    fixed buffer would not."""
    thrember, _real = _import_thrember()
    mine, ref = PEFeatureExtractor(), thrember.PEFeatureExtractor()
    rng = np.random.RandomState(20260901)
    for i in range(50):
        data = _entropy_probe_buffer(rng, i % 6, 64 * 1024)
        a = mine.feature_vector(data)
        b = np.asarray(ref.feature_vector(data), dtype=np.float32)
        assert np.array_equal(a, b), f"divergence on buffer {i} (kind {i % 6})"


def _authenticode_slice(ext: PEFeatureExtractor) -> slice:
    """The 8 Authenticode dims inside the 2568-vector (§3.4 documented approximation)."""
    offset = 0
    for ft in ext.features:
        if ft.name == "authenticode":
            return slice(offset, offset + ft.dim)
        offset += ft.dim
    raise AssertionError("authenticode feature not found in the extractor")


def _iter_embedded_signed_pes(limit: int = 60) -> Iterator[Path]:
    """Yield local PEs that carry an *embedded* Authenticode signature.

    "Signed" here means a non-empty certificate table (data directory entry
    SECURITY) -- the bytes signify actually parses. Most Windows system binaries are
    catalog-signed (empty table), whose Authenticode sub-vector is zeros on both
    sides and would make the parity check trivial again; scan System32 for one that
    carries an *embedded* signature. Bounded and size-capped to stay fast. No sample
    is copied into the repo -- the runner's own binaries are read in place.
    """
    import pefile

    root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    if not root.is_dir():
        return
    sec = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    names = sorted(p.name for p in root.glob("*.dll")) + sorted(p.name for p in root.glob("*.exe"))
    seen = 0
    for name in names:
        if seen >= limit:
            return
        path = root / name
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                continue
            pe = pefile.PE(str(path), fast_load=True)
            d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec]
            has_cert = d.Size > 0 and d.VirtualAddress > 0
            pe.close()
        except Exception:  # noqa: BLE001 - unparseable file, just skip it
            continue
        if has_cert:
            seen += 1
            yield path


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real embedded-signed system PE")
def test_parity_with_thrember_signed_binary() -> None:
    """Parity on a REAL signed Windows binary.

    Full bit-for-bit parity on a signed PE is impossible *by design*: §3.4 forbids
    the ASN.1 / PKCS#7 parser at runtime, so our :class:`AuthenticodeSignature`
    returns zeros for the 8 certificate fields while thrember (real signify) computes
    them. This test therefore proves the strong claim that survives that limit --
    every dim *outside* those 8 matches thrember bit-for-bit even on a signed PE, so
    the model receives the trained vector on all 2560 non-Authenticode features --
    and pins the divergence to exactly the 8 documented dims. It runs only with real
    signify; under the stub it skips loudly rather than pass on trivial zeros.
    """
    thrember, real = _import_thrember()
    if not real:
        pytest.skip("signed-PE parity requires REAL signify; running under the no-op stub")

    ext = PEFeatureExtractor()
    auth = _authenticode_slice(ext)
    zeros_auth = np.zeros(auth.stop - auth.start, dtype=np.float32)
    ref_ext = thrember.PEFeatureExtractor()

    for path in _iter_embedded_signed_pes():
        data = path.read_bytes()
        ref = np.asarray(ref_ext.feature_vector(data), dtype=np.float32)
        if np.array_equal(ref[auth], zeros_auth):
            continue  # signify could not parse this cert -> not a meaningful signed case
        mine = ext.feature_vector(data)
        warnings.warn(
            f"signed-PE parity: REAL signify; binary={path} ({len(data)} bytes); "
            f"ours[auth]={mine[auth].tolist()} ref[auth]={ref[auth].tolist()}",
            stacklevel=1,
        )
        mask = np.ones(mine.shape[0], dtype=bool)
        mask[auth] = False
        assert np.array_equal(mine[mask], ref[mask]), (
            "divergence OUTSIDE the 8 Authenticode dims on a signed PE -- the pefile "
            "rewrite disagrees with thrember somewhere it must not"
        )
        # Our documented §3.4 approximation: the 8 Authenticode dims stay zero.
        assert np.array_equal(mine[auth], zeros_auth)
        # The reference really parsed a signature (guaranteed by the selection above),
        # so this is a genuine signed case, not zeros matching zeros.
        assert not np.array_equal(ref[auth], zeros_auth)
        return

    pytest.skip("no embedded-signed PE with a signify-parseable certificate found on this runner")
