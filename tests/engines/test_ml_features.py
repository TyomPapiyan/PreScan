"""core/ml/features.py: the EMBER2024 feature-version-3 vector.

The blocking parity check (M6a) compares our pefile-only extractor against the
reference ``thrember`` extractor byte-for-byte -- a silent feature mismatch would
not raise, it would just feed the model wrong probabilities. ``thrember`` is a
dev-only dependency (it pulls scikit-learn + signify) and is absent in CI, so the
parity test self-heals to a skip there and must be run locally before M6a closes.
"""

from __future__ import annotations

import numpy as np
import pytest

from prescan.core.ml.features import PEFeatureExtractor
from tests.fixtures.pe import minimal_pe

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
    """Our vector must equal thrember's exactly on the same bytes."""
    thrember = pytest.importorskip("thrember")
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
    thrember = pytest.importorskip("thrember")
    mine, ref = PEFeatureExtractor(), thrember.PEFeatureExtractor()
    rng = np.random.RandomState(20260901)
    for i in range(50):
        data = _entropy_probe_buffer(rng, i % 6, 64 * 1024)
        a = mine.feature_vector(data)
        b = np.asarray(ref.feature_vector(data), dtype=np.float32)
        assert np.array_equal(a, b), f"divergence on buffer {i} (kind {i % 6})"
