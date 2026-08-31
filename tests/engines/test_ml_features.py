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
