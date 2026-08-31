"""EMBER2024 feature-version-3 vector for ONNX inference.

This is a faithful, dependency-light reimplementation of the feature extractor
from EMBER2024 / ``thrember`` (Apache-2.0, https://github.com/FutureComputing4AI/
EMBER2024). It reproduces the same 2568-dimensional vector so a model trained on
``thrember`` features can be served here, but the runtime uses **only** ``pefile``
and ``numpy`` (spec §3.4): the two external pieces ``thrember`` relies on are
reimplemented locally --

* ``sklearn.feature_extraction.FeatureHasher`` -> :func:`_feature_hash`, a pure
  MurmurHash3 (x86_32, seed 0) hasher verified bit-exact against scikit-learn;
* ``signify`` Authenticode parsing -> :class:`AuthenticodeSignature`, which here
  only distinguishes *unsigned* from *signed*. For an unsigned PE (no security
  directory) and for non-PE inputs the sub-vector is all zeros, matching
  ``thrember`` exactly. For a *signed* PE the certificate sub-fields cannot be
  reproduced without an ASN.1/PKCS#7 parser, so they stay zero -- a documented
  approximation. The parity test therefore exercises unsigned PE and ELF inputs.

LIEF is deliberately not used here: EMBER features are computed on ``pefile`` and
must not be mixed with the LIEF-based static analysis in ``static_pe.py`` (§3.4).
"""

from __future__ import annotations

import math
import re
from collections import Counter, OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import pefile
from numpy.typing import NDArray

from prescan.core.errors import ScanCancelled

_MASK = 0xFFFFFFFF


def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 returning a signed 32-bit int (matches scikit-learn)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & _MASK
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k1 = data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24
        k1 = (k1 * c1) & _MASK
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK
        k1 = (k1 * c2) & _MASK
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & _MASK
        h1 = (h1 * 5 + 0xE6546B64) & _MASK
    tail = length & 3
    k1 = 0
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & _MASK
        k1 = ((k1 << 15) | (k1 >> 17)) & _MASK
        k1 = (k1 * c2) & _MASK
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 >= 0x80000000 else h1


def _feature_hash(
    items: list[Any], n_features: int, input_type: str, alternate_sign: bool = True
) -> NDArray[np.float64]:
    """Pure reimplementation of ``sklearn`` ``FeatureHasher.transform([items])[0]``.

    ``input_type='string'`` treats each item as ``(item, 1)``; ``'pair'`` expects
    ``(name, value)`` tuples. Collisions are summed, matching scikit-learn.
    """
    out = np.zeros(n_features, dtype=np.float64)
    for item in items:
        if input_type == "pair":
            name, value = item
            value = float(value)
        else:
            name = item
            value = 1.0
        h = _murmur3_x86_32(name.encode("utf-8"), 0)
        idx = abs(h) % n_features
        if alternate_sign and h < 0:
            value = -value
        out[idx] += value
    return out


class FeatureType:
    """Base class for a single feature group."""

    name: str = ""
    dim: int = 0

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        """Return a JSON-able intermediate representation."""
        raise NotImplementedError

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        """Turn the intermediate representation into a fixed-size vector."""
        raise NotImplementedError

    def feature_vector(self, bytez: bytes, pe: pefile.PE | None = None) -> NDArray[np.float32]:
        return self.process_raw_features(self.raw_features(bytez, pe))


class GeneralFileInfo(FeatureType):
    """General information about the file."""

    name = "general"
    dim = 3 + 4

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        size = len(bytez)
        arr = np.frombuffer(bytez, dtype=np.uint8)
        # Shannon entropy via a vectorized byte histogram, then the same math.log(x, 2)
        # sum thrember uses (bit-identical log function). NOTE: thrember accumulates in
        # Counter's first-appearance order; we accumulate in byte-value order
        # (np.nonzero). The two are NOT equal in float64 -- they differ by ~1e-15 from
        # float addition being non-associative. Parity holds ONLY because the result is
        # stored as float32 (see the hstack in process_raw_features), which rounds the
        # difference away. Do not rely on exact float64 equality here.
        counts = np.bincount(arr, minlength=256)
        entropy = 0.0
        for v in np.nonzero(counts)[0].tolist():
            p_x = float(counts[v]) / size
            entropy -= p_x * math.log(p_x, 2)
        return {
            "size": size,
            "entropy": entropy,
            "is_pe": 0 if pe is None else 1,
            "start_bytes": [
                int(arr[0]),
                int(arr[1]) if size >= 2 else 0,
                int(arr[2]) if size >= 3 else 0,
                int(arr[3]) if size >= 4 else 0,
            ],
        }

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        return np.hstack(
            [
                raw_obj["size"],
                raw_obj["entropy"],
                raw_obj["is_pe"],  # categorical
                raw_obj["start_bytes"],  # categorical
            ],
            dtype=np.float32,
        )


class ByteHistogram(FeatureType):
    """Non-normalized byte histogram over the whole file."""

    name = "histogram"
    dim = 256

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        return counts / total


class ByteEntropyHistogram(FeatureType):
    """2d byte/entropy histogram (Saxe and Berlin, 2015)."""

    name = "byteentropy"
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048) -> None:
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block: NDArray[np.uint8]) -> tuple[int, NDArray[np.int_]]:
        c = np.bincount(block >> 4, minlength=16)  # 16-bin histogram
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        h = np.sum(-p[wh] * np.log2(p[wh])) * 2

        hbin = int(h * 2)  # up to 16 bins (max entropy is 8 bits)
        if hbin == 16:  # handle entropy = 8.0 bits
            hbin = 15
        return hbin, c

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        output = np.zeros((16, 16), dtype=np.int64)
        a = np.frombuffer(bytez, dtype=np.uint8)
        k = self.window // self.step
        nc = a.shape[0] // self.step
        if a.shape[0] < self.window or self.window % self.step != 0 or nc < k:
            # Small input (or unusual window/step): the original single-block path.
            hbin, c = self._entropy_bin_counts(a)
            output[hbin, :] += c
            return output.flatten().tolist()

        # Vectorized equivalent of the strided per-block loop. A window of `window`
        # bytes stepped by `step` is the concatenation of k = window/step adjacent
        # step-chunks, so per-chunk nibble-hi histograms summed over a k-wide sliding
        # window reproduce each block's 16-bin histogram exactly.
        hi = (a[: nc * self.step] >> 4).reshape(nc, self.step)
        chunk_hist = np.empty((nc, 16), dtype=np.int64)
        for kbin in range(16):
            chunk_hist[:, kbin] = (hi == kbin).sum(axis=1)
        if k == 2:
            window_hist = chunk_hist[:-1] + chunk_hist[1:]
        else:
            csum = np.cumsum(chunk_hist, axis=0)
            head = np.zeros((1, 16), dtype=np.int64)
            window_hist = csum[k - 1 :] - np.vstack([head, csum[:-k]])

        # Per-window entropy in the same float32 order as _entropy_bin_counts.
        p = window_hist.astype(np.float32) / self.window
        with np.errstate(divide="ignore", invalid="ignore"):
            logp = np.log2(p)
            terms = np.where(window_hist > 0, -p * logp, np.float32(0.0))
        h = terms.sum(axis=1) * 2
        hbins = (h * 2).astype(np.int64)
        hbins[hbins == 16] = 15
        np.add.at(output, hbins, window_hist)
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        return counts / total


class StringExtractor(FeatureType):
    """String statistics and IOC/keyword counts."""

    name = "strings"
    dim = 5 + 96 + 76

    def __init__(self) -> None:
        # all consecutive runs of 0x20 - 0x7f that are 5+ characters
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._regexes = {
            "url": re.compile("\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+"),
            "ipv4_addr": re.compile(
                "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
            ),
            "ipv6_addr": re.compile(
                "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|"
                "\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\\b|"
                "\\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\\b"
            ),
            "mac_addr": re.compile("\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b"),
            "email_addr": re.compile("\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b"),
            "btc_wallet": re.compile("[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),
            "file_path": re.compile("\\bC:/"),
            "dos_msg": re.compile("!This program "),
            "registry_key": re.compile("\\b(?:KHEY_|KHLM|HKCU)"),
            "/dev/": re.compile("/dev/"),
            "/proc/": re.compile("/proc/"),
            "/bin/": re.compile("/bin/"),
            "/usr/": re.compile("/usr/"),
            "/tmp/": re.compile("/tmp/"),
            "/URI": re.compile("/URI"),
            "/FlateDecode": re.compile("/FlateDecode"),
            "/EmbeddedFile": re.compile("/EmbeddedFile"),
            "html": re.compile("html", re.IGNORECASE),
            "javascript": re.compile("javascript", re.IGNORECASE),
            "<script": re.compile("<script", re.IGNORECASE),
            ".click(": re.compile(".click", re.IGNORECASE),
            "onlick": re.compile("onclick", re.IGNORECASE),
            "powershell": re.compile("powershell", re.IGNORECASE),
            "Invoke-Expression": re.compile("Invoke-Expression"),
            "Invoke-Command": re.compile("Invoke-Command"),
            "Start-process": re.compile("Start-process"),
            "get": re.compile("GET /", re.IGNORECASE),
            "post": re.compile("POST /", re.IGNORECASE),
            "http": re.compile("HTTP/", re.IGNORECASE),
            "http://": re.compile("http://", re.IGNORECASE),
            "https://": re.compile("https://", re.IGNORECASE),
            "ftp": re.compile("ftp:", re.IGNORECASE),
            "useragent": re.compile("User-Agent", re.IGNORECASE),
            "cookie": re.compile("cookie", re.IGNORECASE),
            "internet": re.compile("internet", re.IGNORECASE),
            "download": re.compile("download", re.IGNORECASE),
            "connect": re.compile("connect", re.IGNORECASE),
            "base64": re.compile("base64", re.IGNORECASE),
            "base64string": re.compile(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            ),
            "crypt": re.compile("crypt"),
            "encode": re.compile("encode", re.IGNORECASE),
            "decode": re.compile("decode", re.IGNORECASE),
            "cache": re.compile("cache", re.IGNORECASE),
            "certificate": re.compile("certificate", re.IGNORECASE),
            "clipboard": re.compile("clipboard", re.IGNORECASE),
            "command": re.compile("command", re.IGNORECASE),
            "create": re.compile("create", re.IGNORECASE),
            "debug": re.compile("debug", re.IGNORECASE),
            "delete": re.compile("delete", re.IGNORECASE),
            "desktop": re.compile("desktop", re.IGNORECASE),
            "directory": re.compile("directory", re.IGNORECASE),
            "disk": re.compile("disk", re.IGNORECASE),
            "environment": re.compile("environment", re.IGNORECASE),
            "enum": re.compile("enum", re.IGNORECASE),
            "exit": re.compile("exit", re.IGNORECASE),
            "file": re.compile("file", re.IGNORECASE),
            "hostname": re.compile("hostname", re.IGNORECASE),
            "install": re.compile("install", re.IGNORECASE),
            "hidden": re.compile("hidden", re.IGNORECASE),
            "keyboard": re.compile("keyboard", re.IGNORECASE),
            "memory": re.compile("memory", re.IGNORECASE),
            "module": re.compile("module", re.IGNORECASE),
            "mutex": re.compile("mutex", re.IGNORECASE),
            "password": re.compile("password", re.IGNORECASE),
            "privilege": re.compile("privilege", re.IGNORECASE),
            "process": re.compile("process", re.IGNORECASE),
            "remote": re.compile("remote", re.IGNORECASE),
            "resource": re.compile("resource", re.IGNORECASE),
            "security": re.compile("security", re.IGNORECASE),
            "service": re.compile("service", re.IGNORECASE),
            "shell": re.compile("shell", re.IGNORECASE),
            "snapshot": re.compile("snapshot", re.IGNORECASE),
            "system": re.compile("system", re.IGNORECASE),
            "thread": re.compile("thread", re.IGNORECASE),
            "token": re.compile("token", re.IGNORECASE),
            "wallet": re.compile("wallet", re.IGNORECASE),
            "window": re.compile("window", re.IGNORECASE),
        }
        self.regex_idxs = {k: v for v, k in enumerate(sorted(self._regexes))}

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        allstrings = self._allstrings.findall(bytez)
        allstrings_ascii = [s.decode() for s in allstrings]
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            shifted = np.frombuffer(b"".join(allstrings), dtype=np.uint8).astype(np.int64)
            shifted -= ord(b"\x20")
            c = np.bincount(shifted, minlength=96)  # histogram count
            # Keep csum as a numpy integer: c.astype(float32) / np.int promotes to
            # float64, which is what thrember does -- casting to a Python int here
            # would silently keep float32 and change the string entropy.
            csum = c.sum()
            p = c.astype(np.float32) / csum
            wh = np.where(c)[0]
            h = float(np.sum(-p[wh] * np.log2(p[wh])))
        else:
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            h = 0.0
            csum = np.int64(0)

        # Per-regex count of how many *strings* contain a match -- the exact same
        # per-string semantic as the original O(strings x regexes) loop, not a count
        # of total matches. Speed comes from scanning each regex once over the strings
        # joined by "\n": that byte (0x0a) is outside the printable class the strings
        # are built from and matches none of the patterns (no DOTALL, no class
        # includes it), so no match can span a join boundary. Each match's start
        # offset maps to its string via searchsorted, and np.unique collapses multiple
        # matches in one string to a single count. If you optimize this further, keep
        # the "distinct strings, no cross-boundary" invariant or the vector drifts.
        string_counts: dict[str, int] = {}
        if allstrings_ascii:
            joined = "\n".join(allstrings_ascii)
            lengths = np.fromiter(
                (len(s) for s in allstrings_ascii), dtype=np.int64, count=len(allstrings_ascii)
            )
            starts = np.empty(len(allstrings_ascii) + 1, dtype=np.int64)
            starts[0] = 0
            np.cumsum(lengths + 1, out=starts[1:])
            for k, r in self._regexes.items():
                positions = [m.start() for m in r.finditer(joined)]
                if positions:
                    idxs = np.searchsorted(starts, positions, side="right") - 1
                    string_counts[k] = int(np.unique(idxs).size)
        ordered_counts = OrderedDict(sorted(string_counts.items()))

        return {
            "numstrings": len(allstrings),
            "avlength": avlength,
            "printabledist": c.tolist(),  # non-normalized histogram
            "printables": int(csum),
            "entropy": float(h),
            "string_counts": ordered_counts,
        }

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        hist_divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        string_counts = np.zeros(len(self.regex_idxs), dtype=np.float32)
        for regex, count in raw_obj["string_counts"].items():
            idx = self.regex_idxs[regex]
            string_counts[idx] = count
        return np.hstack(
            [
                raw_obj["numstrings"],
                raw_obj["avlength"],
                raw_obj["printables"],
                np.asarray(raw_obj["printabledist"]) / hist_divisor,
                raw_obj["entropy"],
                string_counts,
            ]
        ).astype(np.float32)


class HeaderFileInfo(FeatureType):
    """Features from the COFF, OPTIONAL, and DOS headers."""

    name = "header"
    dim = 74

    def __init__(self) -> None:
        self._machine_types = [
            "IMAGE_FILE_MACHINE_UNKNOWN",
            "IMAGE_FILE_MACHINE_I386",
            "IMAGE_FILE_MACHINE_R3000",
            "IMAGE_FILE_MACHINE_R4000",
            "IMAGE_FILE_MACHINE_R10000",
            "IMAGE_FILE_MACHINE_WCEMIPSV2",
            "IMAGE_FILE_MACHINE_ALPHA",
            "IMAGE_FILE_MACHINE_SH3",
            "IMAGE_FILE_MACHINE_SH3DSP",
            "IMAGE_FILE_MACHINE_SH3E",
            "IMAGE_FILE_MACHINE_SH4",
            "IMAGE_FILE_MACHINE_SH5",
            "IMAGE_FILE_MACHINE_ARM",
            "IMAGE_FILE_MACHINE_THUMB",
            "IMAGE_FILE_MACHINE_ARMNT",
            "IMAGE_FILE_MACHINE_AM33",
            "IMAGE_FILE_MACHINE_POWERPC",
            "IMAGE_FILE_MACHINE_POWERPCFP",
            "IMAGE_FILE_MACHINE_IA64",
            "IMAGE_FILE_MACHINE_MIPS16",
            "IMAGE_FILE_MACHINE_ALPHA64",
            "IMAGE_FILE_MACHINE_AXP64",
            "IMAGE_FILE_MACHINE_MIPSFPU",
            "IMAGE_FILE_MACHINE_MIPSFPU16",
            "IMAGE_FILE_MACHINE_TRICORE",
            "IMAGE_FILE_MACHINE_CEF",
            "IMAGE_FILE_MACHINE_EBC",
            "IMAGE_FILE_MACHINE_RISCV32",
            "IMAGE_FILE_MACHINE_RISCV64",
            "IMAGE_FILE_MACHINE_RISCV128",
            "IMAGE_FILE_MACHINE_LOONGARCH32",
            "IMAGE_FILE_MACHINE_LOONGARCH64",
            "IMAGE_FILE_MACHINE_AMD64",
            "IMAGE_FILE_MACHINE_M32R",
            "IMAGE_FILE_MACHINE_ARM64",
            "IMAGE_FILE_MACHINE_CEE",
        ]
        self._machine_types_dict = {mt: i for i, mt in enumerate(self._machine_types)}
        self._subsystem_types = [
            "IMAGE_SUBSYSTEM_UNKNOWN",
            "IMAGE_SUBSYSTEM_NATIVE",
            "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            "IMAGE_SUBSYSTEM_OS2_CUI",
            "IMAGE_SUBSYSTEM_POSIX_CUI",
            "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
            "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            "IMAGE_SUBSYSTEM_EFI_ROM",
            "IMAGE_SUBSYSTEM_XBOX",
            "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
        ]
        self._subsystem_types_dict = {st: i for i, st in enumerate(self._subsystem_types)}
        self._image_characteristics = [
            "RELOCS_STRIPPED",
            "EXECUTABLE_IMAGE",
            "LINE_NUMS_STRIPPED",
            "LOCAL_SYMS_STRIPPED",
            "AGGRESIVE_WS_TRIM",
            "LARGE_ADDRESS_AWARE",
            "16BIT_MACHINE",
            "BYTES_REVERSED_LO",
            "32BIT_MACHINE",
            "DEBUG_STRIPPED",
            "REMOVABLE_RUN_FROM_SWAP",
            "NET_RUN_FROM_SWAP",
            "SYSTEM",
            "DLL",
            "UP_SYSTEM_ONLY",
            "BYTES_REVERSED_HI",
        ]
        self._dll_characteristics = [
            "HIGH_ENTROPY_VA",
            "DYNAMIC_BASE",
            "FORCE_INTEGRITY",
            "NX_COMPAT",
            "NO_ISOLATION",
            "NO_SEH",
            "NO_BIND",
            "APPCONTAINER",
            "WDM_DRIVER",
            "GUARD_CF",
            "TERMINAL_SERVER_AWARE",
        ]
        self._dos_members = [
            "e_magic",
            "e_cblp",
            "e_cp",
            "e_crlc",
            "e_cparhdr",
            "e_minalloc",
            "e_maxalloc",
            "e_ss",
            "e_sp",
            "e_csum",
            "e_ip",
            "e_cs",
            "e_lfarlc",
            "e_ovno",
            "e_oemid",
            "e_oeminfo",
            "e_lfanew",
        ]

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is None:
            return {}

        raw_obj: dict[str, Any] = {}
        raw_obj["coff"] = {
            "timestamp": 0,
            "machine": "",
            "number_of_sections": 0,
            "number_of_symbols": 0,
            "sizeof_optional_header": 0,
            "pointer_to_symbol_table": 0,
            "characteristics": [],
        }
        raw_obj["optional"] = {
            "magic": 0,
            "subsystem": "",
            "major_image_version": 0,
            "minor_image_version": 0,
            "major_linker_version": 0,
            "minor_linker_version": 0,
            "major_operating_system_version": 0,
            "minor_operating_system_version": 0,
            "major_subsystem_version": 0,
            "minor_subsystem_version": 0,
            "sizeof_code": 0,
            "sizeof_headers": 0,
            "sizeof_image": 0,
            "sizeof_initialized_data": 0,
            "sizeof_uninitialized_data": 0,
            "sizeof_stack_reserve": 0,
            "sizeof_stack_commit": 0,
            "sizeof_heap_reserve": 0,
            "sizeof_heap_commit": 0,
            "address_of_entrypoint": 0,
            "base_of_code": 0,
            "base_of_data": 0,
            "image_base": 0,
            "section_alignment": 0,
            "checksum": 0,
            "number_of_rvas_and_sizes": 0,
            "dll_characteristics": [],
        }
        raw_obj["dos"] = dict.fromkeys(self._dos_members, 0)

        raw_obj["coff"]["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        raw_obj["coff"]["machine"] = pefile.MACHINE_TYPE.get(
            pe.FILE_HEADER.Machine, "IMAGE_FILE_MACHINE_UNKNOWN"
        )
        raw_obj["coff"]["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
        raw_obj["coff"]["number_of_symbols"] = pe.FILE_HEADER.NumberOfSymbols
        raw_obj["coff"]["sizeof_optional_header"] = pe.FILE_HEADER.SizeOfOptionalHeader
        raw_obj["coff"]["pointer_to_symbol_table"] = pe.FILE_HEADER.PointerToSymbolTable
        raw_obj["coff"]["characteristics"] = [
            k[11:] for k, v in pe.FILE_HEADER.__dict__.items() if k.startswith("IMAGE_FILE_") and v
        ]
        raw_obj["optional"]["magic"] = pe.OPTIONAL_HEADER.Magic
        raw_obj["optional"]["subsystem"] = pefile.SUBSYSTEM_TYPE.get(
            pe.OPTIONAL_HEADER.Subsystem, "IMAGE_SUBSYSTEM_UNKNOWN"
        )
        raw_obj["optional"]["major_image_version"] = pe.OPTIONAL_HEADER.MajorImageVersion
        raw_obj["optional"]["minor_image_version"] = pe.OPTIONAL_HEADER.MinorImageVersion
        raw_obj["optional"]["major_linker_version"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        raw_obj["optional"]["minor_linker_version"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        raw_obj["optional"]["major_operating_system_version"] = (
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        )
        raw_obj["optional"]["minor_operating_system_version"] = (
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        )
        raw_obj["optional"]["major_subsystem_version"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        raw_obj["optional"]["minor_subsystem_version"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        raw_obj["optional"]["sizeof_code"] = pe.OPTIONAL_HEADER.SizeOfCode
        raw_obj["optional"]["sizeof_headers"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        raw_obj["optional"]["sizeof_image"] = pe.OPTIONAL_HEADER.SizeOfImage
        raw_obj["optional"]["sizeof_initialized_data"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        raw_obj["optional"]["sizeof_uninitialized_data"] = (
            pe.OPTIONAL_HEADER.SizeOfUninitializedData
        )
        raw_obj["optional"]["sizeof_stack_reserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        raw_obj["optional"]["sizeof_stack_commit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        raw_obj["optional"]["sizeof_heap_reserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        raw_obj["optional"]["sizeof_heap_commit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        raw_obj["optional"]["address_of_entrypoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        raw_obj["optional"]["base_of_code"] = pe.OPTIONAL_HEADER.BaseOfCode
        raw_obj["optional"]["image_base"] = pe.OPTIONAL_HEADER.ImageBase
        raw_obj["optional"]["section_alignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        raw_obj["optional"]["checksum"] = pe.OPTIONAL_HEADER.CheckSum
        raw_obj["optional"]["number_of_rvas_and_sizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        raw_obj["optional"]["dll_characteristics"] = [
            k[25:]
            for k, v in pe.OPTIONAL_HEADER.__dict__.items()
            if k.startswith("IMAGE_DLLCHARACTERISTICS_") and v
        ]
        dos_dict = pe.DOS_HEADER.dump_dict()
        for member in self._dos_members:
            if dos_dict[member].get("Value") is not None:
                raw_obj["dos"][member] = dos_dict[member]["Value"]
        return raw_obj

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        return np.hstack(
            [
                raw_obj["coff"]["timestamp"],
                raw_obj["coff"]["number_of_sections"],
                raw_obj["coff"]["number_of_symbols"],
                raw_obj["coff"]["sizeof_optional_header"],
                raw_obj["coff"]["pointer_to_symbol_table"],
                self._machine_types_dict.get(raw_obj["coff"]["machine"], 0),  # categorical
                self._subsystem_types_dict.get(raw_obj["optional"]["subsystem"], 0),  # categorical
                raw_obj["optional"]["major_image_version"],
                raw_obj["optional"]["minor_image_version"],
                raw_obj["optional"]["major_linker_version"],
                raw_obj["optional"]["minor_linker_version"],
                raw_obj["optional"]["major_operating_system_version"],
                raw_obj["optional"]["minor_operating_system_version"],
                raw_obj["optional"]["major_subsystem_version"],
                raw_obj["optional"]["minor_subsystem_version"],
                raw_obj["optional"]["sizeof_code"],
                raw_obj["optional"]["sizeof_headers"],
                raw_obj["optional"]["sizeof_image"],
                raw_obj["optional"]["sizeof_initialized_data"],
                raw_obj["optional"]["sizeof_uninitialized_data"],
                raw_obj["optional"]["sizeof_stack_reserve"],
                raw_obj["optional"]["sizeof_stack_commit"],
                raw_obj["optional"]["sizeof_heap_reserve"],
                raw_obj["optional"]["sizeof_heap_commit"],
                raw_obj["optional"]["address_of_entrypoint"],
                raw_obj["optional"]["base_of_code"],
                raw_obj["optional"]["image_base"],
                raw_obj["optional"]["section_alignment"],
                raw_obj["optional"]["checksum"],
                raw_obj["optional"]["number_of_rvas_and_sizes"],
                [ch in raw_obj["coff"]["characteristics"] for ch in self._image_characteristics],
                [
                    ch in raw_obj["optional"]["dll_characteristics"]
                    for ch in self._dll_characteristics
                ],
                [raw_obj["dos"][member] for member in self._dos_members],
            ]
        ).astype(np.float32)


class SectionInfo(FeatureType):
    """Section names, sizes and entropy summarized with the hashing trick."""

    name = "section"
    dim = 11 + 50 + 50 + 50 + 50 + 10 + 3

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is None:
            return {}

        entry_section = ""
        aoep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in pe.sections:
            if section.contains_rva(aoep):
                entry_section = section.Name.strip(b"\x00").decode(errors="ignore").lower()

        isection = 0
        while entry_section == "" and isection < len(pe.sections):
            if pe.sections[isection].Characteristics & 0x20000000 > 0:
                entry_section = (
                    pe.sections[isection].Name.strip(b"\x00").decode(errors="ignore").lower()
                )
            isection += 1

        raw_obj: dict[str, Any] = {"entry": entry_section}
        raw_obj["sections"] = [
            {
                "name": section.Name.strip(b"\x00").decode(errors="ignore").lower(),
                "size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
                "vsize": section.Misc_VirtualSize,
                "size_ratio": section.SizeOfRawData / len(bytez),
                "vsize_ratio": section.SizeOfRawData / max(section.Misc_VirtualSize, 1),
                "props": [
                    sc[10:] for sc, _ in pefile.section_characteristics if section.__dict__[sc]
                ],
            }
            for section in pe.sections
        ]
        raw_obj["overlay"] = {"size": 0, "size_ratio": 0, "entropy": 0}

        overlay = pe.get_overlay()
        if overlay is not None:
            overlay_size = len(overlay)
            occurences = Counter(bytearray(overlay))
            entropy = 0.0
            for x in occurences.values():
                p_x = float(x) / len(overlay)
                entropy -= p_x * math.log(p_x, 2)
            raw_obj["overlay"] = {
                "size": overlay_size,
                "size_ratio": overlay_size / len(bytez),
                "entropy": entropy,
            }
        return raw_obj

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)

        sections = raw_obj["sections"]
        n_sections = len(sections)
        n_zero_size = sum(1 for s in sections if s["size"] == 0)
        n_emtpy_name = sum(1 for s in sections if s["name"] == "")
        n_rx = sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"])
        n_w = sum(1 for s in sections if "MEM_WRITE" in s["props"])
        entropies = [s["entropy"] for s in sections] + [raw_obj["overlay"]["entropy"]] + [0]
        size_ratios = [s["size_ratio"] for s in sections] + [raw_obj["overlay"]["size_ratio"]] + [0]
        vsize_ratios = [s["vsize_ratio"] for s in sections] + [0]

        general = [
            n_sections,
            n_zero_size,
            n_emtpy_name,
            n_rx,
            n_w,
            max(entropies),
            min(entropies),
            max(size_ratios),
            min(size_ratios),
            max(vsize_ratios),
            min(vsize_ratios),
        ]

        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_sizes_hashed = _feature_hash(section_sizes, 50, "pair")
        section_vsize = [(s["name"], s["vsize"]) for s in sections]
        section_vsize_hashed = _feature_hash(section_vsize, 50, "pair")
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_entropy_hashed = _feature_hash(section_entropy, 50, "pair")
        characteristics = [f"{s['name']}:{p}" for s in sections for p in s["props"]]
        characteristics_hashed = _feature_hash(characteristics, 50, "string")
        entry_name_hashed = _feature_hash([raw_obj["entry"]], 10, "string")

        return np.hstack(
            [
                general,
                section_sizes_hashed,
                section_vsize_hashed,
                section_entropy_hashed,
                characteristics_hashed,
                entry_name_hashed,
                raw_obj["overlay"]["size"],
                raw_obj["overlay"]["size_ratio"],
                raw_obj["overlay"]["entropy"],
            ]
        ).astype(np.float32)


class ImportsInfo(FeatureType):
    """Imported libraries and functions from the import address table."""

    name = "imports"
    dim = 2 + 256 + 1024

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        imports: dict[str, list[str]] = {}
        if pe is None or "DIRECTORY_ENTRY_IMPORT" not in pe.__dict__:
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports[dll_name] = []
            for lib in entry.imports:
                if lib.name is not None and len(lib.name):
                    imports[dll_name].append(lib.name.decode()[:10000])
                elif lib.ordinal is not None:
                    imports[dll_name].append(f"{dll_name}:ordinal{lib.ordinal}")
        return imports

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)

        libraries = list({lib.lower() for lib in raw_obj})
        libraries_hashed = _feature_hash(libraries, 256, "string", alternate_sign=False)
        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = _feature_hash(imports, 1024, "string", alternate_sign=False)
        lengths = [len(imports), len(libraries)]
        return np.hstack([lengths, libraries_hashed, imports_hashed]).astype(np.float32)


class ExportsInfo(FeatureType):
    """Exported functions (count is in GeneralFileInfo)."""

    name = "exports"
    dim = 1 + 128

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is None:
            return []

        clipped_exports = []
        if "DIRECTORY_ENTRY_EXPORT" in pe.__dict__:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None and len(exp.name):
                    clipped_exports.append(exp.name.decode()[:10000])
                elif exp.ordinal is not None:
                    clipped_exports.append(f"ordinal{exp.ordinal}")
        return clipped_exports

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        exports_hashed = _feature_hash(raw_obj, 128, "string")
        return np.hstack([np.array([len(exports_hashed)]), exports_hashed.astype(np.float32)])


class DataDirectories(FeatureType):
    """Size and virtual address of the data directories."""

    name = "datadirectories"
    dim = 16 * 2 + 2

    def __init__(self) -> None:
        self._name_order = [
            "EXPORT",
            "IMPORT",
            "RESOURCE",
            "EXCEPTION",
            "SECURITY",
            "BASERELOC",
            "DEBUG",
            "COPYRIGHT",
            "GLOBALPTR",
            "TLS",
            "LOAD_CONFIG",
            "BOUND_IMPORT",
            "IAT",
            "DELAY_IMPORT",
            "COM_DESCRIPTOR",
            "RESERVED",
        ]

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        output: list[dict[str, Any]] = []
        if pe is None:
            return output

        output.append(
            {
                "has_relocs": int(pe.has_relocs()),
                "has_dynamic_relocs": int(pe.has_dynamic_relocs()),
            }
        )
        for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            output.append(
                {
                    "name": str(data_directory.name).replace("IMAGE_DIRECTORY_ENTRY_", ""),
                    "size": data_directory.Size,
                    "virtual_address": data_directory.VirtualAddress,
                }
            )
        return output

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)

        features = np.zeros(2 * len(self._name_order) + 2, dtype=np.float32)
        for i in range(1, len(raw_obj) - 1):
            idx = self._name_order.index(raw_obj[i]["name"])
            features[2 * idx] = raw_obj[i]["size"]
            features[2 * idx + 1] = raw_obj[i]["virtual_address"]
        features[-2] = raw_obj[0]["has_relocs"]
        features[-1] = raw_obj[0]["has_dynamic_relocs"]
        return features


class RichHeader(FeatureType):
    """Features from the Rich header."""

    name = "richheader"
    dim = 1 + 32

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is not None and pe.RICH_HEADER is not None:
            return pe.RICH_HEADER.values
        return []

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)

        number_of_pairs = int(len(raw_obj) / 2)
        paired_values = [(str(raw_obj[i]), raw_obj[i + 1]) for i in range(0, len(raw_obj) - 1, 2)]
        paired_values_hashed = _feature_hash(paired_values, 32, "pair")
        return np.hstack([number_of_pairs, paired_values_hashed]).astype(np.float32)


class AuthenticodeSignature(FeatureType):
    """Authenticode signature features.

    Runtime constraint (§3.4): no ``signify`` / ASN.1 parser is available, so this
    only detects the *presence* of a signature via the SECURITY data directory.
    Unsigned PEs and non-PE inputs produce an all-zero sub-vector, bit-identical to
    ``thrember``. Signed PEs also produce zeros here (certificate fields are not
    parsed) -- a documented approximation, not exercised by the parity test.
    """

    name = "authenticode"
    dim = 8

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is None:
            return {}
        return {
            "num_certs": 0,
            "self_signed": 0,
            "empty_program_name": 0,
            "no_countersigner": 0,
            "parse_error": 0,
            "chain_max_depth": 0,
            "latest_signing_time": 0,
            "signing_time_diff": 0,
        }

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        return np.hstack(
            [
                raw_obj["num_certs"],
                raw_obj["self_signed"],
                raw_obj["empty_program_name"],
                raw_obj["no_countersigner"],
                raw_obj["parse_error"],
                raw_obj["chain_max_depth"],
                raw_obj["latest_signing_time"],
                raw_obj["signing_time_diff"],
            ]
        ).astype(np.float32)


class PEFormatWarnings(FeatureType):
    """One-hot of normalized pefile parser warnings plus a total count."""

    name = "pefilewarnings"
    dim = 87 + 1

    def __init__(self, warnings_file: Path | None = None) -> None:
        if warnings_file is None:
            warnings_file = Path(__file__).with_name("pefile_warnings.txt")
        self.warning_prefixes: set[str] = set()
        self.warning_suffixes: set[str] = set()
        self.warning_ids: dict[str, int] = {}

        if warnings_file.exists():
            with warnings_file.open("r") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if line.startswith("..."):
                        self.warning_suffixes.add(line[3:])
                        self.warning_ids[line] = i
                    else:
                        self.warning_prefixes.add(line[:-3])
                        self.warning_ids[line] = i

    def raw_features(self, bytez: bytes, pe: pefile.PE | None = None) -> Any:
        if pe is None:
            return []

        warnings = set(pe.get_warnings())
        warnings_norm: set[str] = set()
        for warning in warnings:
            found_warning = False
            for suf in self.warning_suffixes:
                if warning.endswith(suf):
                    warnings_norm.add("..." + suf)
                    found_warning = True
                    break
            if found_warning:
                continue
            for pre in self.warning_prefixes:
                if warning.startswith(pre):
                    warnings_norm.add(pre + "...")
                    break
        return sorted(warnings_norm)

    def process_raw_features(self, raw_obj: Any) -> NDArray[np.float32]:
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        ids = [0.0 for _ in range(self.dim)]
        for warning_norm in raw_obj:
            ids[self.warning_ids[warning_norm]] = 1.0
        ids[self.dim - 1] = len(raw_obj)
        return np.array(ids, dtype=np.float32)


class PEFeatureExtractor:
    """Extract the fixed-size EMBER2024 feature-version-3 vector from raw bytes."""

    def __init__(self) -> None:
        features = OrderedDict(
            [
                ("GeneralFileInfo", GeneralFileInfo()),
                ("ByteHistogram", ByteHistogram()),
                ("ByteEntropyHistogram", ByteEntropyHistogram()),
                ("StringExtractor", StringExtractor()),
                ("HeaderFileInfo", HeaderFileInfo()),
                ("SectionInfo", SectionInfo()),
                ("ImportsInfo", ImportsInfo()),
                ("ExportsInfo", ExportsInfo()),
                ("DataDirectories", DataDirectories()),
                ("RichHeader", RichHeader()),
                ("AuthenticodeSignature", AuthenticodeSignature()),
                ("PEFormatWarnings", PEFormatWarnings()),
            ]
        )
        self.features: list[FeatureType] = list(features.values())
        self.dim: int = sum(fe.dim for fe in self.features)

    def raw_features(
        self, bytez: bytes, should_cancel: Callable[[], bool] | None = None
    ) -> dict[str, Any]:
        pe: pefile.PE | None = None
        try:
            pe = pefile.PE(data=bytez)
        except pefile.PEFormatError:
            pass
        except AttributeError:
            pass
        # Extraction on a 256 MiB file is ~30 s in a worker thread; check for
        # cancellation between feature groups so a user's "Cancel" stops the wasted
        # work promptly instead of after the whole vector is built (CLAUDE.md).
        raw: dict[str, Any] = {}
        for fe in self.features:
            if should_cancel is not None and should_cancel():
                raise ScanCancelled
            raw[fe.name] = fe.raw_features(bytez, pe)
        return raw

    def process_raw_features(self, raw_obj: dict[str, Any]) -> NDArray[np.float32]:
        vectors = [fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]
        return np.hstack(vectors).astype(np.float32)

    def feature_vector(
        self, bytez: bytes, should_cancel: Callable[[], bool] | None = None
    ) -> NDArray[np.float32]:
        return self.process_raw_features(self.raw_features(bytez, should_cancel))
