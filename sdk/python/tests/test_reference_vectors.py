# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every vector in the repository-root ``reference.json`` is replayed
through the cdylib: signature vectors re-synthesize their input bytes
locally (the splitmix64 / prefix-insert / zeros recipes of
``tools/gen-reference``), check the raw-input SHA-256, parse the
canonical chunk-set stream and verify both recorded folds over the
digest set; jaccard vectors re-synthesize both inputs and compare the
returned IEEE-754 bits exactly (policy ``exact``); the text vector
extracts the committed PDF fixture; the error vectors expect the
refusal status. The same vectors the Rust ``gen-reference verify`` gate
and the Node/Go SDKs check.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pith_file import (
    FORMAT_PDF,
    FfiError,
    binary_signature,
    find_cdylib,
    jaccard_bits,
    parse_signature_stream,
    text_content,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

# --- the input synthesis recipes of tools/gen-reference/main.rs ----

#: The splitmix64 golden gamma increment.
_GAMMA = 0x9E3779B97F4A7C15
#: splitmix64 output-mixing multipliers.
_M1 = 0xBF58476D1CE4E5B9
_M2 = 0x94D049BB133111EB
_U64 = (1 << 64) - 1


class _SplitMix64:
    """The Steele/Lea/Flood splitmix64 generator, one ``next_u64`` per
    byte with the low byte kept — the byte recipe of the generator in
    ``pith-digest``."""

    def __init__(self, seed: int) -> None:
        self._state = seed & _U64

    def next_u64(self) -> int:
        self._state = (self._state + _GAMMA) & _U64
        z = self._state
        z = ((z ^ (z >> 30)) * _M1) & _U64
        z = ((z ^ (z >> 27)) * _M2) & _U64
        return z ^ (z >> 31)


def _build_input(kind: str, seed: int, length: int) -> bytes:
    """The deterministic input bytes for a corpus kind: ``splitmix64``
    (one ``next_u64`` per byte, low byte kept), ``prefix-insert`` (one
    ``0xAA`` byte in front of the seed stream) and ``zeros``."""
    if kind == "splitmix64":
        rng = _SplitMix64(seed)
        return bytes(rng.next_u64() & 0xFF for _ in range(length))
    if kind == "prefix-insert":
        rng = _SplitMix64(seed)
        return b"\xaa" + bytes(rng.next_u64() & 0xFF for _ in range(length))
    if kind == "zeros":
        return bytes(length)
    raise ValueError(f"unknown corpus kind {kind!r}")


def _fnv1a64(data: bytes) -> int:
    """The FNV-1a 64-bit hash: offset basis ``0xcbf29ce484222325``,
    prime ``0x100000001b3``."""
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & _U64
    return h


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _vectors() -> dict[str, dict]:
    raw = json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))
    return {v["name"]: v for v in raw["vectors"]}


_VECTORS = _vectors()

# The signature-vector inputs, synthesized once (the jaccard vectors
# reference them by name).
_INPUTS: dict[str, bytes] = {
    name: _build_input(
        v["input"]["kind"],
        int(v["input"]["seed_hex"], 16),
        v["input"]["length"],
    )
    for name, v in _VECTORS.items()
    if "raw_sha256" in v
}


def test_cdylib_is_discoverable() -> None:
    path = find_cdylib()
    assert path.is_file(), path


@pytest.mark.parametrize("name", sorted(n for n, v in _VECTORS.items() if "raw_sha256" in v))
def test_signature_vector_is_reproduced_hex_exact(name: str) -> None:
    vector = _VECTORS[name]
    data = _INPUTS[name]

    assert _sha256_hex(data) == vector["raw_sha256"], name

    raw = binary_signature(data)
    signature = parse_signature_stream(raw)
    assert signature.chunk_count == vector["chunk_digest_count"], name
    if signature.chunk_count:
        assert (
            signature.digests[0].hex() == vector["chunk_digests_first"]
        ), name
    else:
        assert vector["chunk_digests_first"] is None, name

    folded = b"".join(signature.digests)
    assert _fnv1a64(folded) == int(vector["chunk_digests_fnv1a64"], 16), name
    assert _sha256_hex(folded) == vector["chunk_digests_sha256"], name


@pytest.mark.parametrize(
    "name", sorted(n for n, v in _VECTORS.items() if "value_bits" in v)
)
def test_jaccard_vector_is_bit_exact(name: str) -> None:
    vector = _VECTORS[name]
    a = _INPUTS[vector["a"]]
    b = _INPUTS[vector["b"]]
    assert jaccard_bits(a, b) == int(vector["value_bits"], 16), name


def test_text_fixture_vector_is_reproduced_hex_exact() -> None:
    vector = _VECTORS["text-fixture-text_page"]
    pdf = (REPO_ROOT / vector["input_path"]).read_bytes()
    assert _sha256_hex(pdf) == vector["input_sha256"]

    extracted = text_content(pdf, FORMAT_PDF)
    assert len(extracted) == vector["text_bytes"]
    assert _sha256_hex(extracted) == vector["text_sha256"]


@pytest.mark.parametrize(
    "name", sorted(n for n, v in _VECTORS.items() if "error_kind" in v)
)
def test_error_vector_refuses_with_status(name: str) -> None:
    vector = _VECTORS[name]
    data = bytes.fromhex(vector["input_hex"])
    with pytest.raises(FfiError) as err:
        text_content(data, FORMAT_PDF)
    assert err.value.status == -2, name


def test_empty_stream_matches_the_rust_pinned_literals() -> None:
    # The 'empty' vector's chunk stream, pinned in the committed
    # reference.json and re-derived by the Rust unit tests: the empty
    # input signs to exactly the 8-byte zero count, the empty digest
    # fold hashes to the empty SHA-256 and the empty FNV-1a input is
    # the offset basis. This test fails loudly even if reference.json
    # were regenerated wrongly.
    raw = binary_signature(b"")
    assert raw == bytes(8)
    assert _sha256_hex(raw[:0]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert format(_fnv1a64(b""), "016x") == "cbf29ce484222325"


def test_unknown_format_code_is_refused_not_crashing() -> None:
    with pytest.raises(FfiError) as err:
        text_content(b"%PDF-1.7\nbody", 99)
    assert err.value.status == -1


def test_malformed_pdf_is_refused_not_crashing() -> None:
    with pytest.raises(FfiError) as err:
        text_content(b"%PDF-1.7\nbody")
    assert err.value.status == -2
