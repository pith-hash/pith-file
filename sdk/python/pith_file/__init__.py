# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-file SDK: file-domain hashing through ctypes.

The single Rust core (the ``pith-file`` cdylib built by
``cargo build --release``) is loaded at runtime; this package carries
no third-party dependency — ``ctypes`` is the standard library.

Discovery order (the suite's cdylib convention):

1. ``PITH_CDYLIB`` — an explicit cdylib *file* path;
2. ``PITH_CDYLIB_DIR`` — a *directory* scanned for the cdylib names
   (the CD pipeline points this at ``target/release``);
3. the package directory itself (the built wheel ships the cdylib as
   package data);
4. ``<repo root>/target/release`` — the repository working-tree layout,
   so a source checkout runs against a local cargo build with no
   configuration.

The FFI surface is three operations plus one free:

- ``pith_file_binary_signature`` signs bytes into the canonical
  chunk-set stream the ``reference.json`` signature vectors are
  defined over (``chunk_count`` big-endian, then the sorted unique
  SHA-256 chunk digests);
- ``pith_file_jaccard`` computes the exact chunk-set similarity of two
  byte strings and reports it as the raw IEEE-754 bit pattern;
- ``pith_file_text_content`` extracts the container text (the single
  ``FORMAT_PDF`` wire code);
- ``pith_file_free`` releases the handed-out buffers.
"""

from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Signature",
    "FfiError",
    "LibraryNotFoundError",
    "find_cdylib",
    "binary_signature",
    "jaccard_bits",
    "jaccard",
    "text_content",
    "parse_signature_stream",
    "FORMAT_PDF",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer, an unknown
#: format wire code).
STATUS_INVALID = -1
#: Status: the core pipeline refused the input (a container the PDF
#: text layer rejects).
STATUS_REJECTED = -2

#: Format wire code: a PDF container — the single extraction lane the
#: cdylib exposes.
FORMAT_PDF = 0

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_file.dll", "libpith_file.so", "libpith_file.dylib")


@dataclass(frozen=True)
class Signature:
    """The binary tier-2 signature, re-expressed from the canonical
    chunk-set stream.

    ``digests`` is the sorted unique set of SHA-256 chunk digests —
    exactly the bytes the ``chunk_digests_sha256`` /
    ``chunk_digests_fnv1a64`` reference folds cover.
    """

    #: Number of distinct chunks.
    chunk_count: int
    #: The sorted unique 32-byte chunk digests.
    digests: tuple[bytes, ...]
    #: The canonical byte stream the digest is computed over.
    raw: bytes


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "input rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-file cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        lib.pith_file_binary_signature.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.POINTER(ctypes.c_void_p),  # out buffer
            ctypes.POINTER(ctypes.c_size_t),  # out length
        ]
        lib.pith_file_binary_signature.restype = ctypes.c_int32
        lib.pith_file_jaccard.argtypes = [
            ctypes.c_void_p,  # a
            ctypes.c_size_t,  # a_len
            ctypes.c_void_p,  # b
            ctypes.c_size_t,  # b_len
            ctypes.POINTER(ctypes.c_uint64),  # out bits
        ]
        lib.pith_file_jaccard.restype = ctypes.c_int32
        lib.pith_file_text_content.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.c_uint32,  # format wire code
            ctypes.POINTER(ctypes.c_void_p),  # out buffer
            ctypes.POINTER(ctypes.c_size_t),  # out length
        ]
        lib.pith_file_text_content.restype = ctypes.c_int32
        lib.pith_file_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.pith_file_free.restype = None
        _lib = lib
    return _lib


# The cdylib refuses NULL data even at len 0 (the suite's C ABI keeps
# the -1 contract for null pointers), while zero-length *input* is a
# legal value — the reference corpus signs the empty stream. Zero-length
# buffers therefore hand the address of a one-byte scratch cell.
_EMPTY_CELL = ctypes.create_string_buffer(1)


def _ptr(data: bytes) -> int:
    """A non-NULL address for the buffer ``data``."""
    if len(data):
        return ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p).value
    return ctypes.cast(_EMPTY_CELL, ctypes.c_void_p).value


def binary_signature(data: bytes) -> bytes:
    """Signs ``data`` into the canonical chunk-set stream the
    ``reference.json`` signature vectors are defined over:
    ``chunk_count`` big-endian, then the sorted unique SHA-256 chunk
    digests.

    Raises :class:`FfiError` with ``status == STATUS_INVALID`` for a
    null buffer and ``STATUS_REJECTED`` if the chunker refused (not
    reachable with the spec-pinned parameters); the core never panics
    through this boundary.
    """
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = _load().pith_file_binary_signature(
        _ptr(data), len(data), ctypes.byref(out), ctypes.byref(out_len)
    )
    if status != STATUS_OK:
        raise FfiError("pith_file_binary_signature", status)
    try:
        return ctypes.string_at(out, out_len.value)
    finally:
        _load().pith_file_free(out, out_len.value)


def jaccard_bits(a: bytes, b: bytes) -> int:
    """Computes the exact Jaccard similarity of the binary signatures
    of ``a`` and ``b`` and returns it as the raw IEEE-754 bit pattern
    of the result (the ``value_bits`` hex the reference jaccard vectors
    record). Both signatures are computed inside the cdylib: the
    arguments are raw bytes, not serialized signatures.

    Two empty inputs score exactly ``0x3ff0000000000000`` (1.0) — two
    empty files are identical.
    """
    out = ctypes.c_uint64()
    status = _load().pith_file_jaccard(
        _ptr(a), len(a), _ptr(b), len(b), ctypes.byref(out)
    )
    if status != STATUS_OK:
        raise FfiError("pith_file_jaccard", status)
    return out.value


def jaccard(a: bytes, b: bytes) -> float:
    """The exact Jaccard similarity as a ``float``, decoded from the
    raw IEEE-754 bits :func:`jaccard_bits` returns."""
    bits = jaccard_bits(a, b)
    return struct.unpack(">d", struct.pack(">Q", bits))[0]


def text_content(data: bytes, format: int = FORMAT_PDF) -> bytes:
    """Extracts the container text of ``data``. ``format`` is one of
    the format wire codes (:data:`FORMAT_PDF`); an unknown code raises
    :class:`FfiError` with ``status == STATUS_INVALID``, and a container
    the text layer refuses raises it with ``STATUS_REJECTED``.
    """
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = _load().pith_file_text_content(
        _ptr(data), len(data), format, ctypes.byref(out), ctypes.byref(out_len)
    )
    if status != STATUS_OK:
        raise FfiError("pith_file_text_content", status)
    try:
        return ctypes.string_at(out, out_len.value)
    finally:
        _load().pith_file_free(out, out_len.value)


def parse_signature_stream(raw: bytes) -> Signature:
    """Re-expresses the canonical chunk-set stream as a
    :class:`Signature`."""
    if len(raw) < 8:
        raise ValueError("canonical stream is shorter than the 8-byte count")
    chunk_count = int.from_bytes(raw[:8], "big")
    digests = raw[8:]
    if len(digests) != chunk_count * 32:
        raise ValueError(
            f"canonical stream carries {len(digests)} digest bytes for a "
            f"count of {chunk_count}"
        )
    return Signature(
        chunk_count=chunk_count,
        digests=tuple(digests[i : i + 32] for i in range(0, len(digests), 32)),
        raw=raw,
    )
