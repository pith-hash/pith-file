// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-file SDK: file-domain hashing through koffi.
 *
 * The single Rust core (the `pith-file` cdylib built by
 * `cargo build --release`) is loaded at runtime; koffi is the only
 * runtime dependency.
 *
 * Discovery order (the suite's cdylib convention):
 *
 *  1. `PITH_CDYLIB` — an explicit cdylib *file* path;
 *  2. `PITH_CDYLIB_DIR` — a *directory* scanned for the cdylib names
 *     (the CD pipeline points this at `target/release`);
 *  3. `prebuilds/` — the packaged npm layout the CD publish job
 *     assembles, flat and per `<os-arch>` (e.g. `linux-x64`);
 *  4. `<repo root>/target/release` — the repository working-tree
 *     layout, so a source checkout runs against a local cargo build
 *     with no configuration.
 *
 * The vectors in `reference.json` at the repository root are the
 * hex-exact cross-language source of truth; the conformance tests
 * under `test/` replay all of them through this binding.
 *
 * The FFI surface is three operations plus one free:
 * `pith_file_binary_signature` signs bytes into the canonical
 * chunk-set stream the reference signature vectors are defined over,
 * `pith_file_jaccard` computes the exact chunk-set similarity of two
 * byte strings and reports it as the raw IEEE-754 bit pattern,
 * `pith_file_text_content` extracts the container text (the single
 * FORMAT_PDF wire code), and `pith_file_free` releases the handed-out
 * buffers.
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** Format wire code: a PDF container — the single extraction lane. */
const FORMAT_PDF = 0;

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_file.dll", "libpith_file.so", "libpith_file.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "input rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-file cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{sign: Function, jaccard: Function, text: Function, free: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  const sign = lib.func("pith_file_binary_signature", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("void *")),
    koffi.out(koffi.pointer("size_t")),
  ]);
  const jaccard = lib.func("pith_file_jaccard", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint64_t")),
  ]);
  const text = lib.func("pith_file_text_content", "int32_t", [
    "const uint8_t *",
    "size_t",
    "uint32_t",
    koffi.out(koffi.pointer("void *")),
    koffi.out(koffi.pointer("size_t")),
  ]);
  const free = lib.func("void pith_file_free(void *ptr, size_t len)");
  cached = { sign, jaccard, text, free };
  return cached;
}

// The cdylib refuses NULL data even at len 0 (the suite's C ABI keeps
// the -1 contract for null pointers), while zero-length *input* is a
// legal value — the reference corpus signs the empty stream.
// Zero-length buffers therefore hand the address of a one-byte
// scratch cell.
const SCRATCH = Buffer.alloc(1);

/**
 * @param {Buffer} data
 * @returns {Buffer} a non-empty buffer view for the pointer argument
 */
function ptrArg(data) {
  return data.length ? data : SCRATCH;
}

/**
 * Signs bytes into the canonical chunk-set stream the `reference.json`
 * signature vectors are defined over: `chunk_count` big-endian, then
 * the sorted unique SHA-256 chunk digests. The handed-out cdylib
 * buffer is copied into a JS Buffer and released before returning.
 *
 * @param {Buffer} data the input bytes
 * @returns {Buffer} the canonical chunk-set stream
 * @throws {FfiError} with `status === -2` if the core refused the input
 */
function binarySignature(data) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const { sign, free } = loadLibrary();
  const out = [null];
  const outLen = [0];
  const status = sign(ptrArg(data), data.length, out, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_file_binary_signature", status);
  }
  try {
    // koffi.decode hands back a Uint8Array view over the external
    // buffer; copy it into a Buffer before the cdylib buffer is freed.
    return Buffer.from(koffi.decode(out[0], "uint8_t", Number(outLen[0])));
  } finally {
    free(out[0], Number(outLen[0]));
  }
}

/**
 * Computes the exact Jaccard similarity of the binary signatures of
 * two byte strings. Both signatures are computed inside the cdylib:
 * the arguments are raw bytes, not serialized signatures. Returns the
 * raw IEEE-754 bit pattern of the result — the `value_bits` hex the
 * reference jaccard vectors record (render with
 * `bits.toString(16).padStart(16, "0")`). Two empty inputs score
 * exactly `0x3ff0000000000000` (1.0).
 *
 * @param {Buffer} a first byte string
 * @param {Buffer} b second byte string
 * @returns {bigint} the IEEE-754 bit pattern of the similarity
 * @throws {FfiError} with `status === -1` or `-2` on refusal
 */
function jaccardBits(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError("a and b must be Buffers");
  }
  const { jaccard } = loadLibrary();
  const out = [null];
  const status = jaccard(ptrArg(a), a.length, ptrArg(b), b.length, out);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_file_jaccard", status);
  }
  return BigInt(out[0]);
}

/**
 * Extracts the container text of `data`. `format` is one of the
 * format wire codes (`FORMAT_PDF`); an unknown code throws with
 * `status === -1` and a refused container with `status === -2`. The
 * handed-out cdylib buffer is copied into a JS Buffer and released
 * before returning.
 *
 * @param {Buffer} data the container bytes
 * @param {number} format one of the format wire codes
 * @returns {Buffer} the extracted text bytes
 * @throws {FfiError} with `status === -1` or `-2` on refusal
 */
function textContent(data, format = FORMAT_PDF) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const { text, free } = loadLibrary();
  const out = [null];
  const outLen = [0];
  const status = text(ptrArg(data), data.length, format, out, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_file_text_content", status);
  }
  try {
    return Buffer.from(koffi.decode(out[0], "uint8_t", Number(outLen[0])));
  } finally {
    free(out[0], Number(outLen[0]));
  }
}

/**
 * Re-expresses the canonical chunk-set stream as a plain object.
 *
 * @param {Buffer} raw the canonical chunk-set stream
 * @returns {{chunkCount: number, digests: Buffer[], raw: Buffer}}
 */
function parseSignatureStream(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 8) {
    throw new TypeError("canonical stream is shorter than the 8-byte count");
  }
  const chunkCount = Number(raw.readBigUInt64BE(0));
  const body = raw.subarray(8);
  if (body.length !== chunkCount * 32) {
    throw new TypeError(
      `canonical stream carries ${body.length} digest bytes for a count of ${chunkCount}`,
    );
  }
  const digests = [];
  for (let i = 0; i < chunkCount; i++) {
    digests.push(body.subarray(i * 32, i * 32 + 32));
  }
  return { chunkCount, digests, raw };
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  FORMAT_PDF,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  binarySignature,
  jaccardBits,
  textContent,
  parseSignatureStream,
};
