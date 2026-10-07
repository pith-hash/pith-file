// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// Every vector in the repository-root reference.json is replayed through
// the cdylib: signature vectors re-synthesize their input bytes locally
// (the splitmix64 / prefix-insert / zeros recipes of tools/gen-reference),
// check the raw-input SHA-256, parse the canonical chunk-set stream and
// verify both recorded folds over the digest set; jaccard vectors
// re-synthesize both inputs and compare the returned IEEE-754 bits
// exactly (policy exact); the text vector extracts the committed PDF
// fixture; the error vectors expect the refusal status. The same vectors
// the Rust gen-reference verify gate and the Python/Go SDKs check.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  FORMAT_PDF,
  FfiError,
  binarySignature,
  findCdylib,
  jaccardBits,
  parseSignatureStream,
  textContent,
} = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

// --- the input synthesis recipes of tools/gen-reference/main.rs ----

// The splitmix64 golden gamma increment.
const GAMMA = 0x9e3779b97f4a7c15n;
// splitmix64 output-mixing multipliers.
const M1 = 0xbf58476d1ce4e5b9n;
const M2 = 0x94d049bb133111ebn;
const U64 = (1n << 64n) - 1n;

/** The Steele/Lea/Flood splitmix64 generator; one next_u64 per byte
 * with the low byte kept — the byte recipe of the generator in
 * pith-digest. */
class SplitMix64 {
  constructor(seed) {
    this.state = BigInt.asUintN(64, BigInt(seed));
  }

  nextU64() {
    this.state = BigInt.asUintN(64, this.state + GAMMA);
    let z = this.state;
    z = BigInt.asUintN(64, (z ^ (z >> 30n)) * M1);
    z = BigInt.asUintN(64, (z ^ (z >> 27n)) * M2);
    return z ^ (z >> 31n);
  }
}

/** The deterministic input bytes for a corpus kind: splitmix64 (one
 * next_u64 per byte, low byte kept), prefix-insert (one 0xAA byte in
 * front of the seed stream) and zeros. */
function buildInput(kind, seed, length) {
  if (kind === "splitmix64") {
    const rng = new SplitMix64(seed);
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      out[i] = Number(rng.nextU64() & 0xffn);
    }
    return out;
  }
  if (kind === "prefix-insert") {
    const rng = new SplitMix64(seed);
    const out = Buffer.alloc(length + 1);
    out[0] = 0xaa;
    for (let i = 0; i < length; i++) {
      out[i + 1] = Number(rng.nextU64() & 0xffn);
    }
    return out;
  }
  if (kind === "zeros") {
    return Buffer.alloc(length);
  }
  throw new TypeError(`unknown corpus kind ${kind}`);
}

/** The FNV-1a 64-bit hash: offset basis 0xcbf29ce484222325, prime
 * 0x100000001b3. */
function fnv1a64(data) {
  let h = 0xcbf29ce484222325n;
  for (const byte of data) {
    h = BigInt.asUintN(64, (h ^ BigInt(byte)) * 0x100000001b3n);
  }
  return h;
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8")).vectors;

const VECTORS = Object.fromEntries(REFERENCE.map((v) => [v.name, v]));

// The signature-vector inputs, synthesized once (the jaccard vectors
// reference them by name).
const INPUTS = new Map(
  REFERENCE
    .filter((v) => v.raw_sha256 !== undefined)
    .map((v) => [
      v.name,
      buildInput(v.input.kind, BigInt("0x" + v.input.seed_hex), v.input.length),
    ]),
);

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

for (const name of Object.keys(VECTORS).filter((n) => VECTORS[n].raw_sha256 !== undefined)) {
  test(`signature vector ${name} is reproduced hex-exact`, () => {
    const vector = VECTORS[name];
    const data = INPUTS.get(name);

    assert.equal(sha256Hex(data), vector.raw_sha256, name);

    const signature = parseSignatureStream(binarySignature(data));
    assert.equal(signature.chunkCount, vector.chunk_digest_count, name);
    if (signature.chunkCount) {
      assert.equal(signature.digests[0].toString("hex"), vector.chunk_digests_first, name);
    } else {
      assert.equal(vector.chunk_digests_first, null, name);
    }

    const folded = Buffer.concat(signature.digests);
    assert.equal(fnv1a64(folded).toString(16).padStart(16, "0"), vector.chunk_digests_fnv1a64, name);
    assert.equal(sha256Hex(folded), vector.chunk_digests_sha256, name);
  });
}

for (const name of Object.keys(VECTORS).filter((n) => VECTORS[n].value_bits !== undefined)) {
  test(`jaccard vector ${name} is bit-exact`, () => {
    const vector = VECTORS[name];
    const a = INPUTS.get(vector.a);
    const b = INPUTS.get(vector.b);
    assert.equal(jaccardBits(a, b).toString(16).padStart(16, "0"), vector.value_bits, name);
  });
}

test("text fixture vector is reproduced hex-exact", () => {
  const vector = VECTORS["text-fixture-text_page"];
  const pdf = fs.readFileSync(path.join(REPO_ROOT, vector.input_path));
  assert.equal(sha256Hex(pdf), vector.input_sha256);

  const extracted = textContent(pdf, FORMAT_PDF);
  assert.equal(extracted.length, vector.text_bytes);
  assert.equal(sha256Hex(extracted), vector.text_sha256);
});

for (const name of Object.keys(VECTORS).filter((n) => VECTORS[n].error_kind !== undefined)) {
  test(`error vector ${name} refuses with status`, () => {
    const vector = VECTORS[name];
    const data = Buffer.from(vector.input_hex, "hex");
    assert.throws(() => textContent(data, FORMAT_PDF), (err) => {
      assert.ok(err instanceof FfiError);
      assert.equal(err.status, -2);
      return true;
    });
  });
}

test("empty stream matches the rust-pinned literals", () => {
  // The 'empty' vector's chunk stream, pinned in the committed
  // reference.json and re-derived by the Rust unit tests: the empty
  // input signs to exactly the 8-byte zero count, the empty digest
  // fold hashes to the empty SHA-256 and the empty FNV-1a input is
  // the offset basis. This test fails loudly even if reference.json
  // were regenerated wrongly.
  const raw = binarySignature(Buffer.alloc(0));
  assert.deepEqual([...raw], new Array(8).fill(0));
  assert.equal(sha256Hex(Buffer.alloc(0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(fnv1a64(Buffer.alloc(0)).toString(16).padStart(16, "0"), "cbf29ce484222325");
});

test("unknown format code is refused, not crashing", () => {
  assert.throws(() => textContent(Buffer.from("%PDF-1.7\nbody"), 99), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -1);
    return true;
  });
});

test("malformed pdf is refused, not crashing", () => {
  assert.throws(() => textContent(Buffer.from("%PDF-1.7\nbody")), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});
