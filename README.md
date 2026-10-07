<p align="center">
  <img src="https://pith-file.n24q02m.com/logo.svg" alt="pith-file" width="120">
</p>

<h1 align="center">pith-file</h1>

<p align="center">
  <strong>File-domain hashing for the pith suite: FastCDC chunk signatures, exact chunk-set Jaccard, PDF text extraction</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-file/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-file/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-file/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-file/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-file/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-file?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-file"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## What it does

The file-domain slice of the suite's hashing facade:

- **`binary_signature(bytes)`** chunks arbitrary bytes with FastCDC
  (min 2 KiB, average 8 KiB, max 32 KiB, default normalization) and
  SHA-256-hashes every chunk into a **unique-digest set** — repeated
  chunks count once;
- **`BinarySignature`** compares two such sets with exact Jaccard
  similarity `|A∩B| / |A∪B|` (two empty sets score `1.0`): identical
  files score `1.0`, a one-byte-prefixed variant stays high
  (content-defined chunking realigns after the insert), unrelated files
  score low;
- **`text_content(bytes, format)`** is the byte source a text pipeline
  hashes over: PDF containers go through `pith_pdf::extract_text`, every
  other format passes the raw bytes through unchanged.

The tier-1 content hash and the cross-modal routing that decides *which*
signature a container gets live in the suite's curator crate, `pith-hash`.

## The pith suite contract

pith-file is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift.
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Repository layout

```
src/                 the pith-file library (no_std + alloc)
tests/fixtures       committed PDF corpus (PROVENANCE.md)
tools/gen-reference  the vector generator binary (bin name: gen-reference)
reference.json       hex-exact cross-SDK test vectors
```

## Install

Rust (the core library):

```bash
cargo add pith-file
```

Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Quick start

```rust
let file = std::fs::read("document.bin")?;

// Tier 2, binary: FastCDC chunk boundaries hashed per chunk; the
// unique-digest set compares with exact Jaccard.
let a = pith_file::binary_signature(&file)?;
let b = pith_file::binary_signature(&variant)?;
println!("{} chunks, jaccard {:.3}", a.len(), a.jaccard(&b));

// The bytes a text pipeline hashes over: PDFs are extracted, other
// formats pass through unchanged.
let text_bytes = pith_file::text_content(&file, pith_digest::Format::Pdf)?;
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash
