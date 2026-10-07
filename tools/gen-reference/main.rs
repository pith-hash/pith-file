//! Regenerates and verifies `reference.json`, the hex-exact cross-SDK
//! test vectors for `pith-file`.
//!
//! Every vector is computed through the crate's public API from inputs
//! that are either the committed PDF fixture (`tests/fixtures/`,
//! embedded at compile time, no working-directory dependence) or inline
//! byte recipes — SplitMix64 streams, constant fills, degenerate sizes —
//! so the output is byte-stable everywhere.
//!
//! A vector pins the observable pipeline in steps: the raw-input SHA-256
//! (the binary tier-1 digest of opaque bytes), the FastCDC chunk
//! boundaries with each chunk's SHA-256 (the composition
//! `binary_signature` is defined over), the unique-digest set of the
//! resulting [`BinarySignature`](pith_file::BinarySignature) (first
//! digest plus an FNV-1a and SHA-256 fold over the sorted digests),
//! Jaccard similarities (raw IEEE-754 bits, hex, policy `exact`), PDF
//! text-extraction digests and the exact refusal messages of malformed
//! containers.
//!
//! Usage:
//! - `gen-reference gen` — recompute every vector and write
//!   `reference.json` at the repository root.
//! - `gen-reference verify` — recompute and compare byte-for-byte
//!   against the committed copy; exit 1 on drift. This is the CI gate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pith_cdc::FastCdc;
use pith_digest::{SplitMix64, fnv1a64, sha256};
use pith_file::{Format, binary_signature, text_content};

/// Where the committed copy lives, relative to the repository root.
const REFERENCE_PATH: &str = "reference.json";
/// The PDF conformance fixture, relative to the repository root.
const PDF_FIXTURE: &str = "tests/fixtures/text_page.pdf";
/// The pinned FastCDC parameter triple of the binary tier-2 signature.
const CDC_PARAMS: (usize, usize, usize) = (2048, 8192, 32768);

/// One chunk-signature corpus entry before measurement.
struct CorpusSpec {
    name: &'static str,
    kind: &'static str,
    seed: u64,
    length: usize,
}

/// The fixed chunk-signature corpus, in file order: the ported
/// duplicate/near-duplicate triad, an unrelated stream, a constant fill
/// (repeated-chunk deduplication), a sub-minimum input (single chunk)
/// and the empty input.
fn corpus_specs() -> [CorpusSpec; 6] {
    [
        CorpusSpec {
            name: "splitmix64-48kib",
            kind: "splitmix64",
            seed: 0xD15E_5EED,
            length: 48 * 1024,
        },
        CorpusSpec {
            name: "splitmix64-48kib-prefix-insert",
            kind: "prefix-insert",
            seed: 0xD15E_5EED,
            length: 48 * 1024,
        },
        CorpusSpec {
            name: "splitmix64-48kib-unrelated",
            kind: "splitmix64",
            seed: 0xBADC_0FFE,
            length: 48 * 1024,
        },
        CorpusSpec {
            name: "zeros-256kib",
            kind: "zeros",
            seed: 0,
            length: 256 * 1024,
        },
        CorpusSpec {
            name: "splitmix64-1kib-submin",
            kind: "splitmix64",
            seed: 9,
            length: 1024,
        },
        CorpusSpec {
            name: "empty",
            kind: "splitmix64",
            seed: 0,
            length: 0,
        },
    ]
}

/// Builds the deterministic input bytes for a corpus kind. The recipes
/// mirror the conformance test byte-for-byte: one `next_u64` per byte,
/// low byte kept, and `prefix-insert` reproduces the ported
/// near-duplicate recipe — one `0xAA` byte in front of the `seed`
/// stream.
fn build_input(kind: &str, seed: u64, length: usize) -> Vec<u8> {
    match kind {
        "splitmix64" => {
            let mut rng = SplitMix64::new(seed);
            (0..length).map(|_| rng.next_u64() as u8).collect()
        }
        "prefix-insert" => {
            let mut rng = SplitMix64::new(seed);
            let mut out = vec![0xAAu8];
            out.reserve(length);
            for _ in 0..length {
                out.push(rng.next_u64() as u8);
            }
            out
        }
        "zeros" => vec![0u8; length],
        other => panic!("unknown corpus kind {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `f64` as 16-digit hex of the IEEE-754 bit pattern.
fn f64_bits(v: f64) -> String {
    format!("{:016x}", v.to_bits())
}

/// The compact transport fold of a chunk-digest set: first digest
/// verbatim, then FNV-1a 64 and SHA-256 over every little-endian digest
/// in sorted order.
struct DigestFold {
    count: usize,
    first: String,
    fnv1a64: u64,
    sha256: String,
}

fn fold_digests(digests: &[[u8; 32]]) -> DigestFold {
    let mut le = Vec::with_capacity(digests.len() * 32);
    for d in digests {
        le.extend_from_slice(d);
    }
    DigestFold {
        count: digests.len(),
        first: hex(digests.first().map_or(&[0u8; 32], |d| d)),
        fnv1a64: fnv1a64(&le),
        sha256: hex(sha256(&le).expect("sha256 of digest set").as_bytes()),
    }
}

/// Serializes one chunk-signature vector: input identity, the raw-byte
/// tier-1 SHA-256, the fold over the unique chunk-digest set and, for
/// the small corpus entries, the full chunk-boundary/digest
/// correlation list.
fn json_sig_vector(name: &str, spec: &CorpusSpec, data: &[u8], with_boundaries: bool) -> String {
    let raw = sha256(data).expect("sha256 of corpus input");
    let sig = binary_signature(data).expect("corpus parameters are spec-pinned valid");
    let fold = fold_digests(&sig.chunks());
    let mut fields = vec![format!("      \"name\": \"{name}\"")];
    fields.push(format!(
        "      \"input\": {{ \"kind\": \"{}\", \"seed_hex\": \"{:016x}\", \"length\": {} }}",
        spec.kind, spec.seed, spec.length
    ));
    fields.push(format!(
        "      \"cdc_params\": {{ \"min\": {}, \"avg\": {}, \"max\": {} }}",
        CDC_PARAMS.0, CDC_PARAMS.1, CDC_PARAMS.2
    ));
    fields.push(format!("      \"raw_sha256\": \"{}\"", hex(raw.as_bytes())));
    fields.push(format!("      \"chunk_digest_count\": {}", fold.count));
    if fold.count == 0 {
        fields.push("      \"chunk_digests_first\": null".to_owned());
    } else {
        fields.push(format!("      \"chunk_digests_first\": \"{}\"", fold.first));
    }
    fields.push(format!(
        "      \"chunk_digests_fnv1a64\": \"{:016x}\"",
        fold.fnv1a64
    ));
    fields.push(format!(
        "      \"chunk_digests_sha256\": \"{}\"",
        fold.sha256
    ));
    if with_boundaries {
        let mut rows = Vec::new();
        for c in FastCdc::new(data, CDC_PARAMS.0, CDC_PARAMS.1, CDC_PARAMS.2)
            .expect("corpus parameters are spec-pinned valid")
        {
            let d = sha256(&data[c.offset..c.offset + c.length]).expect("sha256 of one chunk");
            rows.push(format!(
                "        [{}, {}, \"{}\"]",
                c.offset,
                c.length,
                hex(d.as_bytes())
            ));
        }
        fields.push(format!(
            "      \"chunks\": [\n{}\n      ]",
            rows.join(",\n")
        ));
    }
    object(&fields)
}

/// Serializes one Jaccard vector: raw IEEE-754 bits, policy `exact`.
fn json_jaccard_vector(name: &str, a: &str, b: &str, value: f64) -> String {
    object(&[
        format!("      \"name\": \"{name}\""),
        format!("      \"a\": \"{a}\""),
        format!("      \"b\": \"{b}\""),
        "      \"value_kind\": \"f64-ieee754-bits-hex\"".to_owned(),
        "      \"policy\": \"exact\"".to_owned(),
        format!("      \"value_bits\": \"{}\"", f64_bits(value)),
    ])
}

/// Serializes one text-extraction vector: extraction size and SHA-256
/// of the extracted bytes.
fn json_text_vector(name: &str, source: &str, source_sha256: &str, extracted: &[u8]) -> String {
    let text_digest = sha256(extracted).expect("sha256 of extracted text");
    object(&[
        format!("      \"name\": \"{name}\""),
        "      \"input_kind\": \"fixture-file\"".to_owned(),
        format!("      \"input_path\": \"{source}\""),
        format!("      \"input_sha256\": \"{source_sha256}\""),
        "      \"format\": \"pdf\"".to_owned(),
        format!("      \"text_bytes\": {}", extracted.len()),
        format!("      \"text_sha256\": \"{}\"", hex(text_digest.as_bytes())),
    ])
}

/// Serializes one error vector: the exact `Display` message of the
/// refusal.
fn json_error_vector(name: &str, input_hex: &str, message: &str) -> String {
    object(&[
        format!("      \"name\": \"{name}\""),
        "      \"input_kind\": \"inline-hex\"".to_owned(),
        format!("      \"input_hex\": \"{input_hex}\""),
        "      \"format\": \"pdf\"".to_owned(),
        "      \"error_kind\": \"Pdf\"".to_owned(),
        format!("      \"error_message\": \"{message}\""),
    ])
}

/// Serializes one vector from ordered field lines.
fn object(fields: &[String]) -> String {
    let mut s = String::from("    {\n");
    s.push_str(&fields.join(",\n"));
    s.push_str("\n    }");
    s
}

fn pdf_fixture() -> Vec<u8> {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/text_page.pdf"
    ));
    bytes.to_vec()
}

/// Builds the whole reference.json text.
fn reference_json() -> String {
    let mut vectors: Vec<String> = Vec::new();

    // --- chunk-signature vectors: full boundaries only for the small
    //     entries, folds for the multi-KB streams ---
    for spec in corpus_specs() {
        let data = build_input(spec.kind, spec.seed, spec.length);
        let with_boundaries = matches!(spec.name, "empty" | "splitmix64-1kib-submin");
        vectors.push(json_sig_vector(spec.name, &spec, &data, with_boundaries));
    }

    // --- Jaccard vectors: raw IEEE-754 bits, policy exact ---
    let base = build_input("splitmix64", 0xD15E_5EED, 48 * 1024);
    let shifted = build_input("prefix-insert", 0xD15E_5EED, 48 * 1024);
    let unrelated = build_input("splitmix64", 0xBADC_0FFE, 48 * 1024);
    let sig_base = binary_signature(&base).expect("valid");
    let sig_shifted = binary_signature(&shifted).expect("valid");
    let sig_unrelated = binary_signature(&unrelated).expect("valid");
    let sig_empty = binary_signature(b"").expect("valid");
    vectors.push(json_jaccard_vector(
        "jaccard-identical",
        "splitmix64-48kib",
        "splitmix64-48kib",
        sig_base.jaccard(&sig_base),
    ));
    vectors.push(json_jaccard_vector(
        "jaccard-near-duplicate",
        "splitmix64-48kib",
        "splitmix64-48kib-prefix-insert",
        sig_base.jaccard(&sig_shifted),
    ));
    vectors.push(json_jaccard_vector(
        "jaccard-unrelated",
        "splitmix64-48kib",
        "splitmix64-48kib-unrelated",
        sig_base.jaccard(&sig_unrelated),
    ));
    vectors.push(json_jaccard_vector(
        "jaccard-against-empty",
        "splitmix64-48kib",
        "empty",
        sig_base.jaccard(&sig_empty),
    ));
    vectors.push(json_jaccard_vector(
        "jaccard-empty-empty",
        "empty",
        "empty",
        sig_empty.jaccard(&sig_empty),
    ));

    // --- text-extraction vectors: the committed PDF fixture ---
    let pdf = pdf_fixture();
    let pdf_sha = hex(sha256(&pdf).expect("sha256 of pdf fixture").as_bytes());
    let extracted = text_content(&pdf, Format::Pdf).expect("committed fixture must extract");
    vectors.push(json_text_vector(
        "text-fixture-text_page",
        PDF_FIXTURE,
        &pdf_sha,
        &extracted,
    ));

    // --- error vectors: malformed PDF containers refuse with an exact
    //     message; the chunker path cannot refuse (spec-pinned
    //     parameters), so it has no vector by construction ---
    let gutted = b"%PDF-1.7\nbody".to_vec();
    let gutted_msg = match text_content(&gutted, Format::Pdf) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("gutted pdf must refuse"),
    };
    vectors.push(json_error_vector(
        "error-pdf-gutted",
        &hex(&gutted),
        &gutted_msg,
    ));
    let empty_msg = match text_content(b"", Format::Pdf) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("empty pdf must refuse"),
    };
    vectors.push(json_error_vector("error-pdf-empty", "", &empty_msg));

    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"suite\": \"pith\",\n");
    s.push_str("  \"crate\": \"pith-file\",\n");
    s.push_str("  \"format_version\": 1,\n");
    s.push_str("  \"generator\": \"cargo run --bin gen-reference -- gen\",\n");
    s.push_str("  \"description\": \"Hex-exact file-domain reference vectors for pith-file: raw-byte SHA-256, FastCDC chunk boundaries with per-chunk SHA-256 digests, unique chunk-digest set folds, exact Jaccard similarities (IEEE-754 bits), PDF text-extraction digests and exact PDF refusal messages over the committed fixture and inline corpus.\",\n");
    s.push_str("  \"vectors\": [\n");
    s.push_str(&vectors.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");
    s
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let path = args.next().map(PathBuf::from);
    run(&mode, path.as_deref())
}

/// One CLI invocation, split out of [`main`] so the mode dispatch is
/// unit-testable. `path` overrides the repository-root `reference.json`.
fn run(mode: &str, path: Option<&Path>) -> ExitCode {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join(REFERENCE_PATH));
    match mode {
        "gen" => {
            let json = reference_json();
            fs::write(&path, &json).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
            println!("wrote {} ({} bytes)", path.display(), json.len());
            ExitCode::SUCCESS
        }
        "verify" => {
            let json = reference_json();
            let committed = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: cannot read {path:?}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if committed == json.as_bytes() {
                println!("reference.json is current");
                ExitCode::SUCCESS
            } else {
                let off = committed
                    .iter()
                    .zip(json.as_bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(committed.len().min(json.len()));
                eprintln!(
                    "FAIL: reference.json is stale: committed {} bytes, computed {} bytes, first difference at byte {off}",
                    committed.len(),
                    json.len()
                );
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: gen-reference <gen|verify> [PATH] (got {mode:?})");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pipeline pins: the empty input has no chunks and Jaccard 1.0,
    /// the constant fill deduplicates many boundaries to one digest.
    #[test]
    fn chunking_pins_the_edges() {
        let empty = binary_signature(b"").expect("valid");
        assert_eq!(empty.len(), 0);
        assert_eq!(f64_bits(empty.jaccard(&empty)), "3ff0000000000000");

        let zeros = build_input("zeros", 0, 256 * 1024);
        let sig = binary_signature(&zeros).expect("valid");
        assert_eq!(sig.len(), 1);
    }

    /// The sub-minimum input is one whole-input chunk; the fold must be
    /// the digest of exactly that chunk.
    #[test]
    fn submin_input_is_one_whole_chunk() {
        let data = build_input("splitmix64", 9, 1024);
        let sig = binary_signature(&data).expect("valid");
        assert_eq!(sig.len(), 1);
        let whole = sha256(&data).expect("sha256").as_bytes().to_owned();
        assert_eq!(sig.chunks()[0], whole);
    }

    /// Jaccard bits: 1.0 is exact and the empty pins hold.
    #[test]
    fn jaccard_bits_pins_the_edges() {
        assert_eq!(f64_bits(1.0), "3ff0000000000000");
        assert_eq!(f64_bits(0.0), "0000000000000000");
    }

    /// The committed fixture extracts to valid UTF-8 with the WinAnsi
    /// decoding of the unmapped byte (`na<EF>ve` → `naïve`), the
    /// upstream oracle property the fixture is inherited for.
    #[test]
    fn fixture_extracts_winansi_naive() {
        let pdf = pdf_fixture();
        let text = text_content(&pdf, Format::Pdf).expect("fixture must extract");
        let text = core::str::from_utf8(&text).expect("extraction is UTF-8");
        assert!(
            text.contains("na\u{ef}ve"),
            "WinAnsi 0xEF must decode to U+00EF, got {text:?}"
        );
    }

    /// The JSON header is the cross-SDK identity block.
    #[test]
    fn json_carries_suite_identity() {
        let json = reference_json();
        assert!(json.contains("\"suite\": \"pith\""));
        assert!(json.contains("\"crate\": \"pith-file\""));
        assert!(json.contains("\"format_version\": 1"));
        assert!(json.ends_with("}\n"));
        assert!(json.contains("\"policy\": \"exact\""));
    }

    /// Byte-stability: two builds of the corpus produce identical JSON.
    #[test]
    fn reference_json_is_deterministic() {
        assert_eq!(reference_json(), reference_json());
    }

    /// `gen` and `verify` roundtrip against a private temp copy — the
    /// same-run gen→verify property the CD artifacts rely on. The test
    /// never touches the repository-root `reference.json`, so parallel
    /// test threads cannot interleave a rewrite with the read-only
    /// committed-copy `verify` in `tests/gen_reference.rs`.
    #[test]
    fn gen_then_verify_roundtrip_on_a_private_copy() {
        let dir = std::env::temp_dir().join(format!("pith-file-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("reference.json");
        assert_eq!(run("gen", Some(&path)), ExitCode::SUCCESS);
        assert_eq!(run("verify", Some(&path)), ExitCode::SUCCESS);
        std::fs::remove_file(&path).expect("cleanup");
        std::fs::remove_dir(&dir).expect("cleanup");
    }
}
