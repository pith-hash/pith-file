//! Tier-2 binary signature conformance, ported from the upstream
//! monorepo facade suite (`modhash/tests/facade.rs`,
//! `binary_duplicate_and_near_duplicate`). The corpus recipes and every
//! assertion on the file-domain symbols are preserved verbatim; the
//! lines that exercised the cross-modal facade (`content_hash`,
//! `signature`, `match_`, `detect`) are that crate's surface and are
//! covered by the curator lane.

use pith_digest::SplitMix64;
use pith_file::binary_signature;

/// Duplicate-file detection: same content under different names is the
/// same chunk set; a one-byte-prefixed variant keeps high chunk-set
/// Jaccard.
#[test]
fn binary_duplicate_and_near_duplicate() {
    // Deterministic 48 KiB pseudo-file (SplitMix64 bytes).
    let mut rng = SplitMix64::new(0xD15E_5EED);
    let file: Vec<u8> = (0..48 * 1024).map(|_| rng.next_u64() as u8).collect();

    let sig_a = binary_signature(&file).unwrap();
    let sig_b = binary_signature(&file).unwrap();
    assert_eq!(sig_a, sig_b, "same bytes must chunk identically");
    assert_eq!(sig_a.jaccard(&sig_b), 1.0);
    assert!(sig_a.len() > 1, "48 KiB must produce several chunks");
    // The one-byte-prefixed variant: content-defined chunking realigns
    // after the insert, so most chunk digests survive.
    let mut shifted = vec![0xAA];
    shifted.extend_from_slice(&file);
    let sig_c = binary_signature(&shifted).unwrap();
    let j = sig_a.jaccard(&sig_c);
    assert!(
        j > 0.5,
        "prefix-insert variant must keep high Jaccard, got {j}"
    );

    // Completely different bytes score low.
    let mut rng2 = SplitMix64::new(0xBADC_0FFE);
    let other: Vec<u8> = (0..48 * 1024).map(|_| rng2.next_u64() as u8).collect();
    let j2 = binary_signature(&file)
        .unwrap()
        .jaccard(&binary_signature(&other).unwrap());
    assert!(j2 < 0.1, "unrelated files must score low, got {j2}");

    // Two empty files are identical (Jaccard 1.0).
    assert_eq!(binary_signature(b"").unwrap().len(), 0);
    assert_eq!(
        binary_signature(b"")
            .unwrap()
            .jaccard(&binary_signature(b"").unwrap()),
        1.0
    );
}

/// The digest set is exactly the composition contract: `FastCdc` chunk
/// boundaries hashed per chunk with SHA-256 — recomputing both sides
/// independently through `pith-cdc` + `pith-digest` must agree.
#[test]
fn chunk_digests_match_the_cdc_composition() {
    let mut rng = SplitMix64::new(0x0123_4567_89AB_CDEF);
    let data: Vec<u8> = (0..32 * 1024).map(|_| rng.next_u64() as u8).collect();

    let sig = binary_signature(&data).unwrap();
    let mut expected = std::collections::BTreeSet::new();
    for c in pith_cdc::FastCdc::new(&data, 2048, 8192, 32768).unwrap() {
        let d = pith_digest::sha256(&data[c.offset..c.offset + c.length]).unwrap();
        expected.insert(*d.as_bytes());
    }
    assert_eq!(sig.chunks(), expected.into_iter().collect::<Vec<_>>());
    assert_eq!(sig.len(), sig.chunks().len());
    assert!(!sig.is_empty());
}

/// Repeated identical chunks count once: a constant fill collapses to a
/// single unique digest even though the chunker emits many boundaries.
#[test]
fn repeated_chunks_deduplicate_to_one_digest() {
    let data = vec![0u8; 256 * 1024];
    let boundaries = pith_cdc::FastCdc::new(&data, 2048, 8192, 32768)
        .unwrap()
        .count();
    assert!(boundaries > 1, "256 KiB of zeros must chunk repeatedly");

    let sig = binary_signature(&data).unwrap();
    assert_eq!(sig.len(), 1, "identical chunks must count once");
    assert_eq!(sig.chunks().len(), 1);
    let whole = *pith_digest::sha256(&data).unwrap().as_bytes();
    // The deduplicated digest is one of the per-chunk digests; for a
    // constant fill every chunk digest is the digest of 2048..=32768
    // zero bytes, never of the whole file.
    assert_ne!(sig.chunks()[0], whole);
}

/// Default is the empty signature; symmetry and reflexivity hold.
#[test]
fn signature_edges_and_symmetry() {
    let sig = pith_file::BinarySignature::default();
    assert!(sig.is_empty());
    assert_eq!(sig.len(), 0);
    assert!(sig.chunks().is_empty());

    let mut rng = SplitMix64::new(7);
    let data: Vec<u8> = (0..16 * 1024).map(|_| rng.next_u64() as u8).collect();
    let a = binary_signature(&data).unwrap();
    let empty = pith_file::BinarySignature::default();
    assert_eq!(a.jaccard(&a), 1.0);
    assert_eq!(a.jaccard(&empty), 0.0);
    assert_eq!(empty.jaccard(&a), 0.0, "Jaccard is symmetric");
    assert_eq!(a.clone(), a);
}
