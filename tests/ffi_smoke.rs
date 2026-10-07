//! The C ABI surface exercised from a consumer-crate context: the
//! integration-test binaries link the rlib exactly the way the
//! language SDKs link the cdylib's exported symbols, so the raw
//! `extern "C"` entry points run outside the unit-test compilation
//! unit as well.
//!
//! The vector facts replayed here are the committed reference values
//! (see `tools/gen-reference`); the SDK conformance suites under
//! `sdk/` replay the same numbers through ctypes, koffi and cgo.

use pith_digest::{SplitMix64, fnv1a64, sha256};
use pith_file::ffi::{
    PITH_E_INVALID, PITH_E_REJECTED, PITH_FILE_FORMAT_PDF, PITH_OK, pith_file_binary_signature,
    pith_file_free, pith_file_jaccard, pith_file_text_content,
};

/// Bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The splitmix64 byte recipe of `tools/gen-reference`: one `next_u64`
/// per byte, low byte kept.
fn splitmix_bytes(seed: u64, length: usize) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..length).map(|_| rng.next_u64() as u8).collect()
}

/// The committed `splitmix64-48kib` vector, end-to-end through the raw
/// entry points: status OK, stream layout, and both folds over the
/// digest set.
#[test]
fn consumer_ffi_signature_stream_reproduces_the_committed_vector() {
    let input = splitmix_bytes(0xD15E_5EED, 48 * 1024);
    assert_eq!(
        hex(sha256(&input).expect("raw sha256").as_bytes()),
        "00553543ee7a066c320e955d03ee87d81bcfcb2a082df28b640a2331deabe744"
    );

    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let status =
        unsafe { pith_file_binary_signature(input.as_ptr(), input.len(), &mut out, &mut out_len) };
    assert_eq!(status, PITH_OK);
    let stream = unsafe { core::slice::from_raw_parts(out, out_len) }.to_vec();
    unsafe { pith_file_free(out, out_len) };

    assert!(stream.len() >= 8);
    let count = u64::from_be_bytes(stream[..8].try_into().expect("count"));
    assert_eq!(count, 5);
    assert_eq!(stream.len(), 8 + count as usize * 32);
    assert_eq!(
        hex(&stream[8..40]),
        "7e1d45594ea38b3b0e62022d68cdc011425d3c0388396da22c221bddc5053e8c"
    );
    let digests = &stream[8..];
    assert_eq!(fnv1a64(digests), 0x94f6_9a23_63d2_a0bd);
    assert_eq!(
        hex(sha256(digests).expect("fold sha256").as_bytes()),
        "e9fcd4223e6580c8362c849ee3c28982f049478471c6058d3907057189936ad5"
    );
}

/// The committed jaccard facts through the raw entry point: identical
/// inputs at exactly 1.0, the near-duplicate pair at the recorded
/// bits, both empty inputs at exactly 1.0.
#[test]
fn consumer_ffi_jaccard_reproduces_the_committed_bits() {
    let base = splitmix_bytes(0xD15E_5EED, 48 * 1024);
    let shifted = {
        let mut out = vec![0xAAu8];
        let mut rng = SplitMix64::new(0xD15E_5EED);
        for _ in 0..48 * 1024 {
            out.push(rng.next_u64() as u8);
        }
        out
    };
    let mut bits: u64 = 0;

    let status = unsafe {
        pith_file_jaccard(
            base.as_ptr(),
            base.len(),
            shifted.as_ptr(),
            shifted.len(),
            &mut bits,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(bits, 0x3fe5_5555_5555_5555);

    let status = unsafe {
        pith_file_jaccard(
            base.as_ptr(),
            base.len(),
            base.as_ptr(),
            base.len(),
            &mut bits,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(bits, 0x3ff0_0000_0000_0000);

    let status = unsafe { pith_file_jaccard(b"".as_ptr(), 0, b"".as_ptr(), 0, &mut bits) };
    assert_eq!(status, PITH_OK);
    assert_eq!(bits, 0x3ff0_0000_0000_0000);
}

/// The committed text-extraction vector and the exact refusals,
/// through the raw entry points.
#[test]
fn consumer_ffi_text_content_extracts_and_refuses() {
    let pdf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/text_page.pdf"
    ))
    .expect("fixture");
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = unsafe {
        pith_file_text_content(
            pdf.as_ptr(),
            pdf.len(),
            PITH_FILE_FORMAT_PDF,
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(out_len, 9);
    let text = unsafe { core::slice::from_raw_parts(out, out_len) }.to_vec();
    unsafe { pith_file_free(out, out_len) };
    assert_eq!(
        hex(sha256(&text).expect("text sha256").as_bytes()),
        "6d0c6c3113b6765a4eedb63f451cc5b4b8554159a78a3782f6cceef631046ee4"
    );

    let gutted = b"%PDF-1.7\nbody";
    let status = unsafe {
        pith_file_text_content(
            gutted.as_ptr(),
            gutted.len(),
            PITH_FILE_FORMAT_PDF,
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);

    let status = unsafe {
        pith_file_text_content(gutted.as_ptr(), gutted.len(), 99, &mut out, &mut out_len)
    };
    assert_eq!(status, PITH_E_INVALID);
}
