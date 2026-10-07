//! The C ABI surface of `pith-file`: the entry points the Python
//! (ctypes), Node (koffi) and Go (cgo) SDKs bind through.
//!
//! The suite's FFI convention, defined by this module and mirrored by
//! every `pith-*` cdylib:
//!
//! * one flat set of `#[unsafe(no_mangle)] pub unsafe extern "C"`
//!   functions — raw pointers plus lengths, no structs across the
//!   boundary;
//! * every function returns a status code (see the constants below),
//!   never a `Result`, never a panic: a `panic = "abort"` cdylib must
//!   not be reachable from a foreign caller;
//! * an operation either hands ownership to the caller (and ships a
//!   matching `_free` — [`pith_file_free`] here) or writes into
//!   caller-provided out-parameters ([`pith_file_jaccard`]);
//! * the `unsafe` allowance is confined to this module; every core
//!   module stays unsafe-free behind the crate-root `#![deny]`.
//!
//! The canonical chunk-set stream [`pith_file_binary_signature`] hands
//! out is the transport the `reference.json` signature vectors are
//! defined over: the `chunk_count` big-endian, then the sorted unique
//! SHA-256 chunk digests — exactly the bytes the recorded
//! `chunk_digests_*` folds cover. Jaccard takes raw bytes (both
//! signatures are computed inside the cdylib), and text extraction
//! speaks one format wire code ([`PITH_FILE_FORMAT_PDF`], the single
//! lane the suite's file slice routes to `pith_pdf`).

#![allow(unsafe_code)]

use crate::{Format, binary_signature, text_content};

/// Status: success.
pub const PITH_OK: i32 = 0;
/// Status: a caller argument is invalid — a null pointer or an unknown
/// format wire code.
pub const PITH_E_INVALID: i32 = -1;
/// Status: the core pipeline refused the input. With the spec-pinned
/// chunking parameters the signature paths cannot refuse; the code is
/// exercised by the PDF text layer (a malformed container refuses with
/// a typed error), so a foreign caller never has to reason about a
/// panic.
pub const PITH_E_REJECTED: i32 = -2;

/// Format wire code: a PDF container ([`Format::Pdf`]) — the single
/// extraction lane [`pith_file_text_content`] exposes.
pub const PITH_FILE_FORMAT_PDF: u32 = 0;

/// Computes the binary tier-2 signature of `data` and hands out the
/// canonical chunk-set stream the `reference.json` signature vectors
/// are defined over.
///
/// The stream layout: `chunk_count` as one big-endian `u64`, then
/// `chunk_count` 32-byte SHA-256 digests in sorted (ascending) order —
/// the unique-digest set of the [`BinarySignature`](crate::BinarySignature),
/// so `sha256(concat(digests))` is the recorded `chunk_digests_sha256`
/// and the FNV-1a 64 over the same bytes is `chunk_digests_fnv1a64`.
/// The empty input yields the 8-byte stream carrying a zero count.
///
/// On success the function allocates the stream, writes its address
/// through `out`, its length through `out_len`, and returns
/// [`PITH_OK`]; the caller owns the buffer and must release it with
/// [`pith_file_free`], passing back the same pointer *and* length.
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid for
/// the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_file_binary_signature(
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match signature_stream(bytes) {
        Ok(stream) => {
            let len = stream.len();
            // Hand the exact-length buffer to the caller; `pith_file_free`
            // reconstructs the boxed slice from the same length.
            let ptr = alloc::boxed::Box::into_raw(stream.into_boxed_slice());
            unsafe {
                *out = ptr.cast::<u8>();
                *out_len = len;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Computes the exact Jaccard similarity of the binary signatures of
/// two byte strings and writes the result through `out_bits` as the
/// raw IEEE-754 bit pattern of the `f64` (the `value_bits` hex the
/// `reference.json` jaccard vectors record).
///
/// Both signatures are computed inside the cdylib: the arguments are
/// raw bytes, not serialized signatures. Two empty inputs score
/// `1.0` (`0x3ff0000000000000`) — two empty files are identical.
///
/// # Safety
///
/// `a` must point to `a_len` readable bytes, `b` to `b_len` readable
/// bytes, and `out_bits` to one writable `u64`; all must stay valid
/// for the duration of the call. The function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_file_jaccard(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out_bits: *mut u64,
) -> i32 {
    if a.is_null() || b.is_null() || out_bits.is_null() {
        return PITH_E_INVALID;
    }
    let lhs = unsafe { core::slice::from_raw_parts(a, a_len) };
    let rhs = unsafe { core::slice::from_raw_parts(b, b_len) };
    match jaccard_bits(lhs, rhs) {
        Ok(bits) => {
            unsafe { *out_bits = bits };
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Extracts the container text of `data` and hands out the extracted
/// bytes — `pith_pdf::extract_text` output for the
/// [`PITH_FILE_FORMAT_PDF`] wire code. An unknown wire code is
/// [`PITH_E_INVALID`]; a container the text layer refuses is
/// [`PITH_E_REJECTED`].
///
/// On success the function allocates the output, writes its address
/// through `out`, its length through `out_len`, and returns
/// [`PITH_OK`]; the caller owns the buffer and must release it with
/// [`pith_file_free`], passing back the same pointer *and* length.
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid for
/// the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_file_text_content(
    data: *const u8,
    len: usize,
    format: u32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    let Some(format) = wire_format(format) else {
        return PITH_E_INVALID;
    };
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match extract(bytes, format) {
        Ok(text) => {
            let len = text.len();
            let ptr = alloc::boxed::Box::into_raw(text.into_boxed_slice());
            unsafe {
                *out = ptr.cast::<u8>();
                *out_len = len;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Releases a buffer handed out by [`pith_file_binary_signature`] or
/// [`pith_file_text_content`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by one of those functions with the
/// `out_len` value that came back with it, and must not have been
/// released (or otherwise freed) before. Null is accepted and ignored,
/// so callers can free unconditionally on the error path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_file_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { alloc::boxed::Box::from_raw(slice) });
}

/// The format wire-code table: the single Pdf lane the suite's file
/// slice routes to `pith_pdf`.
fn wire_format(code: u32) -> Option<Format> {
    match code {
        PITH_FILE_FORMAT_PDF => Some(Format::Pdf),
        _ => None,
    }
}

/// The safe core of [`pith_file_binary_signature`]: sign, then
/// serialize the canonical chunk-set stream. Signature failures map to
/// [`PITH_E_REJECTED`] (unreachable with the spec-pinned parameters).
fn signature_stream(bytes: &[u8]) -> Result<alloc::vec::Vec<u8>, i32> {
    let digests = binary_signature(bytes)
        .map_err(|_| PITH_E_REJECTED)?
        .chunks();
    let mut stream = alloc::vec::Vec::with_capacity(8 + digests.len() * 32);
    stream.extend_from_slice(&(digests.len() as u64).to_be_bytes());
    for digest in &digests {
        stream.extend_from_slice(digest);
    }
    Ok(stream)
}

/// The safe core of [`pith_file_jaccard`]: both signatures, then the
/// exact similarity as its IEEE-754 bit pattern.
fn jaccard_bits(a: &[u8], b: &[u8]) -> Result<u64, i32> {
    let lhs = binary_signature(a).map_err(|_| PITH_E_REJECTED)?;
    let rhs = binary_signature(b).map_err(|_| PITH_E_REJECTED)?;
    Ok(lhs.jaccard(&rhs).to_bits())
}

/// The safe core of [`pith_file_text_content`]: extraction failures
/// map to [`PITH_E_REJECTED`].
fn extract(bytes: &[u8], format: Format) -> Result<alloc::vec::Vec<u8>, i32> {
    text_content(bytes, format)
        .map(alloc::borrow::Cow::into_owned)
        .map_err(|_| PITH_E_REJECTED)
}

#[cfg(test)]
mod tests {
    use super::{
        PITH_E_INVALID, PITH_E_REJECTED, PITH_FILE_FORMAT_PDF, PITH_OK, extract,
        pith_file_binary_signature, pith_file_free, pith_file_jaccard, pith_file_text_content,
        signature_stream, wire_format,
    };
    use pith_digest::{SplitMix64, fnv1a64, sha256};

    /// Bytes as lowercase hex.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The splitmix64 byte recipe of `tools/gen-reference`: one
    /// `next_u64` per byte, low byte kept.
    fn splitmix_bytes(seed: u64, length: usize) -> alloc::vec::Vec<u8> {
        let mut rng = SplitMix64::new(seed);
        (0..length).map(|_| rng.next_u64() as u8).collect()
    }

    /// Parses a canonical chunk-set stream into (count, digests).
    fn parse_stream(stream: &[u8]) -> (u64, alloc::vec::Vec<[u8; 32]>) {
        assert!(stream.len() >= 8);
        let count = u64::from_be_bytes(stream[..8].try_into().expect("count"));
        assert_eq!(stream.len(), 8 + count as usize * 32);
        let digests = stream[8..]
            .chunks_exact(32)
            .map(|c| c.try_into().expect("digest"))
            .collect::<alloc::vec::Vec<_>>();
        (count, digests)
    }

    /// The empty input yields the pinned 8-byte zero-count stream; the
    /// empty digest fold hashes to the empty SHA-256. Rust-derived
    /// literals the SDK conformance suites pin too, so a wrongly
    /// regenerated reference.json cannot mask drift.
    #[test]
    fn ffi_empty_signature_stream_is_the_pinned_literal() {
        let stream = signature_stream(b"").expect("empty input signs");
        assert_eq!(stream, [0u8; 8]);
        let (count, digests) = parse_stream(&stream);
        assert_eq!(count, 0);
        assert!(digests.is_empty());
        // The recorded empty-vector facts: raw input and empty fold are
        // both the empty SHA-256, the empty FNV-1a is the offset basis.
        assert_eq!(
            hex(sha256(b"").expect("empty sha256").as_bytes()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);

        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe { pith_file_binary_signature(b"".as_ptr(), 0, &mut out, &mut out_len) };
        assert_eq!(status, PITH_OK);
        assert_eq!(out_len, 8);
        let handed_back = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(handed_back, &[0u8; 8]);
        unsafe { pith_file_free(out, out_len) };
    }

    /// The FFI reproduces the committed `splitmix64-1kib-submin`
    /// vector end-to-end: raw input digest, chunk count, first digest
    /// and both folds over the digest set.
    #[test]
    fn ffi_splitmix_signature_roundtrip() {
        let input = splitmix_bytes(9, 1024);
        assert_eq!(
            hex(sha256(&input).expect("raw sha256").as_bytes()),
            "1d1197d49c7df59db2037526607a4f51614959cbb1233cb686b80f81ddfe6dca"
        );

        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            pith_file_binary_signature(input.as_ptr(), input.len(), &mut out, &mut out_len)
        };
        assert_eq!(status, PITH_OK);
        let stream = unsafe { core::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { pith_file_free(out, out_len) };

        let (count, digests) = parse_stream(&stream);
        assert_eq!(count, 1);
        assert_eq!(
            hex(&digests[0]),
            "1d1197d49c7df59db2037526607a4f51614959cbb1233cb686b80f81ddfe6dca"
        );
        let folded: alloc::vec::Vec<u8> = digests.concat();
        assert_eq!(fnv1a64(&folded), 0x6e79_6816_bf90_8255);
        assert_eq!(
            hex(sha256(&folded).expect("fold sha256").as_bytes()),
            "15ee643bbbb3b634646a652f0fcd927aa29028184520628f48ff789d2a918d51"
        );
    }

    /// Identical inputs score exactly 1.0 — including the empty pair —
    /// and disjoint inputs score exactly 0.0, at the IEEE-754 bit
    /// level.
    #[test]
    fn ffi_jaccard_identical_inputs_are_pinned_bits() {
        let base = splitmix_bytes(0xD15E_5EED, 48 * 1024);
        let unrelated = splitmix_bytes(0xBADC_0FFE, 48 * 1024);
        let mut bits: u64 = 0;
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

        let status = unsafe {
            pith_file_jaccard(
                base.as_ptr(),
                base.len(),
                unrelated.as_ptr(),
                unrelated.len(),
                &mut bits,
            )
        };
        assert_eq!(status, PITH_OK);
        assert_eq!(bits, 0x0000_0000_0000_0000);
    }

    /// The committed PDF fixture extracts through the FFI to the
    /// pinned 9-byte text.
    #[test]
    fn ffi_text_extraction_roundtrip() {
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
        let text = unsafe { core::slice::from_raw_parts(out, out_len) };
        assert_eq!(
            hex(sha256(text).expect("text sha256").as_bytes()),
            "6d0c6c3113b6765a4eedb63f451cc5b4b8554159a78a3782f6cceef631046ee4"
        );
        unsafe { pith_file_free(out, out_len) };
    }

    /// Refusals: a malformed (and an empty) PDF container reject with
    /// [`PITH_E_REJECTED`], never a crash; unknown wire codes and null
    /// pointers reject with [`PITH_E_INVALID`]; freeing a null pointer
    /// is a no-op.
    #[test]
    fn ffi_refusals() {
        let gutted = b"%PDF-1.7\nbody";
        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len: usize = 0;
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
            pith_file_text_content(
                b"".as_ptr(),
                0,
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

        let data = [0u8; 4];
        let null_data = unsafe {
            pith_file_text_content(
                core::ptr::null(),
                0,
                PITH_FILE_FORMAT_PDF,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(null_data, PITH_E_INVALID);
        let null_out = unsafe {
            pith_file_text_content(
                data.as_ptr(),
                data.len(),
                PITH_FILE_FORMAT_PDF,
                core::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(null_out, PITH_E_INVALID);

        let mut bits: u64 = 0;
        let null_a =
            unsafe { pith_file_jaccard(core::ptr::null(), 0, data.as_ptr(), 4, &mut bits) };
        assert_eq!(null_a, PITH_E_INVALID);
        let null_b =
            unsafe { pith_file_jaccard(data.as_ptr(), 4, core::ptr::null(), 0, &mut bits) };
        assert_eq!(null_b, PITH_E_INVALID);
        let null_bits =
            unsafe { pith_file_jaccard(data.as_ptr(), 4, data.as_ptr(), 4, core::ptr::null_mut()) };
        assert_eq!(null_bits, PITH_E_INVALID);

        let null_sig_data =
            unsafe { pith_file_binary_signature(core::ptr::null(), 0, &mut out, &mut out_len) };
        assert_eq!(null_sig_data, PITH_E_INVALID);
        let null_sig_out = unsafe {
            pith_file_binary_signature(
                data.as_ptr(),
                data.len(),
                core::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(null_sig_out, PITH_E_INVALID);
        let null_sig_len = unsafe {
            pith_file_binary_signature(data.as_ptr(), data.len(), &mut out, core::ptr::null_mut())
        };
        assert_eq!(null_sig_len, PITH_E_INVALID);

        unsafe { pith_file_free(core::ptr::null_mut(), 0) };

        assert!(wire_format(PITH_FILE_FORMAT_PDF).is_some());
        assert!(wire_format(1).is_none());
        assert_eq!(extract(gutted, crate::Format::Pdf), Err(PITH_E_REJECTED));
        assert_eq!(
            signature_stream(&splitmix_bytes(9, 1024))
                .expect("stream")
                .len(),
            8 + 32
        );
    }
}
