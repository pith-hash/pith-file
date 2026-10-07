//! File-domain hashing for the pith suite: content-defined chunk
//! signatures, exact chunk-set Jaccard and container text extraction.
//!
//! Part of the `pith` zero-dependency hashing suite: every suite crate
//! depends only on other `pith-*` crates, so the whole suite resolves
//! without a single registry package.
//!
//! This crate is the suite's file slice: it wires the file-domain
//! pieces of the facade design (upstream `docs/algorithms/kit.md`,
//! spec §5) behind one surface:
//!
//! - [`binary_signature`] is the **binary tier 2**: FastCDC chunks the
//!   bytes and SHA-256 hashes every chunk into a unique-digest set;
//! - [`BinarySignature`] compares two such sets with exact Jaccard
//!   similarity;
//! - [`text_content`] is the byte source a text pipeline hashes over:
//!   PDF containers go through `pith_pdf::extract_text`, every other
//!   format passes the raw bytes through unchanged.
//!
//! The tier-1 content hash and the cross-modal facade that routes a
//! sniffed container into this slice live in the suite's curator crate.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod error;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

pub use error::Error;
pub use pith_digest::Format;

/// Facade result alias.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// The FastCDC parameters the binary tier-2 signature is defined over
/// (spec §5): min 2 KiB, average 8 KiB, max 32 KiB, default
/// normalization.
const CDC_MIN: usize = 2048;
/// See [`CDC_MIN`].
const CDC_AVG: usize = 8192;
/// See [`CDC_MIN`].
const CDC_MAX: usize = 32768;

// ---------------------------------------------------------------------
// Tier 2 signatures
// ---------------------------------------------------------------------

/// The binary tier-2 signature: the set of SHA-256 digests of the
/// content-defined chunks (spec §5). A `BTreeSet` — **unique digests
/// only**; repeated chunks count once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BinarySignature {
    chunks: BTreeSet<[u8; 32]>,
}

impl BinarySignature {
    /// The sorted unique chunk digests.
    #[must_use]
    pub fn chunks(&self) -> Vec<[u8; 32]> {
        self.chunks.iter().copied().collect()
    }

    /// The number of distinct chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the signature carries no chunks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Exact Jaccard similarity against `other`: `|A∩B| / |A∪B|`, with
    /// two empty sets scoring `1.0` (two empty files are identical).
    #[must_use]
    pub fn jaccard(&self, other: &BinarySignature) -> f64 {
        if self.chunks.is_empty() && other.chunks.is_empty() {
            return 1.0;
        }
        let inter = self.chunks.intersection(&other.chunks).count();
        let union = self.chunks.union(&other.chunks).count();
        if union == 0 {
            return 1.0;
        }
        inter as f64 / union as f64
    }
}

/// The binary tier-2 signature: FastCDC chunks hashed with SHA-256
/// into a unique-digest set.
///
/// # Errors
///
/// [`Error::Decode`] if the chunker rejects the (fixed, spec-pinned)
/// parameters — unreachable in practice.
pub fn binary_signature(bytes: &[u8]) -> Result<BinarySignature> {
    let err = |e: pith_digest::Error| Error::Decode { source: e };
    let cdc = pith_cdc::FastCdc::new(bytes, CDC_MIN, CDC_AVG, CDC_MAX).map_err(err)?;
    let mut chunks = BTreeSet::new();
    for c in cdc {
        let d = pith_digest::sha256(&bytes[c.offset..c.offset + c.length]).map_err(err)?;
        chunks.insert(*d.as_bytes());
    }
    Ok(BinarySignature { chunks })
}

// ---------------------------------------------------------------------
// Container text extraction
// ---------------------------------------------------------------------

/// The text a modality pipelines over: the raw UTF-8 bytes for bare
/// text, `pith_pdf::extract_text` output for a PDF container.
///
/// `alloc::borrow::Cow` keeps the bare-text path allocation-free while
/// letting pdf hand back an owned `String`.
///
/// # Errors
///
/// [`Error::Pdf`] when the PDF text layer refuses the container.
pub fn text_content(bytes: &[u8], format: Format) -> Result<alloc::borrow::Cow<'_, [u8]>> {
    match format {
        Format::Pdf => pith_pdf::extract_text(bytes)
            .map_err(Error::Pdf)
            .map(|s| alloc::borrow::Cow::Owned(s.into_bytes())),
        _ => Ok(alloc::borrow::Cow::Borrowed(bytes)),
    }
}
