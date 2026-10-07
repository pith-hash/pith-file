//! The file-domain error type: every fallible call in this crate
//! returns it.
//!
//! Two shapes cover the crate: chunker and SHA-256 rejections arrive as
//! [`pith_digest::Error`] and are wrapped in [`Error::Decode`];
//! `pith_pdf` carries its own page/object-attributed error that cannot
//! fold into the fleet error type, wrapped as [`Error::Pdf`].
//! `Display` for both spells the pipeline name first, so an error read
//! from a log always says *which* pipeline refused (`binary:` for the
//! chunking path, `text:` for extraction).

use core::fmt;

/// Every failure the crate can report.
///
/// `Copy` is impossible: [`Error::Pdf`] holds the attributed PDF error.
/// The type still avoids allocating on the hot paths — chunker
/// rejections move a `Copy` inner error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The chunker rejected the input. `source` is the chunker's own
    /// typed error. Unreachable in practice: the chunking parameters
    /// are fixed, spec-pinned constants.
    Decode {
        /// The chunker's own typed error.
        source: pith_digest::Error,
    },
    /// The PDF text layer's own error type (carries page/object
    /// attribution and cannot fold into [`pith_digest::Error`]).
    Pdf(pith_pdf::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode { source } => {
                f.write_str("binary: ")?;
                fmt::Display::fmt(source, f)
            }
            Error::Pdf(e) => {
                f.write_str("text: ")?;
                fmt::Display::fmt(e, f)
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<pith_pdf::Error> for Error {
    fn from(e: pith_pdf::Error) -> Self {
        Error::Pdf(e)
    }
}
