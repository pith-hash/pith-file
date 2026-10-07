//! Container text extraction conformance: the PDF lane through the
//! committed fixture (pinned by the same digest `pith-pdf`'s own
//! reference vectors carry for this document), the pass-through lanes,
//! and the exact refusal shapes for malformed containers.

use std::fs;

use pith_digest::{Format, sha256};
use pith_file::{Error, text_content};

/// Byte-identity pin for the committed fixture, matching
/// `tests/fixtures/PROVENANCE.md` and the `input_sha256` field of
/// `reference.json`. A checkout or copy that alters one byte of the
/// corpus — a CRLF rewrite included — turns this red.
const FIXTURE_SHA256: &str = "81357e9f4320adeed446075dc57fa0690a4d1aa6c4296f91c29da077170b061d";

/// Extraction pins for the fixture, matching the `text-fixture-text_page`
/// vector of `reference.json` (and byte-equal to the `standard_default`
/// extraction `pith-pdf` pins for the same document: the fixture is that
/// crate's corpus document, copied byte-exact).
const TEXT_BYTES: usize = 9;
const TEXT_SHA256: &str = "6d0c6c3113b6765a4eedb63f451cc5b4b8554159a78a3782f6cceef631046ee4";

#[test]
fn pdf_fixture_extracts_pinned_bytes() {
    let pdf = fs::read("tests/fixtures/text_page.pdf").expect("fixture");
    let got = hex(sha256(&pdf).expect("sha256").as_bytes());
    assert_eq!(got, FIXTURE_SHA256, "fixture bytes must match provenance");

    let text = text_content(&pdf, Format::Pdf).expect("committed fixture must extract");
    // PDF extraction hands back owned bytes.
    assert!(matches!(text, std::borrow::Cow::Owned(_)));
    let text = core::str::from_utf8(&text).expect("extraction is UTF-8");
    // WinAnsiEncoding fallback: 0xEF decodes to U+00EF (upstream oracle
    // property, byte-equal to pypdf).
    assert!(text.contains("na\u{ef}ve"), "got {text:?}");
    assert_eq!(text.len(), TEXT_BYTES);
    assert_eq!(
        hex(sha256(text.as_bytes()).unwrap().as_bytes()),
        TEXT_SHA256
    );
}

#[test]
fn non_pdf_formats_pass_bytes_through_borrowed() {
    let bytes = b"plain opaque bytes \xff\xfe";
    for format in [Format::Zip, Format::Unknown, Format::Png] {
        let out = text_content(bytes, format).expect("pass-through cannot fail");
        assert!(
            matches!(out, std::borrow::Cow::Borrowed(_)),
            "{format:?} must borrow, not copy"
        );
        assert_eq!(&*out, &bytes[..]);
    }
}

/// Ported refusal shape from the upstream facade suite
/// (`landed_slots_report_decode_errors_not_pending`): a recognized but
/// gutted PDF container is an `Error::Pdf` refusal, never a guess.
#[test]
fn gutted_pdf_refuses_as_pdf_error() {
    let pdf = b"%PDF-1.7\nbody".to_vec();
    match text_content(&pdf, Format::Pdf) {
        Err(Error::Pdf(_)) => {}
        other => panic!("corrupt pdf must be Error::Pdf, got {other:?}"),
    }
    // The Display prefix names the text pipeline, byte-identical to the
    // upstream facade's wording.
    let msg = text_content(&pdf, Format::Pdf).unwrap_err().to_string();
    assert_eq!(msg, "text: bad value: no objects found while scanning");
}

#[test]
fn empty_pdf_refuses_with_header_truncation() {
    let msg = text_content(b"", Format::Pdf).unwrap_err().to_string();
    assert_eq!(msg, "text: truncated: PDF header");
}

#[test]
fn pdf_error_converts_through_from() {
    let err: Error = match pith_pdf::Document::open(b"not a pdf") {
        Err(e) => e.into(),
        Ok(_) => panic!("not a pdf must refuse"),
    };
    assert!(matches!(err, Error::Pdf(_)));
    assert!(
        err.to_string().starts_with("text: "),
        "Display must name the pipeline first, got {err}"
    );
}

/// The chunker path cannot refuse at runtime (spec-pinned parameters),
/// so its Display wording is pinned directly on a constructed value:
/// byte-identical to the upstream facade's `binary:` prefix.
#[test]
fn decode_display_names_the_binary_pipeline() {
    let err = Error::Decode {
        source: pith_digest::Error::BadValue("chunker parameters"),
    };
    assert_eq!(err.to_string(), "binary: bad value: chunker parameters");
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
