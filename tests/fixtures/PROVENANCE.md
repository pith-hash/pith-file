# `tests/fixtures/` provenance

Every file in this directory is an inherited byte copy, not generated
here. `reference.json` at the repository root pins the extraction output
this suite tests against; `gen-reference verify` is the byte gate.

| file | origin |
|---|---|
| `text_page.pdf` | `n24q02m/modhash` @ `89ed581f`, `modhash/tests/fixtures/text_page.pdf` (sha256 `81357e9f4320adeed446075dc57fa0690a4d1aa6c4296f91c29da077170b061d`, 670 bytes, verified at port time). Upstream provenance (`lab/smoke-fixtures/PROVENANCE.md`): byte copy of the pdf lane's `standard_default.pdf`; extraction output is byte-equal to `pypdf`, with the unmapped-byte case decoding through **WinAnsiEncoding** (`0xEF` → `ï`). |

The generator is not re-shipped here; the files above are the committed
truth this suite tests against.
