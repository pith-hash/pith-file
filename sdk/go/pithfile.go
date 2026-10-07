// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithfile provides Go bindings for the pith-file Rust cdylib:
// FastCDC chunk signatures, exact chunk-set Jaccard and PDF text
// extraction.
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The vectors in reference.json at the repository root are the
// hex-exact cross-language source of truth; the conformance tests
// replay all of them through this binding.
package pithfile

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer or
	// an unknown format wire code).
	StatusInvalid int32 = -1
	// StatusRejected: the core pipeline refused the input (a container
	// the PDF text layer rejects).
	StatusRejected int32 = -2
)

// FormatPDF is the format wire code for a PDF container — the single
// extraction lane the cdylib exposes.
const FormatPDF uint32 = 0

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_file.dll", "libpith_file.so", "libpith_file.dylib"}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "input rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithfile: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithfile: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// scratchByte backs pointers for zero-length inputs: the cdylib
// refuses NULL data even at len 0 (the suite's C ABI keeps the -1
// contract for null pointers), while zero-length input is a legal
// value — the reference corpus signs the empty stream.
var scratchByte byte

// bytePtr returns a non-nil data pointer for b.
func bytePtr(b []byte) *byte {
	if len(b) > 0 {
		return &b[0]
	}
	return &scratchByte
}

// Signature is the binary tier-2 signature, re-expressed from the
// canonical chunk-set stream: the sorted unique SHA-256 chunk digests
// — exactly the bytes the chunk_digests_sha256 / chunk_digests_fnv1a64
// reference folds cover.
type Signature struct {
	// ChunkCount is the number of distinct chunks.
	ChunkCount uint64
	// Digests are the sorted unique 32-byte chunk digests.
	Digests [][32]byte
}

// ParseSignature re-expresses the canonical chunk-set stream as a
// Signature.
func ParseSignature(raw []byte) (Signature, error) {
	if len(raw) < 8 {
		return Signature{}, fmt.Errorf("pithfile: canonical stream is shorter than the 8-byte count")
	}
	count := binary.BigEndian.Uint64(raw[:8])
	digests := raw[8:]
	if uint64(len(digests)) != count*32 {
		return Signature{}, fmt.Errorf(
			"pithfile: canonical stream carries %d digest bytes for a count of %d",
			len(digests), count,
		)
	}
	sig := Signature{ChunkCount: count, Digests: make([][32]byte, count)}
	for i := range sig.Digests {
		copy(sig.Digests[i][:], digests[i*32:(i+1)*32])
	}
	return sig, nil
}

// BinarySignature signs data into the canonical chunk-set stream the
// reference.json signature vectors are defined over: ChunkCount
// big-endian, then the sorted unique SHA-256 chunk digests. The
// returned slice is a Go copy; the handed-out cdylib buffer is
// released before returning.
func BinarySignature(data []byte) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	var out *byte
	var outLen uintptr
	status, err := ffiBinarySignature(libPath, bytePtr(data), len(data), &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_file_binary_signature", Status: status}
	}
	buf := make([]byte, outLen)
	copy(buf, unsafe.Slice(out, outLen))
	ffiFree(libPath, out, outLen)
	return buf, nil
}

// JaccardBits computes the exact Jaccard similarity of the binary
// signatures of two byte strings. Both signatures are computed inside
// the cdylib: the arguments are raw bytes, not serialized signatures.
// The result is the raw IEEE-754 bit pattern of the similarity — the
// value_bits hex the reference jaccard vectors record (render with
// fmt.Sprintf("%016x", bits)). Two empty inputs score exactly
// 0x3ff0000000000000 (1.0).
func JaccardBits(a, b []byte) (uint64, error) {
	libPath, err := locate()
	if err != nil {
		return 0, err
	}
	var bits uint64
	status, err := ffiJaccard(libPath, bytePtr(a), len(a), bytePtr(b), len(b), &bits)
	if err != nil {
		return 0, err
	}
	if status != StatusOK {
		return 0, &FfiError{Op: "pith_file_jaccard", Status: status}
	}
	return bits, nil
}

// TextContent extracts the container text of data. format is one of
// the format wire codes (FormatPDF); an unknown code yields an
// *FfiError with StatusInvalid and a refused container with
// StatusRejected. The returned slice is a Go copy; the handed-out
// cdylib buffer is released before returning.
func TextContent(data []byte, format uint32) ([]byte, error) {
	libPath, err := locate()
	if err != nil {
		return nil, err
	}
	var out *byte
	var outLen uintptr
	status, err := ffiTextContent(libPath, bytePtr(data), len(data), format, &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_file_text_content", Status: status}
	}
	buf := make([]byte, outLen)
	copy(buf, unsafe.Slice(out, outLen))
	ffiFree(libPath, out, outLen)
	return buf, nil
}
