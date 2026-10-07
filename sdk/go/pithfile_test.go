// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The input synthesis recipes of tools/gen-reference/main.rs,
// transcribed: splitmix64 (one next_u64 per byte, low byte kept),
// prefix-insert (one 0xAA byte in front of the seed stream) and zeros.

const (
	gamma = 0x9E3779B97F4A7C15
	m1    = 0xBF58476D1CE4E5B9
	m2    = 0x94D049BB133111EB
)

type splitMix64 struct{ state uint64 }

func (s *splitMix64) nextU64() uint64 {
	s.state += gamma
	z := s.state
	z = (z ^ (z >> 30)) * m1
	z = (z ^ (z >> 27)) * m2
	return z ^ (z >> 31)
}

func buildInput(kind string, seed uint64, length int) ([]byte, error) {
	switch kind {
	case "splitmix64":
		rng := splitMix64{state: seed}
		out := make([]byte, length)
		for i := range out {
			out[i] = byte(rng.nextU64())
		}
		return out, nil
	case "prefix-insert":
		rng := splitMix64{state: seed}
		out := make([]byte, length+1)
		out[0] = 0xAA
		for i := 1; i < len(out); i++ {
			out[i] = byte(rng.nextU64())
		}
		return out, nil
	case "zeros":
		return make([]byte, length), nil
	}
	return nil, fmt.Errorf("unknown corpus kind %q", kind)
}

// fnv1a64: offset basis 0xcbf29ce484222325, prime 0x100000001b3.
func fnv1a64(data []byte) uint64 {
	h := uint64(0xCBF29CE484222325)
	for _, b := range data {
		h = (h ^ uint64(b)) * 0x100000001B3
	}
	return h
}

type referenceFile struct {
	Vectors []map[string]any `json:"vectors"`
}

var (
	repoRoot  = filepath.Join("..", "..")
	reference = func() referenceFile {
		raw, err := os.ReadFile(filepath.Join(repoRoot, "reference.json"))
		if err != nil {
			panic(err)
		}
		var f referenceFile
		if err := json.Unmarshal(raw, &f); err != nil {
			panic(err)
		}
		return f
	}()

	vectors = func() map[string]map[string]any {
		m := make(map[string]map[string]any, len(reference.Vectors))
		for _, v := range reference.Vectors {
			m[v["name"].(string)] = v
		}
		return m
	}()

	// inputs synthesizes every signature-vector input once (the
	// jaccard vectors reference them by name).
	inputs = func() map[string][]byte {
		m := make(map[string][]byte)
		for _, v := range reference.Vectors {
			if _, ok := v["raw_sha256"]; !ok {
				continue
			}
			input := v["input"].(map[string]any)
			seed, err := strconvParseUint64(input["seed_hex"].(string))
			if err != nil {
				panic(err)
			}
			length := int(input["length"].(float64))
			data, err := buildInput(input["kind"].(string), seed, length)
			if err != nil {
				panic(err)
			}
			m[v["name"].(string)] = data
		}
		return m
	}()
)

func strconvParseUint64(s string) (uint64, error) {
	var v uint64
	for _, c := range []byte(s) {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad hex digit %q", c)
		}
		v = v<<4 | d
	}
	return v, nil
}

func TestCdylibIsDiscoverable(t *testing.T) {
	p, err := FindCdylib()
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		t.Fatalf("located cdylib is not a regular file: %s", p)
	}
}

func TestSignatureVectorsAreReproducedHexExact(t *testing.T) {
	for _, raw := range reference.Vectors {
		vector := raw
		name, _ := vector["name"].(string)
		if _, ok := vector["raw_sha256"]; !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data := inputs[name]

			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != vector["raw_sha256"] {
				t.Fatalf("raw input sha256 mismatch: got %s", got)
			}

			stream, err := BinarySignature(data)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := ParseSignature(stream)
			if err != nil {
				t.Fatal(err)
			}
			if want := uint64(vector["chunk_digest_count"].(float64)); sig.ChunkCount != want {
				t.Fatalf("chunk count: got %d want %d", sig.ChunkCount, want)
			}
			if want, _ := vector["chunk_digests_first"].(string); want != "" {
				if got := hex.EncodeToString(sig.Digests[0][:]); got != want {
					t.Fatalf("first digest: got %s want %s", got, want)
				}
			}

			folded := make([]byte, 0, int(sig.ChunkCount)*32)
			for _, d := range sig.Digests {
				folded = append(folded, d[:]...)
			}
			if got := fmt.Sprintf("%016x", fnv1a64(folded)); got != vector["chunk_digests_fnv1a64"] {
				t.Fatalf("fnv1a64 fold: got %s want %s", got, vector["chunk_digests_fnv1a64"])
			}
			sum = sha256.Sum256(folded)
			if got := hex.EncodeToString(sum[:]); got != vector["chunk_digests_sha256"] {
				t.Fatalf("sha256 fold: got %s want %s", got, vector["chunk_digests_sha256"])
			}
		})
	}
}

func TestJaccardVectorsAreBitExact(t *testing.T) {
	for _, raw := range reference.Vectors {
		vector := raw
		name, _ := vector["name"].(string)
		want, ok := vector["value_bits"]
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			a := inputs[vector["a"].(string)]
			b := inputs[vector["b"].(string)]
			bits, err := JaccardBits(a, b)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%016x", bits); got != want.(string) {
				t.Fatalf("jaccard bits: got %s want %s", got, want.(string))
			}
		})
	}
}

func TestTextFixtureVectorIsReproducedHexExact(t *testing.T) {
	vector := vectors["text-fixture-text_page"]
	pdf, err := os.ReadFile(filepath.Join(repoRoot, vector["input_path"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pdf)
	if got := hex.EncodeToString(sum[:]); got != vector["input_sha256"] {
		t.Fatalf("fixture sha256 mismatch: got %s", got)
	}

	extracted, err := TextContent(pdf, FormatPDF)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != int(vector["text_bytes"].(float64)) {
		t.Fatalf("text length: got %d want %v", len(extracted), vector["text_bytes"])
	}
	sum = sha256.Sum256(extracted)
	if got := hex.EncodeToString(sum[:]); got != vector["text_sha256"] {
		t.Fatalf("text sha256: got %s want %s", got, vector["text_sha256"])
	}
}

func TestErrorVectorsRefuseWithStatus(t *testing.T) {
	for _, raw := range reference.Vectors {
		vector := raw
		name, _ := vector["name"].(string)
		if _, ok := vector["error_kind"]; !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(vector["input_hex"].(string))
			if err != nil {
				t.Fatal(err)
			}
			_, err = TextContent(data, FormatPDF)
			var ffiErr *FfiError
			if err == nil || !errorsAs(err, &ffiErr) || ffiErr.Status != StatusRejected {
				t.Fatalf("want FfiError status -2, got %v", err)
			}
		})
	}
}

func errorsAs(err error, target **FfiError) bool {
	for err != nil {
		if e, ok := err.(*FfiError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestEmptyStreamMatchesTheRustPinnedLiterals(t *testing.T) {
	// The 'empty' vector's chunk stream, pinned in the committed
	// reference.json and re-derived by the Rust unit tests: the empty
	// input signs to exactly the 8-byte zero count, the empty digest
	// fold hashes to the empty SHA-256 and the empty FNV-1a input is
	// the offset basis. This test fails loudly even if reference.json
	// were regenerated wrongly.
	stream, err := BinarySignature(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream, make([]byte, 8)) {
		t.Fatalf("empty stream: got %x", stream)
	}
	if got := fmt.Sprintf("%016x", fnv1a64(nil)); got != "cbf29ce484222325" {
		t.Fatalf("empty fnv1a64: got %s", got)
	}
	sum := sha256.Sum256(nil)
	if got := hex.EncodeToString(sum[:]); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty sha256: got %s", got)
	}
}

func TestUnknownFormatCodeIsRefusedNotCrashing(t *testing.T) {
	_, err := TextContent([]byte("%PDF-1.7\nbody"), 99)
	var ffiErr *FfiError
	if err == nil || !errorsAs(err, &ffiErr) || ffiErr.Status != StatusInvalid {
		t.Fatalf("want FfiError status -1, got %v", err)
	}
}

func TestMalformedPdfIsRefusedNotCrashing(t *testing.T) {
	_, err := TextContent([]byte("%PDF-1.7\nbody"), FormatPDF)
	var ffiErr *FfiError
	if err == nil || !errorsAs(err, &ffiErr) || ffiErr.Status != StatusRejected {
		t.Fatalf("want FfiError status -2, got %v", err)
	}
}

func TestJaccardIdenticalEmptyInputsScoreOneDotZero(t *testing.T) {
	// The empty-empty jaccard vector, asserted through the float
	// rendering: 0x3ff0000000000000 is exactly 1.0.
	bits, err := JaccardBits(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bits != 0x3ff0000000000000 {
		t.Fatalf("empty jaccard: got %016x", bits)
	}
	if math.Float64frombits(bits) != 1.0 {
		t.Fatalf("empty jaccard is not 1.0: %v", math.Float64frombits(bits))
	}
}

func TestParseSignatureRejectsTruncatedStream(t *testing.T) {
	if _, err := ParseSignature([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("short stream accepted")
	}
	stream, err := BinarySignature(nil)
	if err != nil {
		t.Fatal(err)
	}
	stream[7] = 1 // announce one digest, carry none
	if _, err := ParseSignature(stream); err == nil {
		t.Fatal("truncated digest body accepted")
	}
}

func TestParseSignatureRoundTrip(t *testing.T) {
	raw := make([]byte, 8+64)
	binary.BigEndian.PutUint64(raw[:8], 2)
	for i := range raw[8:] {
		raw[8+i] = byte(i)
	}
	sig, err := ParseSignature(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sig.ChunkCount != 2 || len(sig.Digests) != 2 {
		t.Fatalf("round trip: %+v", sig)
	}
	if sig.Digests[1][31] != 63 {
		t.Fatalf("digest bytes misplaced: %x", sig.Digests[1])
	}
}
