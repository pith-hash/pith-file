// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && !cgo

package pithfile

import "fmt"

// The pure-Go fallback backend: cgo is unavailable, so the cdylib
// cannot be loaded and every FFI call fails with an actionable error
// naming the build tag that restores the real backend.

var errNoBackend = fmt.Errorf(
	"pithfile: built without cgo (CGO_ENABLED=0 or no C toolchain); rebuild with cgo to load the pith-file cdylib",
)

// ffiBinarySignature reports the no-backend error.
func ffiBinarySignature(string, *byte, int, **byte, *uintptr) (int32, error) {
	return 0, errNoBackend
}

// ffiJaccard reports the no-backend error.
func ffiJaccard(string, *byte, int, *byte, int, *uint64) (int32, error) {
	return 0, errNoBackend
}

// ffiTextContent reports the no-backend error.
func ffiTextContent(string, *byte, int, uint32, **byte, *uintptr) (int32, error) {
	return 0, errNoBackend
}

// ffiFree is a no-op without a backend.
func ffiFree(string, *byte, uintptr) {}
