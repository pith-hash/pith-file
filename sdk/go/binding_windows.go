// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build windows

package pithfile

import (
	"fmt"
	"syscall"
	"unsafe"
)

// openProc loads libPath and resolves name. The library is released
// before returning: on Windows FreeLibrary unmaps the cdylib, so the
// proc must be used (and its buffer copied out) inside the caller.
func openProc(libPath, name string) (proc uintptr, release func(), err error) {
	lib, err := syscall.LoadLibrary(libPath)
	if err != nil {
		return 0, nil, fmt.Errorf("pithfile: LoadLibrary(%s): %w", libPath, err)
	}
	release = func() { syscall.FreeLibrary(lib) }
	proc, err = syscall.GetProcAddress(lib, name)
	if err != nil {
		release()
		return 0, nil, fmt.Errorf("pithfile: symbol %s missing from %s: %w", name, libPath, err)
	}
	return proc, release, nil
}

// ffiBinarySignature loads the cdylib with LoadLibrary (absolute path,
// no PATH involvement), resolves pith_file_binary_signature and calls
// it. The returned buffer stays alive in the cdylib until ffiFree.
func ffiBinarySignature(libPath string, data *byte, n int, out **byte, outLen *uintptr) (int32, error) {
	proc, release, err := openProc(libPath, "pith_file_binary_signature")
	if err != nil {
		return 0, err
	}
	defer release()

	var cOut *byte
	var cLen uintptr
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(unsafe.Pointer(&cOut)),
		uintptr(unsafe.Pointer(&cLen)),
	)
	*out = cOut
	*outLen = cLen
	return int32(rc), nil
}

// ffiJaccard loads the cdylib, resolves pith_file_jaccard and calls it.
func ffiJaccard(libPath string, a *byte, aLen int, b *byte, bLen int, out *uint64) (int32, error) {
	proc, release, err := openProc(libPath, "pith_file_jaccard")
	if err != nil {
		return 0, err
	}
	defer release()

	var bits uint64
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(a)),
		uintptr(aLen),
		uintptr(unsafe.Pointer(b)),
		uintptr(bLen),
		uintptr(unsafe.Pointer(&bits)),
	)
	*out = bits
	return int32(rc), nil
}

// ffiTextContent loads the cdylib, resolves pith_file_text_content and
// calls it.
func ffiTextContent(libPath string, data *byte, n int, format uint32, out **byte, outLen *uintptr) (int32, error) {
	proc, release, err := openProc(libPath, "pith_file_text_content")
	if err != nil {
		return 0, err
	}
	defer release()

	var cOut *byte
	var cLen uintptr
	rc, _, _ := syscall.SyscallN(proc,
		uintptr(unsafe.Pointer(data)),
		uintptr(n),
		uintptr(format),
		uintptr(unsafe.Pointer(&cOut)),
		uintptr(unsafe.Pointer(&cLen)),
	)
	*out = cOut
	*outLen = cLen
	return int32(rc), nil
}

// ffiFree resolves pith_file_free and releases a buffer handed out by
// ffiBinarySignature or ffiTextContent. Null is accepted (the cdylib
// ignores it).
func ffiFree(libPath string, ptr *byte, n uintptr) {
	proc, release, err := openProc(libPath, "pith_file_free")
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	defer release()
	syscall.SyscallN(proc, uintptr(unsafe.Pointer(ptr)), n)
}
