// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

//go:build !windows && cgo

package pithfile

/*
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*pith_sign_fn)(const uint8_t *, size_t, uint8_t **, size_t *);
typedef int32_t (*pith_jaccard_fn)(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t *);
typedef int32_t (*pith_text_fn)(const uint8_t *, size_t, uint32_t, uint8_t **, size_t *);
typedef void (*pith_free_fn)(uint8_t *, size_t);

static int32_t pith_call_sign(void *fn, const uint8_t *data, size_t len,
                              uint8_t **out, size_t *out_len) {
    return ((pith_sign_fn)fn)(data, len, out, out_len);
}

static int32_t pith_call_jaccard(void *fn, const uint8_t *a, size_t a_len,
                                 const uint8_t *b, size_t b_len, uint64_t *out) {
    return ((pith_jaccard_fn)fn)(a, a_len, b, b_len, out);
}

static int32_t pith_call_text(void *fn, const uint8_t *data, size_t len,
                              uint32_t format, uint8_t **out, size_t *out_len) {
    return ((pith_text_fn)fn)(data, len, format, out, out_len);
}

static void pith_call_free(void *fn, uint8_t *ptr, size_t len) {
    ((pith_free_fn)fn)(ptr, len);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// openCdylib dlopens libPath with the error text surfaced verbatim.
func openCdylib(libPath string) (unsafe.Pointer, error) {
	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))
	handle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		msg := "unknown dlopen failure"
		if e := C.dlerror(); e != nil {
			msg = C.GoString(e)
		}
		return nil, fmt.Errorf("pithfile: dlopen(%s): %s", libPath, msg)
	}
	return handle, nil
}

// dlsym resolves one symbol, failing with a named error.
func dlsym(handle unsafe.Pointer, libPath, name string) (unsafe.Pointer, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	sym := C.dlsym(handle, cName)
	if sym == nil {
		return nil, fmt.Errorf("pithfile: symbol %s missing from %s", name, libPath)
	}
	return sym, nil
}

// ffiBinarySignature opens the cdylib, resolves
// pith_file_binary_signature and calls it. The handle is released
// before returning; repeated calls reuse the loader's own refcount.
func ffiBinarySignature(libPath string, data *byte, n int, out **byte, outLen *uintptr) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := dlsym(handle, libPath, "pith_file_binary_signature")
	if err != nil {
		return 0, err
	}
	var cOut *C.uint8_t
	var cLen C.size_t
	rc := C.pith_call_sign(sym, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(n), &cOut, &cLen)
	*out = (*byte)(unsafe.Pointer(cOut))
	*outLen = uintptr(cLen)
	return int32(rc), nil
}

// ffiJaccard opens the cdylib, resolves pith_file_jaccard and calls it.
func ffiJaccard(libPath string, a *byte, aLen int, b *byte, bLen int, out *uint64) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := dlsym(handle, libPath, "pith_file_jaccard")
	if err != nil {
		return 0, err
	}
	var cBits C.uint64_t
	rc := C.pith_call_jaccard(sym,
		(*C.uint8_t)(unsafe.Pointer(a)), C.size_t(aLen),
		(*C.uint8_t)(unsafe.Pointer(b)), C.size_t(bLen), &cBits)
	*out = uint64(cBits)
	return int32(rc), nil
}

// ffiTextContent opens the cdylib, resolves pith_file_text_content and
// calls it.
func ffiTextContent(libPath string, data *byte, n int, format uint32, out **byte, outLen *uintptr) (int32, error) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return 0, err
	}
	defer C.dlclose(handle)
	sym, err := dlsym(handle, libPath, "pith_file_text_content")
	if err != nil {
		return 0, err
	}
	var cOut *C.uint8_t
	var cLen C.size_t
	rc := C.pith_call_text(sym, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(n), C.uint32_t(format), &cOut, &cLen)
	*out = (*byte)(unsafe.Pointer(cOut))
	*outLen = uintptr(cLen)
	return int32(rc), nil
}

// ffiFree resolves pith_file_free and releases a buffer handed out by
// ffiBinarySignature or ffiTextContent. Null is accepted (the cdylib
// ignores it), matching the C contract.
func ffiFree(libPath string, ptr *byte, n uintptr) {
	handle, err := openCdylib(libPath)
	if err != nil {
		return // the library vanished mid-flight; nothing to free
	}
	defer C.dlclose(handle)
	sym, err := dlsym(handle, libPath, "pith_file_free")
	if err != nil {
		return
	}
	C.pith_call_free(sym, (*C.uint8_t)(unsafe.Pointer(ptr)), C.size_t(n))
}
