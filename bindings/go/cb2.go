// Package cb2 is the Go bridge to cb2, a post-quantum token library,
// through its C ABI (bindings/c/include/cb2_c.h).
//
// Keys wrap C handles: every key has an explicit Close and a finalizer
// that releases the handle when the key is collected. Raw tokens carry
// any bytes; claims tokens carry a JSON object that is checked against
// Rules on the way back. Every verdict of the library comes back as an
// *Error whose Code and Name are the library's own.
package cb2

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo LDFLAGS: -L${SRCDIR}/../../build/bindings/c -lcb2_c -Wl,-rpath,${SRCDIR}/../../build/bindings/c
#include <stdlib.h>
#include "cb2_c.h"
*/
import "C"

import "unsafe"

// Version returns the version of the linked library.
func Version() string {
	return C.GoString(C.cb2_version())
}

// HasPublic reports whether the library was built with cb2.public.
func HasPublic() bool {
	return C.cb2_has_public() != 0
}

// HasSeal reports whether the library was built with kcb2.seal.
func HasSeal() bool {
	return C.cb2_has_seal() != 0
}

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func charPtr(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func strPtr(s string) *C.char {
	if len(s) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
}

func takeText(p *C.char, n C.size_t) string {
	if p == nil {
		return ""
	}
	s := C.GoStringN(p, C.int(n))
	C.cb2_free(unsafe.Pointer(p))
	return s
}

func takeBytes(p *C.uint8_t, n C.size_t) []byte {
	if p == nil {
		return []byte{}
	}
	b := C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.cb2_free(unsafe.Pointer(p))
	return b
}

func takeCString(p *C.char) (string, bool) {
	if p == nil {
		return "", false
	}
	s := C.GoString(p)
	C.cb2_free(unsafe.Pointer(p))
	return s, true
}

func takeSecret(p *C.char) (string, bool) {
	if p == nil {
		return "", false
	}
	s := C.GoString(p)
	C.cb2_free_secret(p)
	return s, true
}
