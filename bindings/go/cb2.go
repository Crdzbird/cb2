package cb2

/*
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
