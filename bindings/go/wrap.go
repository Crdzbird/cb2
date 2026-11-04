package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// Wrap encrypts key under wrapping as a kcb2.local-wrap string.
func Wrap(wrapping, key *LocalKey) (string, error) {
	if wrapping == nil || wrapping.h == nil || key == nil || key.h == nil {
		return "", errClosed
	}
	var out *C.char
	code := C.cb2_wrap(wrapping.h, key.h, &out)
	runtime.KeepAlive(wrapping)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	s, ok := takeCString(out)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// Unwrap recovers the key a kcb2.local-wrap string holds.
func Unwrap(text string, wrapping *LocalKey) (*LocalKey, error) {
	if wrapping == nil || wrapping.h == nil {
		return nil, errClosed
	}
	var h *C.cb2_local_key
	code := C.cb2_unwrap(strPtr(text), C.size_t(len(text)), wrapping.h, &h)
	runtime.KeepAlive(wrapping)
	if err := check(code); err != nil {
		return nil, err
	}
	return newLocalKey(h), nil
}

// Seal encrypts key to a recipient as a kcb2.seal string.
func Seal(to *RecipientPublicKey, key *LocalKey) (string, error) {
	if to == nil || to.h == nil || key == nil || key.h == nil {
		return "", errClosed
	}
	var out *C.char
	code := C.cb2_seal(to.h, key.h, &out)
	runtime.KeepAlive(to)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	s, ok := takeCString(out)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// Unseal recovers the key a kcb2.seal string holds with the recipient
// pair.
func Unseal(text string, by *RecipientKey) (*LocalKey, error) {
	if by == nil || by.h == nil {
		return nil, errClosed
	}
	var h *C.cb2_local_key
	code := C.cb2_unseal(strPtr(text), C.size_t(len(text)), by.h, &h)
	runtime.KeepAlive(by)
	if err := check(code); err != nil {
		return nil, err
	}
	return newLocalKey(h), nil
}
