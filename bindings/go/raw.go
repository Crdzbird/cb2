package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// LocalSeal encrypts any message under key into a cb2.local token. The
// footer travels in the clear and is authenticated; the implicit
// assertion is authenticated but not carried.
func LocalSeal(key *LocalKey, msg, footer, implicit []byte) (string, error) {
	if key == nil || key.h == nil {
		return "", errClosed
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_local_seal(key.h, bytesPtr(msg), C.size_t(len(msg)),
		bytesPtr(footer), C.size_t(len(footer)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// LocalOpen decrypts a cb2.local token; the footer and implicit
// assertion must match those it was sealed with. maxTokenBytes of 0
// means the library's default.
func LocalOpen(key *LocalKey, token string, footer, implicit []byte, maxTokenBytes int) ([]byte, error) {
	if key == nil || key.h == nil {
		return nil, errClosed
	}
	var out *C.uint8_t
	var n C.size_t
	code := C.cb2_local_open(key.h, strPtr(token), C.size_t(len(token)),
		bytesPtr(footer), C.size_t(len(footer)),
		bytesPtr(implicit), C.size_t(len(implicit)),
		C.size_t(maxTokenBytes), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return nil, err
	}
	return takeBytes(out, n), nil
}

// PublicSign signs any message with key into a cb2.public token.
func PublicSign(key *SecretKey, msg, footer, implicit []byte) (string, error) {
	if key == nil || key.h == nil {
		return "", errClosed
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_public_sign(key.h, bytesPtr(msg), C.size_t(len(msg)),
		bytesPtr(footer), C.size_t(len(footer)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// PublicVerify checks a cb2.public token and returns its message.
// maxTokenBytes of 0 means the library's default.
func PublicVerify(key *PublicKey, token string, footer, implicit []byte, maxTokenBytes int) ([]byte, error) {
	if key == nil || key.h == nil {
		return nil, errClosed
	}
	var out *C.uint8_t
	var n C.size_t
	code := C.cb2_public_verify(key.h, strPtr(token), C.size_t(len(token)),
		bytesPtr(footer), C.size_t(len(footer)),
		bytesPtr(implicit), C.size_t(len(implicit)),
		C.size_t(maxTokenBytes), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return nil, err
	}
	return takeBytes(out, n), nil
}
