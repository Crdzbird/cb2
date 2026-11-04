package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// LocalKey is the symmetric key of cb2.local tokens (kcb2.local).
type LocalKey struct {
	h *C.cb2_local_key
}

func newLocalKey(h *C.cb2_local_key) *LocalKey {
	k := &LocalKey{h: h}
	runtime.SetFinalizer(k, (*LocalKey).Close)
	return k
}

// GenerateLocalKey draws a fresh key from the library's generator.
func GenerateLocalKey() (*LocalKey, error) {
	var h *C.cb2_local_key
	if err := check(C.cb2_local_key_generate(&h)); err != nil {
		return nil, err
	}
	return newLocalKey(h), nil
}

// LocalKeyFromBytes builds a key from its 32 raw bytes; weak material
// is refused with argument.
func LocalKeyFromBytes(b []byte) (*LocalKey, error) {
	var h *C.cb2_local_key
	if err := check(C.cb2_local_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &h)); err != nil {
		return nil, err
	}
	return newLocalKey(h), nil
}

// LocalKeyFromPaserk parses a kcb2.local string.
func LocalKeyFromPaserk(text string) (*LocalKey, error) {
	var h *C.cb2_local_key
	if err := check(C.cb2_local_key_from_paserk(strPtr(text), C.size_t(len(text)), &h)); err != nil {
		return nil, err
	}
	return newLocalKey(h), nil
}

// Close releases the handle; later calls on the key fail with argument.
func (k *LocalKey) Close() {
	if k.h != nil {
		C.cb2_local_key_free(k.h)
		k.h = nil
	}
}

// ToPaserk serializes the key as kcb2.local. The Go string holds key
// material and cannot be wiped; keep it short-lived.
func (k *LocalKey) ToPaserk() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeSecret(C.cb2_local_key_to_paserk(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.lid identifier.
func (k *LocalKey) PaserkID() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_local_key_paserk_id(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// KeyID returns the id bound into token footers and false when none is
// set.
func (k *LocalKey) KeyID() (string, bool) {
	if k.h == nil {
		return "", false
	}
	s, ok := takeCString(C.cb2_local_key_key_id(k.h))
	runtime.KeepAlive(k)
	return s, ok
}

// SetKeyID sets the key id; an id with forbidden characters is refused
// with argument.
func (k *LocalKey) SetKeyID(id string) error {
	if k.h == nil {
		return errClosed
	}
	err := check(C.cb2_local_key_set_key_id(k.h, strPtr(id), C.size_t(len(id))))
	runtime.KeepAlive(k)
	return err
}

// ClearKeyID removes the key id.
func (k *LocalKey) ClearKeyID() {
	if k.h == nil {
		return
	}
	C.cb2_local_key_clear_key_id(k.h)
	runtime.KeepAlive(k)
}
