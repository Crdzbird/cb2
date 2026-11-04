package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// PublicKey is the verifying half of a cb2.public pair (kcb2.public).
type PublicKey struct {
	h *C.cb2_public_key
}

func newPublicKey(h *C.cb2_public_key) *PublicKey {
	k := &PublicKey{h: h}
	runtime.SetFinalizer(k, (*PublicKey).Close)
	return k
}

// PublicKeyFromBytes builds a verifying key from its raw bytes.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var h *C.cb2_public_key
	if err := check(C.cb2_public_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &h)); err != nil {
		return nil, err
	}
	return newPublicKey(h), nil
}

// PublicKeyFromPaserk parses a kcb2.public string.
func PublicKeyFromPaserk(text string) (*PublicKey, error) {
	var h *C.cb2_public_key
	if err := check(C.cb2_public_key_from_paserk(strPtr(text), C.size_t(len(text)), &h)); err != nil {
		return nil, err
	}
	return newPublicKey(h), nil
}

// Close releases the handle; later calls on the key fail with argument.
func (k *PublicKey) Close() {
	if k.h != nil {
		C.cb2_public_key_free(k.h)
		k.h = nil
	}
}

// ToPaserk serializes the key as kcb2.public.
func (k *PublicKey) ToPaserk() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_public_key_to_paserk(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.pid identifier.
func (k *PublicKey) PaserkID() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_public_key_paserk_id(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// KeyID returns the id bound into token footers and false when none is
// set.
func (k *PublicKey) KeyID() (string, bool) {
	if k.h == nil {
		return "", false
	}
	s, ok := takeCString(C.cb2_public_key_key_id(k.h))
	runtime.KeepAlive(k)
	return s, ok
}

// SetKeyID sets the key id; an id with forbidden characters is refused
// with argument.
func (k *PublicKey) SetKeyID(id string) error {
	if k.h == nil {
		return errClosed
	}
	err := check(C.cb2_public_key_set_key_id(k.h, strPtr(id), C.size_t(len(id))))
	runtime.KeepAlive(k)
	return err
}

// ClearKeyID removes the key id.
func (k *PublicKey) ClearKeyID() {
	if k.h == nil {
		return
	}
	C.cb2_public_key_clear_key_id(k.h)
	runtime.KeepAlive(k)
}
