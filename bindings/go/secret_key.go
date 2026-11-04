package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// SecretKey is the signing half of a cb2.public pair (kcb2.secret).
type SecretKey struct {
	h *C.cb2_secret_key
}

func newSecretKey(h *C.cb2_secret_key) *SecretKey {
	k := &SecretKey{h: h}
	runtime.SetFinalizer(k, (*SecretKey).Close)
	return k
}

// GenerateSecretKey draws a fresh signing pair; unavailable without
// cb2.public.
func GenerateSecretKey() (*SecretKey, error) {
	var h *C.cb2_secret_key
	if err := check(C.cb2_secret_key_generate(&h)); err != nil {
		return nil, err
	}
	return newSecretKey(h), nil
}

// SecretKeyFromBytes builds a signing pair from its raw bytes.
func SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	var h *C.cb2_secret_key
	if err := check(C.cb2_secret_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &h)); err != nil {
		return nil, err
	}
	return newSecretKey(h), nil
}

// SecretKeyFromPaserk parses a kcb2.secret string.
func SecretKeyFromPaserk(text string) (*SecretKey, error) {
	var h *C.cb2_secret_key
	if err := check(C.cb2_secret_key_from_paserk(strPtr(text), C.size_t(len(text)), &h)); err != nil {
		return nil, err
	}
	return newSecretKey(h), nil
}

// Close releases the handle; later calls on the key fail with argument.
func (k *SecretKey) Close() {
	if k.h != nil {
		C.cb2_secret_key_free(k.h)
		k.h = nil
	}
}

// ToPaserk serializes the pair as kcb2.secret. The Go string holds key
// material and cannot be wiped; keep it short-lived.
func (k *SecretKey) ToPaserk() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeSecret(C.cb2_secret_key_to_paserk(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PublicKey returns the verifying half of the pair.
func (k *SecretKey) PublicKey() (*PublicKey, error) {
	if k.h == nil {
		return nil, errClosed
	}
	var h *C.cb2_public_key
	err := check(C.cb2_secret_key_public_key(k.h, &h))
	runtime.KeepAlive(k)
	if err != nil {
		return nil, err
	}
	return newPublicKey(h), nil
}

// KeyID returns the id bound into token footers and false when none is
// set.
func (k *SecretKey) KeyID() (string, bool) {
	if k.h == nil {
		return "", false
	}
	s, ok := takeCString(C.cb2_secret_key_key_id(k.h))
	runtime.KeepAlive(k)
	return s, ok
}

// SetKeyID sets the key id; an id with forbidden characters is refused
// with argument.
func (k *SecretKey) SetKeyID(id string) error {
	if k.h == nil {
		return errClosed
	}
	err := check(C.cb2_secret_key_set_key_id(k.h, strPtr(id), C.size_t(len(id))))
	runtime.KeepAlive(k)
	return err
}

// ClearKeyID removes the key id.
func (k *SecretKey) ClearKeyID() {
	if k.h == nil {
		return
	}
	C.cb2_secret_key_clear_key_id(k.h)
	runtime.KeepAlive(k)
}
