package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// RecipientKey is the decapsulating half of a kcb2.seal pair
// (kcb2.recipient-secret).
type RecipientKey struct {
	h *C.cb2_recipient_key
}

func newRecipientKey(h *C.cb2_recipient_key) *RecipientKey {
	k := &RecipientKey{h: h}
	runtime.SetFinalizer(k, (*RecipientKey).Close)
	return k
}

// GenerateRecipientKey draws a fresh recipient pair; unavailable
// without kcb2.seal.
func GenerateRecipientKey() (*RecipientKey, error) {
	var h *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_generate(&h)); err != nil {
		return nil, err
	}
	return newRecipientKey(h), nil
}

// RecipientKeyFromBytes builds a recipient pair from its raw bytes.
func RecipientKeyFromBytes(b []byte) (*RecipientKey, error) {
	var h *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &h)); err != nil {
		return nil, err
	}
	return newRecipientKey(h), nil
}

// RecipientKeyFromPaserk parses a kcb2.recipient-secret string.
func RecipientKeyFromPaserk(text string) (*RecipientKey, error) {
	var h *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_from_paserk(strPtr(text), C.size_t(len(text)), &h)); err != nil {
		return nil, err
	}
	return newRecipientKey(h), nil
}

// Close releases the handle; later calls on the key fail with argument.
func (k *RecipientKey) Close() {
	if k.h != nil {
		C.cb2_recipient_key_free(k.h)
		k.h = nil
	}
}

// ToPaserk serializes the pair as kcb2.recipient-secret. The Go string
// holds key material and cannot be wiped; keep it short-lived.
func (k *RecipientKey) ToPaserk() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeSecret(C.cb2_recipient_key_to_paserk(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PublicKey returns the encapsulating half of the pair.
func (k *RecipientKey) PublicKey() (*RecipientPublicKey, error) {
	if k.h == nil {
		return nil, errClosed
	}
	var h *C.cb2_recipient_public_key
	err := check(C.cb2_recipient_key_public_key(k.h, &h))
	runtime.KeepAlive(k)
	if err != nil {
		return nil, err
	}
	return newRecipientPublicKey(h), nil
}

// PaserkID returns the pair's kcb2.rid identifier.
func (k *RecipientKey) PaserkID() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_recipient_key_paserk_id(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}
