package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// RecipientPublicKey is the encapsulating half of a kcb2.seal pair
// (kcb2.recipient).
type RecipientPublicKey struct {
	h *C.cb2_recipient_public_key
}

func newRecipientPublicKey(h *C.cb2_recipient_public_key) *RecipientPublicKey {
	k := &RecipientPublicKey{h: h}
	runtime.SetFinalizer(k, (*RecipientPublicKey).Close)
	return k
}

// RecipientPublicKeyFromBytes builds an encapsulating key from its raw
// bytes.
func RecipientPublicKeyFromBytes(b []byte) (*RecipientPublicKey, error) {
	var h *C.cb2_recipient_public_key
	if err := check(C.cb2_recipient_public_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &h)); err != nil {
		return nil, err
	}
	return newRecipientPublicKey(h), nil
}

// RecipientPublicKeyFromPaserk parses a kcb2.recipient string.
func RecipientPublicKeyFromPaserk(text string) (*RecipientPublicKey, error) {
	var h *C.cb2_recipient_public_key
	if err := check(C.cb2_recipient_public_key_from_paserk(strPtr(text), C.size_t(len(text)), &h)); err != nil {
		return nil, err
	}
	return newRecipientPublicKey(h), nil
}

// Close releases the handle; later calls on the key fail with argument.
func (k *RecipientPublicKey) Close() {
	if k.h != nil {
		C.cb2_recipient_public_key_free(k.h)
		k.h = nil
	}
}

// ToPaserk serializes the key as kcb2.recipient.
func (k *RecipientPublicKey) ToPaserk() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_recipient_public_key_to_paserk(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.rid identifier.
func (k *RecipientPublicKey) PaserkID() (string, error) {
	if k.h == nil {
		return "", errClosed
	}
	s, ok := takeCString(C.cb2_recipient_public_key_paserk_id(k.h))
	runtime.KeepAlive(k)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}
