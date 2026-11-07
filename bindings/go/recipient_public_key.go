package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// RecipientPublicKey is the encapsulating half of a kcb2.seal pair
// (kcb2.recipient).
//
// A RecipientPublicKey is safe for concurrent use by multiple
// goroutines, Close included. Close it when done; a finalizer releases
// the C handle of a key that becomes unreachable without Close.
type RecipientPublicKey struct {
	h handle[*C.cb2_recipient_public_key]
}

func newRecipientPublicKey(p *C.cb2_recipient_public_key) *RecipientPublicKey {
	k := &RecipientPublicKey{}
	k.h.init(p, func(p *C.cb2_recipient_public_key) { C.cb2_recipient_public_key_free(p) })
	runtime.SetFinalizer(k, (*RecipientPublicKey).Close)
	return k
}

func (k *RecipientPublicKey) handle() *handle[*C.cb2_recipient_public_key] {
	if k == nil {
		return new(handle[*C.cb2_recipient_public_key])
	}
	return &k.h
}

// RecipientPublicKeyFromBytes builds an encapsulating key from its raw
// bytes.
func RecipientPublicKeyFromBytes(b []byte) (*RecipientPublicKey, error) {
	var p *C.cb2_recipient_public_key
	if err := check(C.cb2_recipient_public_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &p)); err != nil {
		return nil, err
	}
	return newRecipientPublicKey(p), nil
}

// RecipientPublicKeyFromPaserk parses a kcb2.recipient string.
func RecipientPublicKeyFromPaserk(text string) (*RecipientPublicKey, error) {
	var p *C.cb2_recipient_public_key
	if err := check(C.cb2_recipient_public_key_from_paserk(strPtr(text), C.size_t(len(text)), &p)); err != nil {
		return nil, err
	}
	return newRecipientPublicKey(p), nil
}

// Close releases the key. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (k *RecipientPublicKey) Close() {
	if k == nil {
		return
	}
	runtime.SetFinalizer(k, nil)
	k.h.close()
}

// ToPaserk serializes the key as kcb2.recipient.
func (k *RecipientPublicKey) ToPaserk() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_recipient_public_key_to_paserk(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.rid identifier.
func (k *RecipientPublicKey) PaserkID() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_recipient_public_key_paserk_id(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}
