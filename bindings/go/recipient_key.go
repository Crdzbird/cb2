package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// RecipientKey is the decapsulating half of a kcb2.seal pair
// (kcb2.recipient-secret).
//
// A RecipientKey is safe for concurrent use by multiple goroutines,
// Close included. Close it when done; a finalizer releases the C handle
// of a key that becomes unreachable without Close.
type RecipientKey struct {
	h handle[*C.cb2_recipient_key]
}

func newRecipientKey(p *C.cb2_recipient_key) *RecipientKey {
	k := &RecipientKey{}
	k.h.init(p, func(p *C.cb2_recipient_key) { C.cb2_recipient_key_free(p) })
	runtime.SetFinalizer(k, (*RecipientKey).Close)
	return k
}

func (k *RecipientKey) handle() *handle[*C.cb2_recipient_key] {
	if k == nil {
		return new(handle[*C.cb2_recipient_key])
	}
	return &k.h
}

// GenerateRecipientKey draws a fresh recipient pair; ErrUnavailable
// without kcb2.seal.
func GenerateRecipientKey() (*RecipientKey, error) {
	var p *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_generate(&p)); err != nil {
		return nil, err
	}
	return newRecipientKey(p), nil
}

// RecipientKeyFromBytes builds a recipient pair from its raw bytes.
func RecipientKeyFromBytes(b []byte) (*RecipientKey, error) {
	var p *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &p)); err != nil {
		return nil, err
	}
	return newRecipientKey(p), nil
}

// RecipientKeyFromPaserk parses a kcb2.recipient-secret string.
func RecipientKeyFromPaserk(text string) (*RecipientKey, error) {
	var p *C.cb2_recipient_key
	if err := check(C.cb2_recipient_key_from_paserk(strPtr(text), C.size_t(len(text)), &p)); err != nil {
		return nil, err
	}
	return newRecipientKey(p), nil
}

// Close releases the key. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (k *RecipientKey) Close() {
	if k == nil {
		return
	}
	runtime.SetFinalizer(k, nil)
	k.h.close()
}

// ToPaserk serializes the pair as kcb2.recipient-secret. The Go string
// holds key material and cannot be wiped; keep it short-lived.
func (k *RecipientKey) ToPaserk() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeSecret(C.cb2_recipient_key_to_paserk(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PublicKey returns the encapsulating half of the pair as a new key
// with its own lifetime.
func (k *RecipientKey) PublicKey() (*RecipientPublicKey, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return nil, ErrClosed
	}
	var out *C.cb2_recipient_public_key
	if err := check(C.cb2_recipient_key_public_key(p, &out)); err != nil {
		return nil, err
	}
	return newRecipientPublicKey(out), nil
}

// PaserkID returns the pair's kcb2.rid identifier.
func (k *RecipientKey) PaserkID() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_recipient_key_paserk_id(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}
