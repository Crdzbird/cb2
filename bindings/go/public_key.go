package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// PublicKey is the verifying half of a cb2.public pair (kcb2.public).
//
// A PublicKey is safe for concurrent use by multiple goroutines, Close
// and SetKeyID included. Close it when done; a finalizer releases the C
// handle of a key that becomes unreachable without Close.
type PublicKey struct {
	h handle[*C.cb2_public_key]
}

func newPublicKey(p *C.cb2_public_key) *PublicKey {
	k := &PublicKey{}
	k.h.init(p, func(p *C.cb2_public_key) { C.cb2_public_key_free(p) })
	runtime.SetFinalizer(k, (*PublicKey).Close)
	return k
}

func (k *PublicKey) handle() *handle[*C.cb2_public_key] {
	if k == nil {
		return new(handle[*C.cb2_public_key])
	}
	return &k.h
}

// PublicKeyFromBytes builds a verifying key from its raw bytes.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var p *C.cb2_public_key
	if err := check(C.cb2_public_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &p)); err != nil {
		return nil, err
	}
	return newPublicKey(p), nil
}

// PublicKeyFromPaserk parses a kcb2.public string.
func PublicKeyFromPaserk(text string) (*PublicKey, error) {
	var p *C.cb2_public_key
	if err := check(C.cb2_public_key_from_paserk(strPtr(text), C.size_t(len(text)), &p)); err != nil {
		return nil, err
	}
	return newPublicKey(p), nil
}

// Close releases the key. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (k *PublicKey) Close() {
	if k == nil {
		return
	}
	runtime.SetFinalizer(k, nil)
	k.h.close()
}

// ToPaserk serializes the key as kcb2.public.
func (k *PublicKey) ToPaserk() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_public_key_to_paserk(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.pid identifier.
func (k *PublicKey) PaserkID() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_public_key_paserk_id(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// KeyID returns the id the key expects in token footers and false when
// none is set or the key is closed.
func (k *PublicKey) KeyID() (string, bool) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", false
	}
	return takeCString(C.cb2_public_key_key_id(p))
}

// SetKeyID sets the key id; an id with forbidden characters is refused
// with ErrArgument. It waits for calls in flight on the key to finish.
func (k *PublicKey) SetKeyID(id string) error {
	var code C.int
	if !k.handle().mutate(func(p *C.cb2_public_key) {
		code = C.cb2_public_key_set_key_id(p, strPtr(id), C.size_t(len(id)))
	}) {
		return ErrClosed
	}
	return check(code)
}

// ClearKeyID removes the key id; it does nothing on a closed key.
func (k *PublicKey) ClearKeyID() {
	k.handle().mutate(func(p *C.cb2_public_key) {
		C.cb2_public_key_clear_key_id(p)
	})
}
