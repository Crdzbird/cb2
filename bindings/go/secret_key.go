package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// SecretKey is the signing half of a cb2.public pair (kcb2.secret).
//
// A SecretKey is safe for concurrent use by multiple goroutines, Close
// and SetKeyID included. Close it when done; a finalizer releases the C
// handle of a key that becomes unreachable without Close.
type SecretKey struct {
	h handle[*C.cb2_secret_key]
}

func newSecretKey(p *C.cb2_secret_key) *SecretKey {
	k := &SecretKey{}
	k.h.init(p, func(p *C.cb2_secret_key) { C.cb2_secret_key_free(p) })
	runtime.SetFinalizer(k, (*SecretKey).Close)
	return k
}

func (k *SecretKey) handle() *handle[*C.cb2_secret_key] {
	if k == nil {
		return new(handle[*C.cb2_secret_key])
	}
	return &k.h
}

// GenerateSecretKey draws a fresh signing pair; ErrUnavailable without
// cb2.public.
func GenerateSecretKey() (*SecretKey, error) {
	var p *C.cb2_secret_key
	if err := check(C.cb2_secret_key_generate(&p)); err != nil {
		return nil, err
	}
	return newSecretKey(p), nil
}

// SecretKeyFromBytes builds a signing pair from its raw bytes.
func SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	var p *C.cb2_secret_key
	if err := check(C.cb2_secret_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &p)); err != nil {
		return nil, err
	}
	return newSecretKey(p), nil
}

// SecretKeyFromPaserk parses a kcb2.secret string.
func SecretKeyFromPaserk(text string) (*SecretKey, error) {
	var p *C.cb2_secret_key
	if err := check(C.cb2_secret_key_from_paserk(strPtr(text), C.size_t(len(text)), &p)); err != nil {
		return nil, err
	}
	return newSecretKey(p), nil
}

// Close releases the key. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (k *SecretKey) Close() {
	if k == nil {
		return
	}
	runtime.SetFinalizer(k, nil)
	k.h.close()
}

// ToPaserk serializes the pair as kcb2.secret. The Go string holds key
// material and cannot be wiped; keep it short-lived.
func (k *SecretKey) ToPaserk() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeSecret(C.cb2_secret_key_to_paserk(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PublicKey returns the verifying half of the pair as a new key with
// its own lifetime.
func (k *SecretKey) PublicKey() (*PublicKey, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return nil, ErrClosed
	}
	var out *C.cb2_public_key
	if err := check(C.cb2_secret_key_public_key(p, &out)); err != nil {
		return nil, err
	}
	return newPublicKey(out), nil
}

// KeyID returns the id bound into token footers and false when none is
// set or the key is closed.
func (k *SecretKey) KeyID() (string, bool) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", false
	}
	return takeCString(C.cb2_secret_key_key_id(p))
}

// SetKeyID sets the key id bound into the footer of the tokens the key
// signs from now on; an id with forbidden characters is refused with
// ErrArgument. It waits for calls in flight on the key to finish.
func (k *SecretKey) SetKeyID(id string) error {
	var code C.int
	if !k.handle().mutate(func(p *C.cb2_secret_key) {
		code = C.cb2_secret_key_set_key_id(p, strPtr(id), C.size_t(len(id)))
	}) {
		return ErrClosed
	}
	return check(code)
}

// ClearKeyID removes the key id; it does nothing on a closed key.
func (k *SecretKey) ClearKeyID() {
	k.handle().mutate(func(p *C.cb2_secret_key) {
		C.cb2_secret_key_clear_key_id(p)
	})
}
