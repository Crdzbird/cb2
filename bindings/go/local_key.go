package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// LocalKey is the symmetric key of cb2.local tokens (kcb2.local).
//
// A LocalKey is safe for concurrent use by multiple goroutines, Close
// and SetKeyID included. Close it when done; a finalizer releases the C
// handle of a key that becomes unreachable without Close.
type LocalKey struct {
	h handle[*C.cb2_local_key]
}

func newLocalKey(p *C.cb2_local_key) *LocalKey {
	k := &LocalKey{}
	k.h.init(p, func(p *C.cb2_local_key) { C.cb2_local_key_free(p) })
	runtime.SetFinalizer(k, (*LocalKey).Close)
	return k
}

func (k *LocalKey) handle() *handle[*C.cb2_local_key] {
	if k == nil {
		return new(handle[*C.cb2_local_key])
	}
	return &k.h
}

// GenerateLocalKey draws a fresh key from the library's generator.
func GenerateLocalKey() (*LocalKey, error) {
	var p *C.cb2_local_key
	if err := check(C.cb2_local_key_generate(&p)); err != nil {
		return nil, err
	}
	return newLocalKey(p), nil
}

// LocalKeyFromBytes builds a key from its 32 raw bytes; weak material
// is refused with ErrArgument.
func LocalKeyFromBytes(b []byte) (*LocalKey, error) {
	var p *C.cb2_local_key
	if err := check(C.cb2_local_key_from_bytes(bytesPtr(b), C.size_t(len(b)), &p)); err != nil {
		return nil, err
	}
	return newLocalKey(p), nil
}

// LocalKeyFromPaserk parses a kcb2.local string.
func LocalKeyFromPaserk(text string) (*LocalKey, error) {
	var p *C.cb2_local_key
	if err := check(C.cb2_local_key_from_paserk(strPtr(text), C.size_t(len(text)), &p)); err != nil {
		return nil, err
	}
	return newLocalKey(p), nil
}

// Close releases the key. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (k *LocalKey) Close() {
	if k == nil {
		return
	}
	runtime.SetFinalizer(k, nil)
	k.h.close()
}

// ToPaserk serializes the key as kcb2.local. The Go string holds key
// material and cannot be wiped; keep it short-lived.
func (k *LocalKey) ToPaserk() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeSecret(C.cb2_local_key_to_paserk(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// PaserkID returns the key's kcb2.lid identifier.
func (k *LocalKey) PaserkID() (string, error) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	s, ok := takeCString(C.cb2_local_key_paserk_id(p))
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// KeyID returns the id bound into token footers and false when none is
// set or the key is closed.
func (k *LocalKey) KeyID() (string, bool) {
	h := k.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", false
	}
	return takeCString(C.cb2_local_key_key_id(p))
}

// SetKeyID sets the key id bound into the footer of the tokens the key
// makes from now on; an id with forbidden characters is refused with
// ErrArgument. It waits for calls in flight on the key to finish.
func (k *LocalKey) SetKeyID(id string) error {
	var code C.int
	if !k.handle().mutate(func(p *C.cb2_local_key) {
		code = C.cb2_local_key_set_key_id(p, strPtr(id), C.size_t(len(id)))
	}) {
		return ErrClosed
	}
	return check(code)
}

// ClearKeyID removes the key id; it does nothing on a closed key.
func (k *LocalKey) ClearKeyID() {
	k.handle().mutate(func(p *C.cb2_local_key) {
		C.cb2_local_key_clear_key_id(p)
	})
}
