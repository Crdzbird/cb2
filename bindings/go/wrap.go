package cb2

/*
#include "cb2_c.h"
*/
import "C"

// Wrap encrypts key under wrapping as a kcb2.local-wrap string.
func Wrap(wrapping, key *LocalKey) (string, error) {
	wh, kh := wrapping.handle(), key.handle()
	wp, kp := wh.acquire(), kh.acquire()
	defer wh.release()
	defer kh.release()
	if wp == nil || kp == nil {
		return "", ErrClosed
	}
	var out *C.char
	if err := check(C.cb2_wrap(wp, kp, &out)); err != nil {
		return "", err
	}
	s, ok := takeCString(out)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// Unwrap recovers the key a kcb2.local-wrap string holds, as a new key
// with its own lifetime.
func Unwrap(text string, wrapping *LocalKey) (*LocalKey, error) {
	wh := wrapping.handle()
	wp := wh.acquire()
	defer wh.release()
	if wp == nil {
		return nil, ErrClosed
	}
	var out *C.cb2_local_key
	if err := check(C.cb2_unwrap(strPtr(text), C.size_t(len(text)), wp, &out)); err != nil {
		return nil, err
	}
	return newLocalKey(out), nil
}

// Seal encrypts key to a recipient as a kcb2.seal string; ErrUnavailable
// without kcb2.seal.
func Seal(to *RecipientPublicKey, key *LocalKey) (string, error) {
	th, kh := to.handle(), key.handle()
	tp, kp := th.acquire(), kh.acquire()
	defer th.release()
	defer kh.release()
	if tp == nil || kp == nil {
		return "", ErrClosed
	}
	var out *C.char
	if err := check(C.cb2_seal(tp, kp, &out)); err != nil {
		return "", err
	}
	s, ok := takeCString(out)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}

// Unseal recovers the key a kcb2.seal string holds with the recipient
// pair, as a new key with its own lifetime.
func Unseal(text string, by *RecipientKey) (*LocalKey, error) {
	bh := by.handle()
	bp := bh.acquire()
	defer bh.release()
	if bp == nil {
		return nil, ErrClosed
	}
	var out *C.cb2_local_key
	if err := check(C.cb2_unseal(strPtr(text), C.size_t(len(text)), bp, &out)); err != nil {
		return nil, err
	}
	return newLocalKey(out), nil
}
