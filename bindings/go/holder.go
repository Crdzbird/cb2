package cb2

/*
#include "cb2_c.h"
*/
import "C"

import "runtime"

// HolderProve signs a proof with the client's pair for one request
// (method, target and optional nonce) and one access token, with the
// given proof id, issue time and lifetime in seconds.
func HolderProve(client *SecretKey, htm, htu string, nonce *string, accessToken, jti string, now, lifetime int64) (string, error) {
	if client == nil || client.h == nil {
		return "", errClosed
	}
	var noncePtr *C.char
	var nonceLen C.size_t
	if nonce != nil {
		noncePtr = strPtr(*nonce)
		nonceLen = C.size_t(len(*nonce))
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_holder_prove(client.h, strPtr(htm), C.size_t(len(htm)),
		strPtr(htu), C.size_t(len(htu)), noncePtr, nonceLen,
		strPtr(accessToken), C.size_t(len(accessToken)),
		strPtr(jti), C.size_t(len(jti)),
		C.int64_t(now), C.int64_t(lifetime), &out, &n)
	runtime.KeepAlive(client)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// NormalizeTarget reduces a request URI to the form a holder proof
// commits to: lower-case scheme and host, default port dropped, query
// and fragment removed.
func NormalizeTarget(uri string) (string, error) {
	var out *C.char
	if err := check(C.cb2_holder_normalize_target(strPtr(uri), C.size_t(len(uri)), &out)); err != nil {
		return "", err
	}
	s, ok := takeCString(out)
	if !ok {
		return "", nilResult()
	}
	return s, nil
}
