package cb2

/*
#include "cb2_c.h"
*/
import "C"

// HolderProve signs a proof with the client's pair for one request
// (method, target and optional nonce) and one access token, with the
// given proof id, issue time and lifetime in seconds: the public mode.
func HolderProve(client *SecretKey, htm, htu string, nonce *string, accessToken, jti string, now, lifetime int64) (string, error) {
	h := client.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	noncePtr, nonceLen := optionalText(nonce)
	var out *C.char
	var n C.size_t
	code := C.cb2_holder_prove(p, strPtr(htm), C.size_t(len(htm)),
		strPtr(htu), C.size_t(len(htu)), noncePtr, nonceLen,
		strPtr(accessToken), C.size_t(len(accessToken)),
		strPtr(jti), C.size_t(len(jti)),
		C.int64_t(now), C.int64_t(lifetime), &out, &n)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// HolderProveLocal makes a proof under the kcb2.local proof key the
// issuer wrote into cnf of a cb2.local access token and handed to the
// client with it, for one request and that token: the local mode,
// available in every build.
func HolderProveLocal(proofKey *LocalKey, htm, htu string, nonce *string, accessToken, jti string, now, lifetime int64) (string, error) {
	h := proofKey.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	noncePtr, nonceLen := optionalText(nonce)
	var out *C.char
	var n C.size_t
	code := C.cb2_holder_prove_local(p, strPtr(htm), C.size_t(len(htm)),
		strPtr(htu), C.size_t(len(htu)), noncePtr, nonceLen,
		strPtr(accessToken), C.size_t(len(accessToken)),
		strPtr(jti), C.size_t(len(jti)),
		C.int64_t(now), C.int64_t(lifetime), &out, &n)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

func optionalText(s *string) (*C.char, C.size_t) {
	if s == nil {
		return nil, 0
	}
	return strPtr(*s), C.size_t(len(*s))
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
