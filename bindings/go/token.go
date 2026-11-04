package cb2

/*
#include <stdint.h>
#include "cb2_c.h"

extern int cb2GoReplay(void* user, char* jti, size_t n);
extern int cb2GoProofReplay(void* user, char* jti, size_t n);

static int cb2_go_token_open(const cb2_local_key* key, const char* token, size_t token_len,
                             const char* rules, size_t rules_len,
                             const uint8_t* implicit, size_t implicit_len,
                             int with_replay, int with_proof, uintptr_t user,
                             char** out_claims, size_t* out_len) {
    return cb2_token_open(key, token, token_len, rules, rules_len, implicit, implicit_len,
                          with_replay ? (cb2_replay_fn)cb2GoReplay : NULL,
                          with_proof ? (cb2_replay_fn)cb2GoProofReplay : NULL,
                          (void*)user, out_claims, out_len);
}

static int cb2_go_token_verify(const cb2_public_key* key, const char* token, size_t token_len,
                               const char* rules, size_t rules_len,
                               const uint8_t* implicit, size_t implicit_len,
                               int with_replay, int with_proof, uintptr_t user,
                               char** out_claims, size_t* out_len) {
    return cb2_token_verify(key, token, token_len, rules, rules_len, implicit, implicit_len,
                            with_replay ? (cb2_replay_fn)cb2GoReplay : NULL,
                            with_proof ? (cb2_replay_fn)cb2GoProofReplay : NULL,
                            (void*)user, out_claims, out_len);
}
*/
import "C"

import (
	"encoding/json"
	"runtime"
)

// TokenSeal encrypts a claims object under key into a cb2.local token.
// The registered claims are strings (times as RFC 3339); the key id, when
// set, is bound into the footer.
func TokenSeal(key *LocalKey, claims map[string]any, implicit []byte) (string, error) {
	if key == nil || key.h == nil {
		return "", errClosed
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_token_seal(key.h, charPtr(payload), C.size_t(len(payload)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// TokenSign signs a claims object with key into a cb2.public token.
func TokenSign(key *SecretKey, claims map[string]any, implicit []byte) (string, error) {
	if key == nil || key.h == nil {
		return "", errClosed
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_token_sign(key.h, charPtr(payload), C.size_t(len(payload)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	runtime.KeepAlive(key)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// TokenOpen decrypts a cb2.local claims token and checks it against the
// rules, returning the claims. A panic in a replay callback refuses the
// id and is raised again once the library has returned.
func TokenOpen(key *LocalKey, token string, rules Rules, implicit []byte) (map[string]any, error) {
	if key == nil || key.h == nil {
		return nil, errClosed
	}
	rj, err := json.Marshal(rules.object())
	if err != nil {
		return nil, err
	}
	cb := newCallbacks(&rules)
	defer cb.release()
	var out *C.char
	var n C.size_t
	code := C.cb2_go_token_open(key.h, strPtr(token), C.size_t(len(token)),
		charPtr(rj), C.size_t(len(rj)), bytesPtr(implicit), C.size_t(len(implicit)),
		flag(rules.Replay != nil), flag(rules.ProofReplay != nil), cb.user(), &out, &n)
	runtime.KeepAlive(key)
	cb.rethrow()
	return claimsResult(code, out, n)
}

// TokenVerify checks a cb2.public claims token against the rules and
// returns the claims. Callbacks behave as in TokenOpen.
func TokenVerify(key *PublicKey, token string, rules Rules, implicit []byte) (map[string]any, error) {
	if key == nil || key.h == nil {
		return nil, errClosed
	}
	rj, err := json.Marshal(rules.object())
	if err != nil {
		return nil, err
	}
	cb := newCallbacks(&rules)
	defer cb.release()
	var out *C.char
	var n C.size_t
	code := C.cb2_go_token_verify(key.h, strPtr(token), C.size_t(len(token)),
		charPtr(rj), C.size_t(len(rj)), bytesPtr(implicit), C.size_t(len(implicit)),
		flag(rules.Replay != nil), flag(rules.ProofReplay != nil), cb.user(), &out, &n)
	runtime.KeepAlive(key)
	cb.rethrow()
	return claimsResult(code, out, n)
}

func claimsResult(code C.int, out *C.char, n C.size_t) (map[string]any, error) {
	if err := check(code); err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(takeText(out, n)), &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// PeekKeyID returns the key id a token's footer names, unverified, and
// false when the footer names none.
func PeekKeyID(token string) (string, bool, error) {
	var out *C.char
	if err := check(C.cb2_peek_key_id(strPtr(token), C.size_t(len(token)), &out)); err != nil {
		return "", false, err
	}
	id, ok := takeCString(out)
	return id, ok, nil
}
