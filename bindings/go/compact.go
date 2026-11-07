package cb2

/*
#include <stdint.h>
#include "cb2_c.h"

extern int cb2GoReplay(void* user, char* jti, size_t n);
extern int cb2GoProofReplay(void* user, char* jti, size_t n);

static int cb2_go_compact_open(const cb2_local_key* key, const char* token, size_t token_len,
                               const char* rules, size_t rules_len,
                               const uint8_t* implicit, size_t implicit_len,
                               int with_replay, int with_proof, uintptr_t user,
                               char** out_claims, size_t* out_len) {
    return cb2_compact_open(key, token, token_len, rules, rules_len, implicit, implicit_len,
                            with_replay ? (cb2_replay_fn)cb2GoReplay : NULL,
                            with_proof ? (cb2_replay_fn)cb2GoProofReplay : NULL,
                            (void*)user, out_claims, out_len);
}

static int cb2_go_compact_verify(const cb2_public_key* key, const char* token, size_t token_len,
                                 const char* rules, size_t rules_len,
                                 const uint8_t* implicit, size_t implicit_len,
                                 int with_replay, int with_proof, uintptr_t user,
                                 char** out_claims, size_t* out_len) {
    return cb2_compact_verify(key, token, token_len, rules, rules_len, implicit, implicit_len,
                              with_replay ? (cb2_replay_fn)cb2GoReplay : NULL,
                              with_proof ? (cb2_replay_fn)cb2GoProofReplay : NULL,
                              (void*)user, out_claims, out_len);
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// KeyDigestBytes is the length in bytes, 16, of the key digest a
// compact token's footer carries in place of the key id.
const KeyDigestBytes = C.CB2_KEY_DIGEST_BYTES

// KeyDigest is the digest of a key id that a compact token's footer
// carries.
type KeyDigest [KeyDigestBytes]byte

// CompactSeal encrypts a claims object under key into a compact local
// token, the experimental format of docs/PROTOCOL.md section 15. It
// takes the same claims as TokenSeal and carries them as CBOR, with the
// key id, when set, bound as its KeyDigest. A custom number that is not
// an int64 integer written in canonical form (1.5, 1e3, -0) is refused
// with ErrArgument, as are a time outside years 0000 to 9999 and a cnf
// that is not a kcb2.local or kcb2.public key.
func CompactSeal(key *LocalKey, claims map[string]any, implicit []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("cb2: encode claims: %w", err)
	}
	h := key.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_compact_seal(p, charPtr(payload), C.size_t(len(payload)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// CompactSign signs a claims object with key into a compact public
// token. Claims are refused as in CompactSeal, and so is a cnf holding
// a kcb2.local key.
func CompactSign(key *SecretKey, claims map[string]any, implicit []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("cb2: encode claims: %w", err)
	}
	h := key.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return "", ErrClosed
	}
	var out *C.char
	var n C.size_t
	code := C.cb2_compact_sign(p, charPtr(payload), C.size_t(len(payload)),
		bytesPtr(implicit), C.size_t(len(implicit)), &out, &n)
	if err := check(code); err != nil {
		return "", err
	}
	return takeText(out, n), nil
}

// CompactOpen decrypts a compact local token and checks it against the
// rules, returning the claims as TokenOpen would. A cb2.local token is
// refused here with ErrInvalid, and a compact token is refused by
// TokenOpen. Callbacks behave as in TokenOpen.
func CompactOpen(key *LocalKey, token string, rules Rules, implicit []byte) (map[string]any, error) {
	rj, err := json.Marshal(rules.object())
	if err != nil {
		return nil, fmt.Errorf("cb2: encode rules: %w", err)
	}
	h := key.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return nil, ErrClosed
	}
	cb := newCallbacks(&rules)
	defer cb.release()
	var out *C.char
	var n C.size_t
	code := C.cb2_go_compact_open(p, strPtr(token), C.size_t(len(token)),
		charPtr(rj), C.size_t(len(rj)), bytesPtr(implicit), C.size_t(len(implicit)),
		flag(rules.Replay != nil), flag(rules.ProofReplay != nil), cb.user(), &out, &n)
	cb.rethrow()
	return claimsResult(code, out, n)
}

// CompactVerify checks a compact public token against the rules and
// returns the claims. Callbacks behave as in TokenOpen.
func CompactVerify(key *PublicKey, token string, rules Rules, implicit []byte) (map[string]any, error) {
	rj, err := json.Marshal(rules.object())
	if err != nil {
		return nil, fmt.Errorf("cb2: encode rules: %w", err)
	}
	h := key.handle()
	p := h.acquire()
	defer h.release()
	if p == nil {
		return nil, ErrClosed
	}
	cb := newCallbacks(&rules)
	defer cb.release()
	var out *C.char
	var n C.size_t
	code := C.cb2_go_compact_verify(p, strPtr(token), C.size_t(len(token)),
		charPtr(rj), C.size_t(len(rj)), bytesPtr(implicit), C.size_t(len(implicit)),
		flag(rules.Replay != nil), flag(rules.ProofReplay != nil), cb.user(), &out, &n)
	cb.rethrow()
	return claimsResult(code, out, n)
}

// PeekKeyDigest returns the key digest a compact token's footer
// carries, unverified, and false when it carries none, as a cb2 token
// never does. Compare it with KeyDigestOf each key id to pick a key;
// nothing it returns is authenticated.
func PeekKeyDigest(token string) (KeyDigest, bool, error) {
	var out *C.uint8_t
	if err := check(C.cb2_compact_peek_key_digest(strPtr(token), C.size_t(len(token)), &out)); err != nil {
		return KeyDigest{}, false, err
	}
	d, ok := takeDigest(out)
	return d, ok, nil
}

// KeyDigestOf returns the digest that the footer of a compact token
// carries when the key's id is id (see KeyID on the keys). An empty id
// is valid; an id with control characters is refused with ErrArgument.
func KeyDigestOf(id string) (KeyDigest, error) {
	var out *C.uint8_t
	if err := check(C.cb2_compact_key_digest(strPtr(id), C.size_t(len(id)), &out)); err != nil {
		return KeyDigest{}, err
	}
	d, ok := takeDigest(out)
	if !ok {
		return KeyDigest{}, nilResult()
	}
	return d, nil
}

func takeDigest(p *C.uint8_t) (KeyDigest, bool) {
	var d KeyDigest
	if p == nil {
		return d, false
	}
	copy(d[:], unsafe.Slice((*byte)(unsafe.Pointer(p)), KeyDigestBytes))
	C.cb2_free(unsafe.Pointer(p))
	return d, true
}
