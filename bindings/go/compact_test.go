package cb2

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestCompactLocal(t *testing.T) {
	k := newLocal(t)
	compact, err := CompactSeal(k, claims, nil)
	need(t, err)
	full, err := TokenSeal(k, claims, nil)
	need(t, err)
	if !strings.HasPrefix(compact, "cb3.local.") || len(compact) >= len(full) {
		t.Fatalf("compact %d bytes against %d: %q", len(compact), len(full), compact)
	}
	a, err := CompactOpen(k, compact, baseRules(), nil)
	need(t, err)
	b, err := TokenOpen(k, full, baseRules(), nil)
	need(t, err)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("compact claims %v, cb2 claims %v", a, b)
	}
	_, err = TokenOpen(k, compact, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpen(k, full, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpen(k, compact, Rules{}, nil)
	wantCode(t, err, CodeRulesIncomplete)
	other := baseRules()
	other.Audience = String("web")
	_, err = CompactOpen(k, compact, other, nil)
	wantCode(t, err, CodeAudienceMismatch)
	late := baseRules()
	late.Now = Int64(4102444800)
	_, err = CompactOpen(k, compact, late, nil)
	wantCode(t, err, CodeExpired)
	list := baseRules()
	list.SeenJTI = []string{"id-1"}
	_, err = CompactOpen(k, compact, list, nil)
	wantCode(t, err, CodeReplayed)
	seen := map[string]bool{}
	replay := baseRules()
	replay.Replay = func(jti string) bool {
		if seen[jti] {
			return false
		}
		seen[jti] = true
		return true
	}
	_, err = CompactOpen(k, compact, replay, nil)
	need(t, err)
	_, err = CompactOpen(k, compact, replay, nil)
	wantCode(t, err, CodeReplayed)
	_, err = CompactOpen(k, compact, baseRules(), []byte("x"))
	wantCode(t, err, CodeInvalid)
}

func TestCompactKeyDigest(t *testing.T) {
	k := newLocal(t)
	compact, err := CompactSeal(k, claims, nil)
	need(t, err)
	kid, ok := k.KeyID()
	if !ok {
		t.Fatal("generated key has no key id")
	}
	peeked, ok, err := PeekKeyDigest(compact)
	need(t, err)
	want, err := KeyDigestOf(kid)
	need(t, err)
	if !ok || peeked != want || len(peeked) != KeyDigestBytes {
		t.Fatalf("peeked %x %v, want %x", peeked, ok, want)
	}
	full, err := TokenSeal(k, claims, nil)
	need(t, err)
	if _, ok, err := PeekKeyDigest(full); err != nil || ok {
		t.Fatalf("a cb2 token gave a digest: %v %v", ok, err)
	}
	_, err = KeyDigestOf("a\nb")
	wantCode(t, err, CodeArgument)
	empty, err := KeyDigestOf("")
	need(t, err)
	if empty == want {
		t.Fatal("the empty id has the digest of the key id")
	}
	k.ClearKeyID()
	bare, err := CompactSeal(k, claims, nil)
	need(t, err)
	if _, ok, err := PeekKeyDigest(bare); err != nil || ok {
		t.Fatalf("a token without key id gave a digest: %v %v", ok, err)
	}
	_, err = CompactOpen(k, compact, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpen(k, bare, baseRules(), nil)
	need(t, err)
}

func TestCompactRefusals(t *testing.T) {
	k := newLocal(t)
	fraction := map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": "2099-01-01T00:00:00+00:00",
		"n":   1.5,
	}
	_, err := CompactSeal(k, fraction, nil)
	wantCode(t, err, CodeArgument)
	_, err = TokenSeal(k, fraction, nil)
	need(t, err)
	fraction["n"] = math.Copysign(0, -1)
	_, err = CompactSeal(k, fraction, nil)
	wantCode(t, err, CodeArgument)
	fraction["n"] = float64(3)
	_, err = CompactSeal(k, fraction, nil)
	need(t, err)
	_, err = CompactSeal(k, map[string]any{"bad": func() {}}, nil)
	var e *Error
	if err == nil || errors.As(err, &e) {
		t.Fatalf("want a JSON encoding error, got %v", err)
	}
	closed := newLocal(t)
	closed.Close()
	_, err = CompactSeal(closed, claims, nil)
	wantCode(t, err, CodeArgument)
	_, err = CompactOpen(closed, "cb3.local.x", baseRules(), nil)
	wantCode(t, err, CodeArgument)
}

func TestCompactHolderLocal(t *testing.T) {
	k := newLocal(t)
	proofKey := newLocal(t)
	cnf, err := proofKey.ToPaserk()
	need(t, err)
	bound := map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": "2099-01-01T00:00:00+00:00",
		"cnf": cnf,
	}
	access, err := CompactSeal(k, bound, nil)
	need(t, err)
	_, err = CompactOpen(k, access, baseRules(), nil)
	wantCode(t, err, CodeMissingProof)
	proof, err := HolderProveLocal(proofKey, "GET", "https://api.example/v1/me", nil, access, "p-1", 1700000000, 60)
	need(t, err)
	rules := baseRules()
	rules.Proof = proof
	rules.Request = &HolderRequest{HTM: "GET", HTU: "https://api.example/v1/me"}
	rules.ProofReplay = func(string) bool { return true }
	got, err := CompactOpen(k, access, rules, nil)
	need(t, err)
	if got["cnf"] != cnf {
		t.Fatalf("cnf %v", got["cnf"])
	}
	mismatch := baseRules()
	mismatch.Proof = proof
	mismatch.Request = &HolderRequest{HTM: "POST", HTU: "https://api.example/v1/me"}
	mismatch.ProofSeenJTI = []string{}
	_, err = CompactOpen(k, access, mismatch, nil)
	wantCode(t, err, CodeProofMismatch)
}

func TestCompactPublic(t *testing.T) {
	if !HasPublic() {
		t.Skip("cb2.public unavailable in this build")
	}
	sk, pk := newSecret(t)
	signed, err := CompactSign(sk, claims, nil)
	need(t, err)
	full, err := TokenSign(sk, claims, nil)
	need(t, err)
	if !strings.HasPrefix(signed, "cb3.public.") || len(signed) >= len(full) {
		t.Fatalf("compact %d bytes against %d", len(signed), len(full))
	}
	got, err := CompactVerify(pk, signed, baseRules(), nil)
	need(t, err)
	if got["sub"] != "user-1" {
		t.Fatalf("claims %v", got)
	}
	_, err = TokenVerify(pk, signed, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactVerify(pk, full, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	other := baseRules()
	other.Audience = String("web")
	_, err = CompactVerify(pk, signed, other, nil)
	wantCode(t, err, CodeAudienceMismatch)
	_, spk := newSecret(t)
	_, err = CompactVerify(spk, signed, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	if _, ok, err := PeekKeyDigest(signed); err != nil || !ok {
		t.Fatalf("signed token digest: %v %v", ok, err)
	}
	proofKey := newLocal(t)
	cnf, err := proofKey.ToPaserk()
	need(t, err)
	_, err = CompactSign(sk, map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": "2099-01-01T00:00:00+00:00",
		"cnf": cnf,
	}, nil)
	wantCode(t, err, CodeArgument)
}
