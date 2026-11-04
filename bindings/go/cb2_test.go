package cb2

import (
	"errors"
	"strings"
	"testing"
)

var claims = map[string]any{
	"iss":  "https://issuer.example",
	"sub":  "user-1",
	"aud":  "api",
	"exp":  "2099-01-01T00:00:00+00:00",
	"jti":  "id-1",
	"role": "admin",
}

func baseRules() Rules {
	return Rules{
		Issuer:   String("https://issuer.example"),
		Audience: String("api"),
		Now:      Int64(1700000000),
	}
}

func need(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want %s, got %v", ErrorName(code), err)
	}
	if e.Code != code {
		t.Fatalf("want %s, got %s", ErrorName(code), e.Name)
	}
	if !errors.Is(err, NewError(code)) {
		t.Fatalf("errors.Is does not match %s", ErrorName(code))
	}
}

func localID(t *testing.T, k *LocalKey) string {
	t.Helper()
	id, err := k.PaserkID()
	need(t, err)
	return id
}

func newLocal(t *testing.T) *LocalKey {
	t.Helper()
	k, err := GenerateLocalKey()
	need(t, err)
	t.Cleanup(k.Close)
	return k
}

func newSecret(t *testing.T) (*SecretKey, *PublicKey) {
	t.Helper()
	sk, err := GenerateSecretKey()
	need(t, err)
	t.Cleanup(sk.Close)
	pk, err := sk.PublicKey()
	need(t, err)
	t.Cleanup(pk.Close)
	return sk, pk
}

func TestLibrary(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
	if ErrorName(CodeArgument) != "argument" || ErrorName(0) != "ok" {
		t.Fatal("error names")
	}
	if ErrorName(CodeProofReplayed) != "proof_replayed" || ErrorName(99) != "unknown" {
		t.Fatal("error names")
	}
	if ErrArgument.Error() != "cb2: argument" {
		t.Fatal(ErrArgument.Error())
	}
}

func TestLocalKey(t *testing.T) {
	k := newLocal(t)
	paserk, err := k.ToPaserk()
	need(t, err)
	if !strings.HasPrefix(paserk, "kcb2.local.") || len(paserk) != 54 {
		t.Fatalf("paserk %q", paserk)
	}
	id := localID(t, k)
	kid, ok := k.KeyID()
	if !ok || kid != id || !strings.HasPrefix(id, "kcb2.lid.") {
		t.Fatalf("id %q kid %q", id, kid)
	}
	same, err := LocalKeyFromPaserk(paserk)
	need(t, err)
	defer same.Close()
	if localID(t, same) != id {
		t.Fatal("round trip changed the id")
	}
	need(t, k.SetKeyID("rotation-1"))
	if kid, ok := k.KeyID(); !ok || kid != "rotation-1" {
		t.Fatalf("kid %q", kid)
	}
	wantCode(t, k.SetKeyID("a\u200b"), CodeArgument)
	k.ClearKeyID()
	if _, ok := k.KeyID(); ok {
		t.Fatal("key id survived clear")
	}
	weak := make([]byte, 32)
	for i := range weak {
		weak[i] = 7
	}
	_, err = LocalKeyFromBytes(weak)
	wantCode(t, err, CodeArgument)
	closed := newLocal(t)
	closed.Close()
	closed.Close()
	_, err = closed.ToPaserk()
	wantCode(t, err, CodeArgument)
}

func TestLocalRaw(t *testing.T) {
	k := newLocal(t)
	paserk, err := k.ToPaserk()
	need(t, err)
	same, err := LocalKeyFromPaserk(paserk)
	need(t, err)
	defer same.Close()
	msg := []byte("hello")
	footer := []byte(`{"kid":"x"}`)
	token, err := LocalSeal(k, msg, footer, nil)
	need(t, err)
	if !strings.HasPrefix(token, "cb2.local.") {
		t.Fatalf("token %q", token)
	}
	out, err := LocalOpen(same, token, footer, nil, 0)
	need(t, err)
	if string(out) != "hello" {
		t.Fatalf("opened %q", out)
	}
	_, err = LocalOpen(same, token, nil, nil, 0)
	wantCode(t, err, CodeInvalid)
	flipped := "B"
	if token[len(token)-1] == 'B' {
		flipped = "A"
	}
	_, err = LocalOpen(same, token[:len(token)-1]+flipped, footer, nil, 0)
	wantCode(t, err, CodeInvalid)
}

func TestLocalClaims(t *testing.T) {
	k := newLocal(t)
	ct, err := TokenSeal(k, claims, nil)
	need(t, err)
	got, err := TokenOpen(k, ct, baseRules(), nil)
	need(t, err)
	if got["role"] != "admin" || got["jti"] != "id-1" {
		t.Fatalf("claims %v", got)
	}
	peeked, ok, err := PeekKeyID(ct)
	if err != nil || !ok || peeked != localID(t, k) {
		t.Fatalf("peek %q %v %v", peeked, ok, err)
	}
	_, err = TokenOpen(k, ct, Rules{}, nil)
	wantCode(t, err, CodeRulesIncomplete)
	other := baseRules()
	other.Audience = String("other")
	_, err = TokenOpen(k, ct, other, nil)
	wantCode(t, err, CodeAudienceMismatch)
	late := baseRules()
	late.Now = Int64(4102444801)
	_, err = TokenOpen(k, ct, late, nil)
	wantCode(t, err, CodeExpired)
	seen := map[string]bool{}
	replay := baseRules()
	replay.Replay = func(jti string) bool {
		if seen[jti] {
			return false
		}
		seen[jti] = true
		return true
	}
	_, err = TokenOpen(k, ct, replay, nil)
	need(t, err)
	_, err = TokenOpen(k, ct, replay, nil)
	wantCode(t, err, CodeReplayed)
	if !seen["id-1"] {
		t.Fatal("the callback never saw id-1")
	}
	list := baseRules()
	list.SeenJTI = []string{"id-1"}
	_, err = TokenOpen(k, ct, list, nil)
	wantCode(t, err, CodeReplayed)
	lifetime := baseRules()
	lifetime.MaxLifetime = Int64(60)
	_, err = TokenOpen(k, ct, lifetime, nil)
	wantCode(t, err, CodeLifetimeExceeded)
	bad := map[string]any{"sub": "a\u200bb", "exp": "2099-01-01T00:00:00+00:00"}
	_, err = TokenSeal(k, bad, nil)
	wantCode(t, err, CodeArgument)
}

func TestReplayPanic(t *testing.T) {
	k := newLocal(t)
	ct, err := TokenSeal(k, claims, nil)
	need(t, err)
	rules := baseRules()
	rules.Replay = func(string) bool { panic("store down") }
	defer func() {
		if r := recover(); r != "store down" {
			t.Fatalf("recovered %v", r)
		}
	}()
	_, _ = TokenOpen(k, ct, rules, nil)
	t.Fatal("the panic did not reach the caller")
}

func TestWrap(t *testing.T) {
	k := newLocal(t)
	wrapping := newLocal(t)
	wrapped, err := Wrap(wrapping, k)
	need(t, err)
	if !strings.HasPrefix(wrapped, "kcb2.local-wrap.") || len(wrapped) != 144 {
		t.Fatalf("wrapped %q", wrapped)
	}
	unwrapped, err := Unwrap(wrapped, wrapping)
	need(t, err)
	defer unwrapped.Close()
	if localID(t, unwrapped) != localID(t, k) {
		t.Fatal("unwrap changed the key")
	}
	_, err = Unwrap(wrapped, k)
	wantCode(t, err, CodeInvalid)
}

func TestPublic(t *testing.T) {
	if !HasPublic() {
		t.Skip("cb2.public unavailable in this build")
	}
	sk, pk := newSecret(t)
	pub, err := pk.ToPaserk()
	need(t, err)
	if len(pub) != 2658 {
		t.Fatalf("public paserk length %d", len(pub))
	}
	pk2, err := PublicKeyFromPaserk(pub)
	need(t, err)
	defer pk2.Close()
	token, err := TokenSign(sk, claims, nil)
	need(t, err)
	got, err := TokenVerify(pk2, token, baseRules(), nil)
	need(t, err)
	if got["sub"] != "user-1" {
		t.Fatalf("claims %v", got)
	}
	_, spk := newSecret(t)
	_, err = TokenVerify(spk, token, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	raw, err := PublicSign(sk, []byte("signed"), []byte("f"), []byte("i"))
	need(t, err)
	if !strings.HasPrefix(raw, "cb2.public.") {
		t.Fatalf("token %q", raw)
	}
	msg, err := PublicVerify(pk2, raw, []byte("f"), []byte("i"), 0)
	need(t, err)
	if string(msg) != "signed" {
		t.Fatalf("verified %q", msg)
	}
	_, err = PublicVerify(pk2, raw, []byte("f"), nil, 0)
	wantCode(t, err, CodeInvalid)
}

func TestHolder(t *testing.T) {
	if !HasPublic() {
		t.Skip("cb2.public unavailable in this build")
	}
	client, clientPublic := newSecret(t)
	clientPub, err := clientPublic.ToPaserk()
	need(t, err)
	k := newLocal(t)
	bound := map[string]any{
		"iss": "https://issuer.example",
		"aud": "api",
		"exp": "2099-01-01T00:00:00+00:00",
		"cnf": clientPub,
	}
	access, err := TokenSeal(k, bound, nil)
	need(t, err)
	_, err = TokenOpen(k, access, baseRules(), nil)
	wantCode(t, err, CodeMissingProof)
	proof, err := HolderProve(client, "GET", "https://api.example/v1/me", nil, access, "p-1", 1700000000, 60)
	need(t, err)
	if !strings.HasPrefix(proof, "cb2.holder-public.") {
		t.Fatalf("proof %q", proof)
	}
	rules := baseRules()
	rules.Proof = proof
	rules.Request = &HolderRequest{HTM: "GET", HTU: "HTTPS://API.EXAMPLE:443/v1/me?x=1"}
	_, err = TokenOpen(k, access, rules, nil)
	wantCode(t, err, CodeRulesIncomplete)
	rules.ProofReplay = func(string) bool { return true }
	_, err = TokenOpen(k, access, rules, nil)
	need(t, err)
	mismatch := baseRules()
	mismatch.Proof = proof
	mismatch.Request = &HolderRequest{HTM: "POST", HTU: "https://api.example/v1/me"}
	mismatch.ProofSeenJTI = []string{}
	_, err = TokenOpen(k, access, mismatch, nil)
	wantCode(t, err, CodeProofMismatch)
	replayed := baseRules()
	replayed.Proof = proof
	replayed.Request = &HolderRequest{HTM: "GET", HTU: "https://api.example/v1/me"}
	replayed.ProofSeenJTI = []string{"p-1"}
	_, err = TokenOpen(k, access, replayed, nil)
	wantCode(t, err, CodeProofReplayed)
	expired := baseRules()
	expired.Now = Int64(1700000100)
	expired.Proof = proof
	expired.Request = &HolderRequest{HTM: "GET", HTU: "https://api.example/v1/me"}
	expired.ProofSeenJTI = []string{}
	_, err = TokenOpen(k, access, expired, nil)
	wantCode(t, err, CodeProofExpired)
	ignore := baseRules()
	ignore.IgnoreCnf = true
	_, err = TokenOpen(k, access, ignore, nil)
	need(t, err)
	norm, err := NormalizeTarget("HTTPS://API.Example:443/a?b#c")
	need(t, err)
	if norm != "https://api.example/a" {
		t.Fatalf("normalized %q", norm)
	}
	_, err = NormalizeTarget("nope")
	wantCode(t, err, CodeArgument)
}

func TestSeal(t *testing.T) {
	if !HasSeal() {
		t.Skip("kcb2.seal unavailable in this build")
	}
	r, err := GenerateRecipientKey()
	need(t, err)
	defer r.Close()
	rp, err := r.PublicKey()
	need(t, err)
	defer rp.Close()
	rec, err := rp.ToPaserk()
	need(t, err)
	if !strings.HasPrefix(rec, "kcb2.recipient.") || len(rec) != 1637 {
		t.Fatalf("recipient paserk length %d", len(rec))
	}
	secret, err := r.ToPaserk()
	need(t, err)
	if len(secret) != 65 {
		t.Fatalf("recipient secret length %d", len(secret))
	}
	r2, err := RecipientKeyFromPaserk(secret)
	need(t, err)
	defer r2.Close()
	k := newLocal(t)
	sealed, err := Seal(rp, k)
	need(t, err)
	if len(sealed) != 1632 {
		t.Fatalf("sealed length %d", len(sealed))
	}
	back, err := Unseal(sealed, r2)
	need(t, err)
	defer back.Close()
	if localID(t, back) != localID(t, k) {
		t.Fatal("unseal changed the key")
	}
	other, err := GenerateRecipientKey()
	need(t, err)
	defer other.Close()
	_, err = Unseal(sealed, other)
	wantCode(t, err, CodeInvalid)
	rid, err := rp.PaserkID()
	need(t, err)
	rid2, err := r2.PaserkID()
	need(t, err)
	if rid != rid2 || !strings.HasPrefix(rid, "kcb2.rid.") {
		t.Fatalf("rid %q", rid)
	}
}
