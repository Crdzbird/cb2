package cb2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var tableEntries = []string{"https://issuer.example", "api", "billing"}

func newTable(t *testing.T, entries []string) *ClaimTable {
	t.Helper()
	table, err := NewClaimTable(entries)
	need(t, err)
	t.Cleanup(table.Close)
	return table
}

func TestClaimTable(t *testing.T) {
	table := newTable(t, tableEntries)
	same := newTable(t, tableEntries)
	other := newTable(t, []string{"api", "https://issuer.example", "billing"})
	refused := [][]string{nil, {}, {"a", "a"}, {"a", ""}, {"a\nb"}}
	for _, entries := range refused {
		_, err := NewClaimTable(entries)
		wantCode(t, err, CodeArgument)
	}
	many := make([]string, 257)
	for i := range many {
		many[i] = fmt.Sprintf("e%d", i)
	}
	_, err := NewClaimTable(many)
	wantCode(t, err, CodeArgument)
	newTable(t, many[:256])
	d1, err := table.Digest()
	need(t, err)
	d2, err := same.Digest()
	need(t, err)
	d3, err := other.Digest()
	need(t, err)
	if d1 != d2 || d1 == d3 || len(d1) != ClaimTableDigestBytes {
		t.Fatalf("digests %x %x %x", d1, d2, d3)
	}
	if got := hex.EncodeToString(d1[:]); got != "767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d" {
		t.Fatalf("digest %s", got)
	}
	closed, err := NewClaimTable(tableEntries)
	need(t, err)
	closed.Close()
	closed.Close()
	if _, err := closed.Digest(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed table digest: %v", err)
	}
	var none *ClaimTable
	none.Close()
	if _, err := none.Digest(); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil table digest: %v", err)
	}
	if _, err := CompactSealWithTable(newLocal(t), closed, claims, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("seal under a closed table: %v", err)
	}
}

func TestClaimTableLocal(t *testing.T) {
	table := newTable(t, tableEntries)
	same := newTable(t, tableEntries)
	other := newTable(t, []string{"api", "https://issuer.example", "billing"})
	k := newLocal(t)
	tabled, err := CompactSealWithTable(k, table, claims, nil)
	need(t, err)
	plain, err := CompactSeal(k, claims, nil)
	need(t, err)
	if !strings.HasPrefix(tabled, "cb3.local.") || len(tabled)+30 >= len(plain) {
		t.Fatalf("tabled %d bytes against %d", len(tabled), len(plain))
	}
	a, err := CompactOpenWithTable(k, same, tabled, baseRules(), nil)
	need(t, err)
	b, err := CompactOpen(k, plain, baseRules(), nil)
	need(t, err)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("tabled claims %v, plain claims %v", a, b)
	}
	_, err = CompactOpen(k, tabled, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpenWithTable(k, nil, tabled, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpenWithTable(k, other, tabled, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpenWithTable(k, table, plain, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactOpenWithTable(k, nil, plain, baseRules(), nil)
	need(t, err)
	billing := baseRules()
	billing.Audience = String("billing")
	_, err = CompactOpenWithTable(k, table, tabled, billing, nil)
	wantCode(t, err, CodeAudienceMismatch)
	stranger := baseRules()
	stranger.Issuer = String("https://other.example")
	_, err = CompactOpenWithTable(k, table, tabled, stranger, nil)
	wantCode(t, err, CodeIssuerMismatch)
	anyone := Rules{AllowAnyIssuer: true, AllowAnyAudience: true, Now: Int64(1700000000)}
	_, err = CompactOpenWithTable(k, table, tabled, anyone, nil)
	need(t, err)
	reserved := []byte("kcb3.table.")
	_, err = CompactSeal(k, claims, reserved)
	wantCode(t, err, CodeArgument)
	_, err = CompactSealWithTable(k, nil, claims, reserved)
	wantCode(t, err, CodeArgument)
	_, err = CompactOpen(k, plain, baseRules(), reserved)
	wantCode(t, err, CodeArgument)
	withContext, err := CompactSealWithTable(k, table, claims, reserved)
	need(t, err)
	_, err = CompactOpenWithTable(k, table, withContext, baseRules(), reserved)
	need(t, err)
	_, err = CompactSealWithTable(nil, table, claims, nil)
	wantCode(t, err, CodeArgument)
}

func TestClaimTablePublic(t *testing.T) {
	if !HasPublic() {
		t.Skip("cb2.public unavailable in this build")
	}
	table := newTable(t, tableEntries)
	same := newTable(t, tableEntries)
	other := newTable(t, []string{"api", "https://issuer.example", "billing"})
	sk, pk := newSecret(t)
	signed, err := CompactSignWithTable(sk, table, claims, nil)
	need(t, err)
	plain, err := CompactSign(sk, claims, nil)
	need(t, err)
	if !strings.HasPrefix(signed, "cb3.public.") || len(signed) >= len(plain) {
		t.Fatalf("tabled %d bytes against %d", len(signed), len(plain))
	}
	got, err := CompactVerifyWithTable(pk, same, signed, baseRules(), nil)
	need(t, err)
	if got["iss"] != "https://issuer.example" || got["aud"] != "api" {
		t.Fatalf("claims %v", got)
	}
	_, err = CompactVerify(pk, signed, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
	_, err = CompactVerifyWithTable(pk, other, signed, baseRules(), nil)
	wantCode(t, err, CodeInvalid)
}
