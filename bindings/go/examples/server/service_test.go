package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

type fixture struct {
	t      *testing.T
	srv    *httptest.Server
	offset atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := cb2.GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	f := &fixture{t: t}
	clock := func() time.Time { return time.Now().Add(time.Duration(f.offset.Load())) }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := newService(key, "https://api.example", time.Minute, map[string]string{"alice": "wonderland"}, clock, log)
	f.srv = httptest.NewServer(svc.routes())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) login(user, password string) (loginResponse, int) {
	f.t.Helper()
	body := `{"username":"` + user + `","password":"` + password + `"}`
	resp, err := http.Post(f.srv.URL+"/login", "application/json", strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out loginResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode
}

func (f *fixture) proof(s loginResponse, method, target, jti string) string {
	f.t.Helper()
	key, err := cb2.LocalKeyFromPaserk(s.ProofKey)
	if err != nil {
		f.t.Fatal(err)
	}
	defer key.Close()
	now := time.Now().Add(time.Duration(f.offset.Load())).Unix()
	p, err := cb2.HolderProveLocal(key, method, target, nil, s.AccessToken, jti, now, 60)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) me(token, proof string) (int, string) {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.srv.URL+"/me", nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "CB2 "+token)
	}
	if proof != "" {
		req.Header.Set("CB2-Proof", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if e, ok := out["error"].(string); ok {
		return resp.StatusCode, e
	}
	sub, _ := out["sub"].(string)
	return resp.StatusCode, sub
}

func TestService(t *testing.T) {
	f := newFixture(t)
	if _, code := f.login("alice", "nope"); code != http.StatusUnauthorized {
		t.Fatalf("bad password: %d", code)
	}
	s, code := f.login("alice", "wonderland")
	if code != http.StatusOK || !strings.HasPrefix(s.AccessToken, "cb2.local.") {
		t.Fatalf("login: %d %+v", code, s)
	}
	const me = "https://api.example/me"
	tampered := s.AccessToken[:40] + flip(s.AccessToken[40]) + s.AccessToken[41:]
	cases := []struct {
		name   string
		token  string
		proof  string
		status int
		want   string
	}{
		{"accepted", s.AccessToken, f.proof(s, "GET", me, "p-1"), 200, "alice"},
		{"replayed proof", s.AccessToken, f.proof(s, "GET", me, "p-1"), 401, "proof_replayed"},
		{"no token", "", "", 401, "missing_token"},
		{"no proof", s.AccessToken, "", 401, "missing_proof"},
		{"other target", s.AccessToken, f.proof(s, "GET", "https://api.example/admin", "p-2"), 401, "proof_mismatch"},
		{"other method", s.AccessToken, f.proof(s, "POST", me, "p-3"), 401, "proof_mismatch"},
		{"tampered token", tampered, f.proof(s, "GET", me, "p-4"), 401, "invalid"},
	}
	for _, c := range cases {
		status, got := f.me(c.token, c.proof)
		if status != c.status || got != c.want {
			t.Errorf("%s: got %d %q, want %d %q", c.name, status, got, c.status, c.want)
		}
	}
	f.offset.Store(int64(2 * time.Minute))
	if status, got := f.me(s.AccessToken, f.proof(s, "GET", me, "p-5")); status != 401 || got != "expired" {
		t.Errorf("expired: got %d %q", status, got)
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestReplayStoreForgetsAndBounds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := newReplayStore(time.Minute, 2, func() time.Time { return now })
	if !s.firstUse("a") || s.firstUse("a") || !s.firstUse("b") {
		t.Fatal("first use")
	}
	if s.firstUse("c") {
		t.Fatal("a full store must refuse")
	}
	now = now.Add(2 * time.Minute)
	if !s.firstUse("a") || !s.firstUse("c") {
		t.Fatal("expired ids must be forgotten")
	}
}
