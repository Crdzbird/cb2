package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

const (
	audience      = "cb2-example-api"
	proofLifetime = 60 * time.Second
	clockSkew     = 5 * time.Second
)

var errNoToken = errors.New("no CB2 access token in the Authorization header")

type service struct {
	key    *cb2.LocalKey
	origin string
	ttl    time.Duration
	users  map[string][sha256.Size]byte
	proofs *replayStore
	now    func() time.Time
	log    *slog.Logger
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ProofKey    string `json:"proof_key"`
	ExpiresAt   string `json:"expires_at"`
}

type meResponse struct {
	Subject   any `json:"sub"`
	TokenID   any `json:"jti"`
	ExpiresAt any `json:"exp"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func newService(key *cb2.LocalKey, origin string, ttl time.Duration, users map[string]string, now func() time.Time, log *slog.Logger) *service {
	hashed := make(map[string][sha256.Size]byte, len(users))
	for name, password := range users {
		hashed[name] = sha256.Sum256([]byte(password))
	}
	return &service{
		key:    key,
		origin: strings.TrimSuffix(origin, "/"),
		ttl:    ttl,
		users:  hashed,
		proofs: newReplayStore(proofLifetime+2*clockSkew, 100000, now),
		now:    now,
		log:    log,
	}
}

func (s *service) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /me", s.me)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "cb2": cb2.Version()})
	})
	return mux
}

func (s *service) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "bad_request"})
		return
	}
	if !s.checkPassword(req.Username, req.Password) {
		s.log.Info("login refused", "user", req.Username)
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "bad_credentials"})
		return
	}
	resp, err := s.issue(req.Username)
	if err != nil {
		s.log.Error("issue token", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
		return
	}
	s.log.Info("token issued", "user", req.Username, "expires_at", resp.ExpiresAt)
	writeJSON(w, http.StatusOK, resp)
}

func (s *service) checkPassword(name, password string) bool {
	want, known := s.users[name]
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1 && known
}

func (s *service) issue(subject string) (loginResponse, error) {
	proofKey, err := cb2.GenerateLocalKey()
	if err != nil {
		return loginResponse{}, err
	}
	defer proofKey.Close()
	cnf, err := proofKey.ToPaserk()
	if err != nil {
		return loginResponse{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	exp := now.Add(s.ttl).Format(time.RFC3339)
	token, err := cb2.TokenSeal(s.key, map[string]any{
		"iss": s.origin,
		"aud": audience,
		"sub": subject,
		"jti": randomID(),
		"iat": now.Format(time.RFC3339),
		"exp": exp,
		"cnf": cnf,
	}, nil)
	if err != nil {
		return loginResponse{}, err
	}
	return loginResponse{AccessToken: token, TokenType: "CB2", ProofKey: cnf, ExpiresAt: exp}, nil
}

func (s *service) me(w http.ResponseWriter, r *http.Request) {
	claims, err := s.authenticate(r)
	if err != nil {
		s.refuse(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, meResponse{Subject: claims["sub"], TokenID: claims["jti"], ExpiresAt: claims["exp"]})
}

// authenticate checks the access token of the Authorization header and
// the holder proof of the CB2-Proof header against this very request.
// The target the proof must name is built from the configured origin,
// never from the Host header the client sent.
func (s *service) authenticate(r *http.Request) (map[string]any, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "CB2 ")
	if !ok || token == "" {
		return nil, errNoToken
	}
	htu, err := cb2.NormalizeTarget(s.origin + r.URL.Path)
	if err != nil {
		return nil, err
	}
	return cb2.TokenOpen(s.key, token, cb2.Rules{
		Issuer:        cb2.String(s.origin),
		Audience:      cb2.String(audience),
		Now:           cb2.Int64(s.now().Unix()),
		ClockSkew:     cb2.Int64(int64(clockSkew / time.Second)),
		RequireCnf:    true,
		Proof:         r.Header.Get("CB2-Proof"),
		Request:       &cb2.HolderRequest{HTM: r.Method, HTU: htu},
		ProofLifetime: cb2.Int64(int64(proofLifetime / time.Second)),
		ProofReplay:   s.proofs.firstUse,
	}, nil)
}

func (s *service) refuse(w http.ResponseWriter, r *http.Request, err error) {
	var verdict *cb2.Error
	switch {
	case errors.Is(err, errNoToken):
		w.Header().Set("WWW-Authenticate", `CB2 realm="cb2-example"`)
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing_token"})
	case errors.As(err, &verdict) && verdict.Code != cb2.CodeInternal:
		s.log.Info("request refused", "path", r.URL.Path, "verdict", verdict.Name)
		w.Header().Set("WWW-Authenticate", `CB2 realm="cb2-example", error="`+verdict.Name+`"`)
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: verdict.Name})
	default:
		s.log.Error("authenticate", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
