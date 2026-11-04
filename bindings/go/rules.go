package cb2

// HolderRequest describes the request a holder proof must match.
type HolderRequest struct {
	HTM   string
	HTU   string
	Nonce *string
}

// Rules are the checks a claims token must pass; they mirror the rules
// JSON of cb2_c.h. Pointer fields are sent only when set, so the
// library's defaults apply otherwise. Replay and ProofReplay are the
// replay callbacks and run when non-nil. SeenJTI and ProofSeenJTI are
// the built-in lists for tests and simple stores: a non-nil list, even
// an empty one, turns that check on. A Proof without ProofReplay or
// ProofSeenJTI is refused as rules_incomplete.
type Rules struct {
	Issuer           *string
	Audience         *string
	Subject          *string
	Now              *int64
	ClockSkew        *int64
	RequireExp       *bool
	AllowAnyAudience bool
	AllowAnyIssuer   bool
	MaxTokenBytes    *int64
	MaxLifetime      *int64
	Replay           func(jti string) bool
	SeenJTI          []string
	RequireCnf       bool
	IgnoreCnf        bool
	Proof            string
	Request          *HolderRequest
	ProofLifetime    *int64
	ProofReplay      func(jti string) bool
	ProofSeenJTI     []string
}

// String returns a pointer to s for the optional fields of Rules.
func String(s string) *string {
	return &s
}

// Int64 returns a pointer to v for the optional fields of Rules.
func Int64(v int64) *int64 {
	return &v
}

// Bool returns a pointer to b for the optional fields of Rules.
func Bool(b bool) *bool {
	return &b
}

func put[T any](o map[string]any, key string, v *T) {
	if v != nil {
		o[key] = *v
	}
}

func putFlag(o map[string]any, key string, on bool) {
	if on {
		o[key] = true
	}
}

func putList(o map[string]any, key string, v []string) {
	if v != nil {
		o[key] = v
	}
}

func (r *Rules) object() map[string]any {
	o := map[string]any{}
	put(o, "issuer", r.Issuer)
	put(o, "audience", r.Audience)
	put(o, "subject", r.Subject)
	put(o, "now", r.Now)
	put(o, "clock_skew", r.ClockSkew)
	put(o, "require_exp", r.RequireExp)
	putFlag(o, "allow_any_audience", r.AllowAnyAudience)
	putFlag(o, "allow_any_issuer", r.AllowAnyIssuer)
	put(o, "max_token_bytes", r.MaxTokenBytes)
	put(o, "max_lifetime", r.MaxLifetime)
	putFlag(o, "replay", r.Replay != nil)
	putList(o, "seen_jti", r.SeenJTI)
	putFlag(o, "require_cnf", r.RequireCnf)
	putFlag(o, "ignore_cnf", r.IgnoreCnf)
	if r.Proof != "" {
		o["proof"] = r.Proof
	}
	if r.Request != nil {
		o["request"] = r.Request.object()
	}
	put(o, "proof_lifetime", r.ProofLifetime)
	putList(o, "proof_seen_jti", r.ProofSeenJTI)
	return o
}

func (q *HolderRequest) object() map[string]any {
	o := map[string]any{"htm": q.HTM, "htu": q.HTU}
	put(o, "nonce", q.Nonce)
	return o
}
