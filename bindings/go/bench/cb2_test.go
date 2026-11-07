package bench

import (
	"errors"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

func cb2Claims() map[string]any {
	return map[string]any{
		"iss":  issuer,
		"sub":  subject,
		"aud":  audience,
		"exp":  expiresAt.Format(time.RFC3339),
		"iat":  issuedAt.Format(time.RFC3339),
		"jti":  tokenID,
		"role": role,
	}
}

func cb2Rules() cb2.Rules {
	return cb2.Rules{Issuer: cb2.String(issuer), Audience: cb2.String(audience)}
}

func cb2Role(claims map[string]any, err error) error {
	if err != nil {
		return err
	}
	if claims["role"] != role {
		return errClaim
	}
	return nil
}

func cb2Formats() ([]format, func(), error) {
	claims := cb2Claims()
	local, err := cb2.GenerateLocalKey()
	if err != nil {
		return nil, nil, err
	}
	fs := []format{{
		name:  "cb2.local",
		issue: func() (string, error) { return cb2.TokenSeal(local, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.TokenOpen(local, t, cb2Rules(), nil)) },
	}, {
		name:  "compact.local",
		issue: func() (string, error) { return cb2.CompactSeal(local, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.CompactOpen(local, t, cb2Rules(), nil)) },
	}}
	table, err := cb2.NewClaimTable([]string{issuer, audience})
	if err != nil {
		local.Close()
		return nil, nil, err
	}
	fs = append(fs, format{
		name:  "compact.local.table",
		issue: func() (string, error) { return cb2.CompactSealWithTable(local, table, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.CompactOpenWithTable(local, table, t, cb2Rules(), nil)) },
	})
	secret, err := cb2.GenerateSecretKey()
	if errors.Is(err, cb2.ErrUnavailable) {
		return fs, func() {
			local.Close()
			table.Close()
		}, nil
	}
	if err != nil {
		local.Close()
		table.Close()
		return nil, nil, err
	}
	public, err := secret.PublicKey()
	if err != nil {
		local.Close()
		table.Close()
		secret.Close()
		return nil, nil, err
	}
	fs = append(fs, format{
		name:  "cb2.public",
		issue: func() (string, error) { return cb2.TokenSign(secret, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.TokenVerify(public, t, cb2Rules(), nil)) },
	}, format{
		name:  "compact.public",
		issue: func() (string, error) { return cb2.CompactSign(secret, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.CompactVerify(public, t, cb2Rules(), nil)) },
	}, format{
		name:  "compact.public.table",
		issue: func() (string, error) { return cb2.CompactSignWithTable(secret, table, claims, nil) },
		check: func(t string) error { return cb2Role(cb2.CompactVerifyWithTable(public, table, t, cb2Rules(), nil)) },
	})
	return fs, func() {
		local.Close()
		table.Close()
		secret.Close()
		public.Close()
	}, nil
}
