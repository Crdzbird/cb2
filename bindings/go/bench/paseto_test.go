package bench

import (
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
)

var errIssuedInFuture = errors.New("bench: token issued in the future")

func notIssuedInFuture(t paseto.Token) error {
	iat, err := t.GetIssuedAt()
	if err != nil {
		return err
	}
	if iat.After(time.Now()) {
		return errIssuedInFuture
	}
	return nil
}

func pasetoRole(t *paseto.Token, err error) error {
	if err != nil {
		return err
	}
	got, err := t.GetString("role")
	if err != nil {
		return err
	}
	if got != role {
		return errClaim
	}
	return nil
}

func pasetoFormats() ([]format, func(), error) {
	token := paseto.NewToken()
	token.SetIssuer(issuer)
	token.SetSubject(subject)
	token.SetAudience(audience)
	token.SetExpiration(expiresAt)
	token.SetIssuedAt(issuedAt)
	token.SetJti(tokenID)
	token.SetString("role", role)

	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy(issuer), paseto.ForAudience(audience), notIssuedInFuture)

	local := paseto.NewV4SymmetricKey()
	secret := paseto.NewV4AsymmetricSecretKey()
	public := secret.Public()
	return []format{{
		name:  "paseto.v4.local",
		issue: func() (string, error) { return token.V4Encrypt(local, nil), nil },
		check: func(t string) error { return pasetoRole(parser.ParseV4Local(local, t, nil)) },
	}, {
		name:  "paseto.v4.public",
		issue: func() (string, error) { return token.V4Sign(secret, nil), nil },
		check: func(t string) error { return pasetoRole(parser.ParseV4Public(public, t, nil)) },
	}}, func() {}, nil
}
