package bench

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/golang-jwt/jwt/v5"
)

func jwtFormat(name string, method jwt.SigningMethod, signKey, verifyKey any) format {
	claims := jwt.MapClaims{
		"iss":  issuer,
		"sub":  subject,
		"aud":  audience,
		"exp":  expiresAt.Unix(),
		"iat":  issuedAt.Unix(),
		"jti":  tokenID,
		"role": role,
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{method.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	keyFunc := func(*jwt.Token) (any, error) { return verifyKey, nil }
	return format{
		name: name,
		issue: func() (string, error) {
			return jwt.NewWithClaims(method, claims).SignedString(signKey)
		},
		check: func(t string) error {
			parsed, err := parser.Parse(t, keyFunc)
			if err != nil {
				return err
			}
			if parsed.Claims.(jwt.MapClaims)["role"] != role {
				return errClaim
			}
			return nil
		},
	}
}

func jwtFormats() ([]format, func(), error) {
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, nil, err
	}
	edPublic, edSecret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ecSecret, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []format{
		jwtFormat("jwt.HS256", jwt.SigningMethodHS256, hmacKey, hmacKey),
		jwtFormat("jwt.EdDSA", jwt.SigningMethodEdDSA, edSecret, edPublic),
		jwtFormat("jwt.ES256", jwt.SigningMethodES256, ecSecret, &ecSecret.PublicKey),
	}, func() {}, nil
}
