package bench

import (
	"errors"
	"time"
)

const (
	issuer   = "https://issuer.example"
	subject  = "user-1"
	audience = "api"
	tokenID  = "4f1c2a9e7b3d4c58"
	role     = "admin"
)

var (
	issuedAt  = time.Now().UTC().Truncate(time.Second)
	expiresAt = issuedAt.Add(time.Hour)
	errClaim  = errors.New("bench: custom claim missing after a parse")
)

type format struct {
	name  string
	issue func() (string, error)
	check func(token string) error
}

func formats() ([]format, func(), error) {
	var all []format
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	builders := []func() ([]format, func(), error){cb2Formats, jwtFormats, pasetoFormats}
	for _, build := range builders {
		fs, c, err := build()
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		all = append(all, fs...)
		closers = append(closers, c)
	}
	return all, closeAll, nil
}
