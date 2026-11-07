// Package bench compares the Go binding of cb2 with golang-jwt and
// go-paseto on one claims payload: issuing a token, and checking it with
// a validating parse that verifies the signature or tag and the issuer,
// audience, expiry and issued-at claims, then reads a custom claim.
//
// It is a separate module so that the binding's own go.mod needs no JWT
// or PASETO dependency. Run it from this directory:
//
//	go test -run '^$' -bench . -benchmem -benchtime 1s -count 10 | tee new.txt
//	go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e new.txt
package bench
