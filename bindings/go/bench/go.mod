module github.com/Crdzbird/cb2/bindings/go/bench

go 1.24.0

replace github.com/Crdzbird/cb2/bindings/go => ../

require (
	aidanwoods.dev/go-paseto v1.6.0
	github.com/Crdzbird/cb2/bindings/go v0.0.0-00010101000000-000000000000
	github.com/golang-jwt/jwt/v5 v5.3.1
)

require (
	aidanwoods.dev/go-result v0.3.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
