// Package cb2 is the Go binding of cb2 (Cryptographically Bound tokens,
// version 2), a post-quantum token library, through its C ABI
// (libcb2_c, header cb2_c.h).
//
// # Tokens
//
// Two kinds of token exist. A cb2.local token is encrypted and
// authenticated under a symmetric LocalKey (XChaCha20 and keyed
// BLAKE3); a cb2.public token is signed with a SecretKey (Ed25519 and
// ML-DSA-65, both required) and checked with its PublicKey. Raw tokens
// (LocalSeal, LocalOpen, PublicSign, PublicVerify) carry any bytes.
// Claims tokens (TokenSeal, TokenSign, TokenOpen, TokenVerify) carry a
// JSON object with the registered claims as strings, times as RFC 3339,
// and are checked against Rules on the way back: issuer, audience,
// expiry, replay and, for sender-constrained tokens, a holder proof.
//
// # Compact claims tokens
//
// The experimental compact formats (CompactSeal, CompactOpen,
// CompactSign, CompactVerify) use the same keys, claims and Rules as the
// claims tokens, but carry the claims as CBOR and bind the key id as a
// KeyDigest, which makes a local token about half as long. They may
// change before they are released. A cb2 token never opens as a compact
// one, nor the reverse. PeekKeyDigest and KeyDigestOf pick a key. A
// ClaimTable, shared by the issuer and its verifiers like a key, makes
// the token shorter still when passed to the WithTable forms.
//
// # Holder proofs
//
// An access token whose cnf claim holds a key is refused unless the
// request carries a proof made with that key for this request and this
// token. In the local mode the issuer writes a fresh kcb2.local proof
// key into cnf and hands the same key to the client, which signs each
// request with HolderProveLocal; the verifier passes the proof and the
// request to TokenOpen through Rules.Proof and Rules.Request. The public
// mode uses the client's own SecretKey and HolderProve.
//
// # Keys and their lifetime
//
// Every key wraps a C handle. Call Close when a key is no longer needed;
// it is idempotent, and calls in flight on the key finish before the
// handle is released. Later calls fail with ErrClosed. A finalizer
// closes a key that becomes unreachable without Close, as a safety net
// rather than a policy: the key material then stays in C memory until
// the garbage collector runs. Keys are safe for concurrent use by
// multiple goroutines, Close and SetKeyID included. Functions that
// return a key (PublicKey, Unwrap, Unseal) return a new key with its own
// lifetime.
//
// Serialized secret keys (ToPaserk on LocalKey, SecretKey and
// RecipientKey) are wiped on the C side, but a Go string cannot be
// wiped; keep such strings short-lived.
//
// # Errors
//
// Every verdict of the library is an *Error carrying the library's Code
// and stable Name. Test for one verdict with errors.Is and the Err
// sentinels (errors.Is(err, ErrExpired)), or read the code with
// errors.As. Errors from encoding claims or rules to JSON are wrapped
// with %w and are not *Error values.
//
// # Linking
//
// The package uses cgo and links libcb2_c. Inside the cb2 repository it
// finds the header in bindings/c/include and the library in
// build/bindings/c with no configuration. Elsewhere, build with the tag
// cb2_pkgconfig to resolve the library through pkg-config (module
// cb2_c), or point CGO_CFLAGS and CGO_LDFLAGS at an installed copy. The
// module README describes both.
//
// # Versions
//
// The module path is github.com/Crdzbird/cb2/bindings/go. Being in a
// subdirectory of the repository, its versions are tags of the form
// bindings/go/vX.Y.Z; the module stays at major version 0 until its API
// is declared stable.
package cb2
