/*
 * cb2_c: the C ABI of cb2, the one surface every language bridge sits on.
 *
 * Keys are opaque handles created by the generate, from_bytes and
 * from_paserk functions and released with the matching free function.
 * Every function that produces bytes or text allocates the result with
 * malloc and hands it to the caller, who releases it with cb2_free, or with
 * cb2_free_secret for the strings that carry key material (kcb2.local,
 * kcb2.secret, kcb2.recipient-secret), which wipes before freeing.
 *
 * Every fallible function returns 0 on success or a positive error code;
 * cb2_error_name turns a code into the stable name the library uses
 * ("invalid", "expired", ...). The verdicts and their order are exactly
 * those of docs/PROTOCOL.md; the claims layer takes and returns claims as
 * JSON text and takes its rules as JSON text (see cb2_token_open).
 *
 * Text arguments are byte strings with explicit lengths, UTF-8 where the
 * library requires it; nothing is NUL-terminated on input. Results that
 * are text come back NUL-terminated as well as with a length.
 *
 * Ownership and lifetime
 *
 *   Inputs are borrowed for the duration of the call only. The library
 *   keeps no pointer to any argument after it returns, so the caller may
 *   free or reuse every input buffer as soon as the call is over. An input
 *   pointer may be NULL when its length is 0.
 *
 *   A handle (cb2_local_key and the other key types) belongs to the caller
 *   from the moment a constructor stores it in *out until the caller
 *   passes it to the matching free function, exactly once. Handles are
 *   independent: a public key taken from a signing pair, or a key opened
 *   from a wrapped or sealed text, stays valid after its source is freed.
 *   Every free function accepts NULL and does nothing with it.
 *
 *   An output written through a char**, uint8_t** or handle pointer is
 *   written only on success (CB2_OK); on failure it is left as it was, so
 *   an earlier value the caller still holds is never lost or overwritten.
 *   Where a result length is reported through a size_t*, it excludes the
 *   terminating NUL.
 *
 *   A returned char* or uint8_t* is a fresh malloc'd block owned by the
 *   caller and released with cb2_free; the ones carrying key material are
 *   released with cb2_free_secret instead. The const char* that
 *   cb2_version and cb2_error_name return are static and never freed.
 *
 *   A NULL handle or a NULL output pointer is refused with CB2_ARGUMENT by
 *   the functions that return a code, and with NULL by those that return a
 *   pointer.
 *
 * Threads
 *
 *   The library holds no mutable global state; every function is
 *   reentrant. A handle may be used from several threads at once by every
 *   function that takes it as const. cb2_*_set_key_id, cb2_*_clear_key_id
 *   and the free functions change the handle and need exclusive access.
 *   The replay callbacks run on the calling thread, during the call.
 *
 * ABI stability
 *
 *   The shared library carries CB2_C_ABI_VERSION as its SOVERSION
 *   (libcb2_c.so.0, libcb2_c.0.dylib). Within one ABI version the surface
 *   only grows: functions and error codes are added, never removed, and no
 *   signature, struct layout, error code value or ownership rule changes.
 *   Every type that crosses the boundary is a scalar, a pointer with an
 *   explicit length, or an opaque handle, so the library's internals can
 *   change freely. A program can compare cb2_abi_version with the
 *   CB2_C_ABI_VERSION it was compiled against to detect a mismatched
 *   library at run time.
 */

#ifndef CB2_C_H
#define CB2_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The version of this header and of the library built from it. */
#define CB2_C_VERSION_MAJOR 0
#define CB2_C_VERSION_MINOR 1
#define CB2_C_VERSION_PATCH 0
#define CB2_C_ABI_VERSION 0

/* Define CB2_C_STATIC when linking the static library on Windows. */
#ifndef CB2_API
#if defined(_WIN32)
#if defined(CB2_C_BUILDING)
#define CB2_API __declspec(dllexport)
#elif defined(CB2_C_STATIC)
#define CB2_API
#else
#define CB2_API __declspec(dllimport)
#endif
#else
#define CB2_API __attribute__((visibility("default")))
#endif
#endif

/* Error codes: 0 is success; the others are 1 + the library's Error index. */
enum cb2_code {
    CB2_OK = 0,
    CB2_INVALID = 1,
    CB2_TOO_LARGE = 2,
    CB2_ARGUMENT = 3,
    CB2_RULES_INCOMPLETE = 4,
    CB2_INTERNAL = 5,
    CB2_UNAVAILABLE = 6,
    CB2_CLAIMS_MALFORMED = 7,
    CB2_MISSING_EXP = 8,
    CB2_EXPIRED = 9,
    CB2_NOT_YET_VALID = 10,
    CB2_ISSUED_IN_FUTURE = 11,
    CB2_LIFETIME_EXCEEDED = 12,
    CB2_ISSUER_MISMATCH = 13,
    CB2_AUDIENCE_MISMATCH = 14,
    CB2_SUBJECT_MISMATCH = 15,
    CB2_MISSING_JTI = 16,
    CB2_REPLAYED = 17,
    CB2_MISSING_CNF = 18,
    CB2_MISSING_PROOF = 19,
    CB2_PROOF_INVALID = 20,
    CB2_PROOF_MALFORMED = 21,
    CB2_PROOF_EXPIRED = 22,
    CB2_PROOF_MISMATCH = 23,
    CB2_PROOF_REPLAYED = 24
};

typedef struct cb2_local_key cb2_local_key;
typedef struct cb2_secret_key cb2_secret_key;
typedef struct cb2_public_key cb2_public_key;
typedef struct cb2_recipient_key cb2_recipient_key;
typedef struct cb2_recipient_public_key cb2_recipient_public_key;

/* A replay check: returns 1 to accept the id, 0 to refuse it. jti is
 * borrowed for the duration of the callback and is not NUL-terminated. */
typedef int (*cb2_replay_fn)(void* user, const char* jti, size_t jti_len);

/* Library. cb2_version is the library version as static text ("0.1.0");
 * cb2_abi_version is the CB2_C_ABI_VERSION the library was built with.
 * cb2_has_public and cb2_has_seal are 1 when the build carries cb2.public
 * and kcb2.seal, 0 otherwise; without them the matching functions return
 * CB2_UNAVAILABLE. cb2_error_name returns static text, "unknown" for a
 * code it does not know. cb2_free releases any result of this library;
 * cb2_free_secret wipes a NUL-terminated secret text, then releases it. */
CB2_API const char* cb2_version(void);
CB2_API int cb2_abi_version(void);
CB2_API int cb2_has_public(void);
CB2_API int cb2_has_seal(void);
CB2_API const char* cb2_error_name(int code);
CB2_API void cb2_free(void* p);
CB2_API void cb2_free_secret(char* s);

/* Local keys. to_paserk returns the secret kcb2.local text, released with
 * cb2_free_secret. paserk_id returns the public kcb2.lid identifier.
 * key_id returns the id written into footers, the paserk_id unless one was
 * set, or NULL when it was cleared. The char* results are NULL when the
 * allocation fails. */
CB2_API int cb2_local_key_generate(cb2_local_key** out);
CB2_API int cb2_local_key_from_bytes(const uint8_t* bytes, size_t len, cb2_local_key** out);
CB2_API int cb2_local_key_from_paserk(const char* text, size_t len, cb2_local_key** out);
CB2_API char* cb2_local_key_to_paserk(const cb2_local_key* key);
CB2_API char* cb2_local_key_paserk_id(const cb2_local_key* key);
CB2_API char* cb2_local_key_key_id(const cb2_local_key* key);
CB2_API int cb2_local_key_set_key_id(cb2_local_key* key, const char* id, size_t len);
CB2_API void cb2_local_key_clear_key_id(cb2_local_key* key);
CB2_API void cb2_local_key_free(cb2_local_key* key);

/* Signing pairs and their public halves (only when cb2_has_public). The
 * secret_key to_paserk text is secret and released with cb2_free_secret;
 * the public texts and ids are released with cb2_free. public_key returns
 * a new handle the caller frees on its own. */
CB2_API int cb2_secret_key_generate(cb2_secret_key** out);
CB2_API int cb2_secret_key_from_bytes(const uint8_t* bytes, size_t len, cb2_secret_key** out);
CB2_API int cb2_secret_key_from_paserk(const char* text, size_t len, cb2_secret_key** out);
CB2_API char* cb2_secret_key_to_paserk(const cb2_secret_key* key);
CB2_API int cb2_secret_key_public_key(const cb2_secret_key* key, cb2_public_key** out);
CB2_API char* cb2_secret_key_key_id(const cb2_secret_key* key);
CB2_API int cb2_secret_key_set_key_id(cb2_secret_key* key, const char* id, size_t len);
CB2_API void cb2_secret_key_clear_key_id(cb2_secret_key* key);
CB2_API void cb2_secret_key_free(cb2_secret_key* key);

CB2_API int cb2_public_key_from_bytes(const uint8_t* bytes, size_t len, cb2_public_key** out);
CB2_API int cb2_public_key_from_paserk(const char* text, size_t len, cb2_public_key** out);
CB2_API char* cb2_public_key_to_paserk(const cb2_public_key* key);
CB2_API char* cb2_public_key_paserk_id(const cb2_public_key* key);
CB2_API char* cb2_public_key_key_id(const cb2_public_key* key);
CB2_API int cb2_public_key_set_key_id(cb2_public_key* key, const char* id, size_t len);
CB2_API void cb2_public_key_clear_key_id(cb2_public_key* key);
CB2_API void cb2_public_key_free(cb2_public_key* key);

/* Recipient pairs for kcb2.seal (only when cb2_has_seal). The
 * recipient_key to_paserk text is secret and released with
 * cb2_free_secret; the others are released with cb2_free. */
CB2_API int cb2_recipient_key_generate(cb2_recipient_key** out);
CB2_API int cb2_recipient_key_from_bytes(const uint8_t* bytes, size_t len, cb2_recipient_key** out);
CB2_API int cb2_recipient_key_from_paserk(const char* text, size_t len, cb2_recipient_key** out);
CB2_API char* cb2_recipient_key_to_paserk(const cb2_recipient_key* key);
CB2_API int cb2_recipient_key_public_key(const cb2_recipient_key* key, cb2_recipient_public_key** out);
CB2_API char* cb2_recipient_key_paserk_id(const cb2_recipient_key* key);
CB2_API void cb2_recipient_key_free(cb2_recipient_key* key);

CB2_API int cb2_recipient_public_key_from_bytes(const uint8_t* bytes, size_t len, cb2_recipient_public_key** out);
CB2_API int cb2_recipient_public_key_from_paserk(const char* text, size_t len, cb2_recipient_public_key** out);
CB2_API char* cb2_recipient_public_key_to_paserk(const cb2_recipient_public_key* key);
CB2_API char* cb2_recipient_public_key_paserk_id(const cb2_recipient_public_key* key);
CB2_API void cb2_recipient_public_key_free(cb2_recipient_public_key* key);

/* Raw tokens: any bytes as the message, an optional footer and implicit
 * assertion. The token comes back as text; the opened message as bytes.
 * out_len is required. The opened message is followed by one 0 byte that
 * out_len does not count, so a text message can be read as a C string.
 * max_token_bytes 0 means the library default. */
CB2_API int cb2_local_seal(const cb2_local_key* key, const uint8_t* msg, size_t msg_len,
                           const uint8_t* footer, size_t footer_len,
                           const uint8_t* implicit, size_t implicit_len,
                           char** out_token, size_t* out_len);
CB2_API int cb2_local_open(const cb2_local_key* key, const char* token, size_t token_len,
                           const uint8_t* footer, size_t footer_len,
                           const uint8_t* implicit, size_t implicit_len,
                           size_t max_token_bytes, uint8_t** out_msg, size_t* out_len);
CB2_API int cb2_public_sign(const cb2_secret_key* key, const uint8_t* msg, size_t msg_len,
                            const uint8_t* footer, size_t footer_len,
                            const uint8_t* implicit, size_t implicit_len,
                            char** out_token, size_t* out_len);
CB2_API int cb2_public_verify(const cb2_public_key* key, const char* token, size_t token_len,
                              const uint8_t* footer, size_t footer_len,
                              const uint8_t* implicit, size_t implicit_len,
                              size_t max_token_bytes, uint8_t** out_msg, size_t* out_len);

/* Claims tokens. claims_json is the payload the library would write: a
 * JSON object with the registered claims as strings (times as RFC 3339)
 * and any custom claims. The key id is bound into the footer.
 *
 * rules_json is an object with these members, every one optional:
 *   now                  Unix seconds; the clock when absent
 *   clock_skew           seconds, default 0
 *   require_exp          bool, default true
 *   allow_any_audience   bool; else "audience" is required
 *   allow_any_issuer     bool; else "issuer" is required
 *   issuer, audience, subject   expected strings
 *   max_token_bytes      default 16384
 *   max_lifetime         seconds; unset by default
 *   replay               bool: run the replay callback on jti
 *   seen_jti             array of ids a built-in replay check refuses
 *                        (for tests and simple stores; "replay" is the
 *                        real one)
 *   require_cnf, ignore_cnf     bool
 *   proof                the holder proof text presented with the request
 *   request              {"htm":..., "htu":..., "nonce":...}
 *   proof_lifetime       seconds, default 60
 *   proof_seen_jti       array of proof ids the built-in proof replay
 *                        check refuses; otherwise the proof callback runs
 * replay and proof_replay are the callbacks; user is passed back to them.
 * A proof without any proof replay check is rules_incomplete, as the
 * library requires. On success *out_claims is the JSON of the claims.
 * The callbacks and user are used only during the call. out_len may be
 * NULL in this group; the text results are NUL-terminated either way. */
CB2_API int cb2_token_seal(const cb2_local_key* key, const char* claims_json, size_t claims_len,
                           const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len);
CB2_API int cb2_token_sign(const cb2_secret_key* key, const char* claims_json, size_t claims_len,
                           const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len);
CB2_API int cb2_token_open(const cb2_local_key* key, const char* token, size_t token_len,
                           const char* rules_json, size_t rules_len,
                           const uint8_t* implicit, size_t implicit_len,
                           cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                           char** out_claims, size_t* out_len);
CB2_API int cb2_token_verify(const cb2_public_key* key, const char* token, size_t token_len,
                             const char* rules_json, size_t rules_len,
                             const uint8_t* implicit, size_t implicit_len,
                             cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                             char** out_claims, size_t* out_len);

/* The key id a token's footer names, unverified; 0 and NULL when none. */
CB2_API int cb2_peek_key_id(const char* token, size_t token_len, char** out_id);

/* Compact claims tokens, the experimental cb3.local and cb3.public
 * formats of docs/PROTOCOL.md section 15. They take and return the same
 * claims JSON and rules JSON as the cb2_token group, and give the same
 * verdicts, but carry the claims as strict CBOR and bind the key id as a
 * CB2_KEY_DIGEST_BYTES digest instead of its text. The issuer refuses
 * with CB2_ARGUMENT what the compact profile cannot carry: a custom
 * number that is not an integer in int64 written in canonical form, a
 * time outside years 0000 to 9999, and a cnf that is not a kcb2.local or
 * kcb2.public key. A cb2 token never opens here and a compact token never
 * opens in the cb2_token group. Holder proofs bind a compact access token
 * exactly as they bind a cb2 one. */
#define CB2_KEY_DIGEST_BYTES 16

CB2_API int cb2_compact_seal(const cb2_local_key* key, const char* claims_json, size_t claims_len,
                             const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len);
CB2_API int cb2_compact_sign(const cb2_secret_key* key, const char* claims_json, size_t claims_len,
                             const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len);
CB2_API int cb2_compact_open(const cb2_local_key* key, const char* token, size_t token_len,
                             const char* rules_json, size_t rules_len,
                             const uint8_t* implicit, size_t implicit_len,
                             cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                             char** out_claims, size_t* out_len);
CB2_API int cb2_compact_verify(const cb2_public_key* key, const char* token, size_t token_len,
                               const char* rules_json, size_t rules_len,
                               const uint8_t* implicit, size_t implicit_len,
                               cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                               char** out_claims, size_t* out_len);

/* The key digest a compact token's footer carries, unverified, as
 * CB2_KEY_DIGEST_BYTES malloc'd bytes; 0 and NULL when the token has none.
 * cb2_compact_key_digest computes the digest of a key id (see the
 * cb2_*_key_id functions), so a verifier holding several keys can pick the
 * one whose digest matches. */
CB2_API int cb2_compact_peek_key_digest(const char* token, size_t token_len, uint8_t** out_digest);
CB2_API int cb2_compact_key_digest(const char* id, size_t len, uint8_t** out_digest);

/* Holder proofs (sender constraint) for one request and one access token;
 * nonce may be NULL. cb2_holder_prove is the public mode, a proof by the
 * client's signing pair (only when cb2_has_public). cb2_holder_prove_local
 * is the local mode, in every build: a proof under the kcb2.local proof key
 * the issuer wrote into cnf of a cb2.local access token and handed to the
 * client with it. The verifier checks either through cb2_token_open or
 * cb2_token_verify with "proof" and "request" in the rules. out_len may be
 * NULL. cb2_holder_normalize_target returns the canonical form of a request
 * target, the one a proof binds. */
CB2_API int cb2_holder_prove(const cb2_secret_key* client, const char* htm, size_t htm_len,
                             const char* htu, size_t htu_len, const char* nonce, size_t nonce_len,
                             const char* access_token, size_t access_len, const char* jti, size_t jti_len,
                             int64_t now, int64_t lifetime, char** out_proof, size_t* out_len);
CB2_API int cb2_holder_prove_local(const cb2_local_key* proof_key, const char* htm, size_t htm_len,
                                   const char* htu, size_t htu_len, const char* nonce, size_t nonce_len,
                                   const char* access_token, size_t access_len, const char* jti, size_t jti_len,
                                   int64_t now, int64_t lifetime, char** out_proof, size_t* out_len);
CB2_API int cb2_holder_normalize_target(const char* uri, size_t len, char** out);

/* Key wrapping and sealing. The wrapped and sealed texts are released with
 * cb2_free; the keys they open to are new handles. */
CB2_API int cb2_wrap(const cb2_local_key* wrapping, const cb2_local_key* key, char** out);
CB2_API int cb2_unwrap(const char* text, size_t len, const cb2_local_key* wrapping, cb2_local_key** out);
CB2_API int cb2_seal(const cb2_recipient_public_key* to, const cb2_local_key* key, char** out);
CB2_API int cb2_unseal(const char* text, size_t len, const cb2_recipient_key* by, cb2_local_key** out);

#ifdef __cplusplus
}
#endif

#endif
