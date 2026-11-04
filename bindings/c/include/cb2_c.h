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
 */

#ifndef CB2_C_H
#define CB2_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define CB2_API __declspec(dllexport)
#else
#define CB2_API __attribute__((visibility("default")))
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

/* A replay check: returns 1 to accept the id, 0 to refuse it. */
typedef int (*cb2_replay_fn)(void* user, const char* jti, size_t jti_len);

/* Library */
CB2_API const char* cb2_version(void);
CB2_API int cb2_has_public(void);
CB2_API int cb2_has_seal(void);
CB2_API const char* cb2_error_name(int code);
CB2_API void cb2_free(void* p);
CB2_API void cb2_free_secret(char* s);

/* Local keys */
CB2_API int cb2_local_key_generate(cb2_local_key** out);
CB2_API int cb2_local_key_from_bytes(const uint8_t* bytes, size_t len, cb2_local_key** out);
CB2_API int cb2_local_key_from_paserk(const char* text, size_t len, cb2_local_key** out);
CB2_API char* cb2_local_key_to_paserk(const cb2_local_key* key);
CB2_API char* cb2_local_key_paserk_id(const cb2_local_key* key);
CB2_API char* cb2_local_key_key_id(const cb2_local_key* key);
CB2_API int cb2_local_key_set_key_id(cb2_local_key* key, const char* id, size_t len);
CB2_API void cb2_local_key_clear_key_id(cb2_local_key* key);
CB2_API void cb2_local_key_free(cb2_local_key* key);

/* Signing pairs and their public halves (only when cb2_has_public) */
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

/* Recipient pairs for kcb2.seal (only when cb2_has_seal) */
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
 * assertion. The token comes back as text; the opened message as bytes. */
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
 * library requires. On success *out_claims is the JSON of the claims. */
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

/* Holder proofs (sender constraint): a proof by the client's signing pair
 * for one request and one access token. nonce may be NULL. */
CB2_API int cb2_holder_prove(const cb2_secret_key* client, const char* htm, size_t htm_len,
                             const char* htu, size_t htu_len, const char* nonce, size_t nonce_len,
                             const char* access_token, size_t access_len, const char* jti, size_t jti_len,
                             int64_t now, int64_t lifetime, char** out_proof, size_t* out_len);
CB2_API int cb2_holder_normalize_target(const char* uri, size_t len, char** out);

/* Key wrapping and sealing */
CB2_API int cb2_wrap(const cb2_local_key* wrapping, const cb2_local_key* key, char** out);
CB2_API int cb2_unwrap(const char* text, size_t len, const cb2_local_key* wrapping, cb2_local_key** out);
CB2_API int cb2_seal(const cb2_recipient_public_key* to, const cb2_local_key* key, char** out);
CB2_API int cb2_unseal(const char* text, size_t len, const cb2_recipient_key* by, cb2_local_key** out);

#ifdef __cplusplus
}
#endif

#endif
