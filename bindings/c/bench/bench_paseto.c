/*
 * The PASETO rows of cb2_c_bench, through libpaseto (the kennt fork,
 * which adds v4 to authenticvision/libpaseto).
 *
 * libpaseto encrypts or signs a message and decrypts or verifies one;
 * it leaves the claims to the application. So one check here is what an
 * application has to do with it: decrypt or verify, parse the claims
 * with jansson, and compare the issuer, the audience and the expiry.
 */
#include "bench.h"

#include <jansson.h>
#include <paseto.h>
#include <sodium.h>

#include <string.h>

struct paseto_ctx {
    uint8_t local_key[paseto_v4_LOCAL_KEYBYTES];
    uint8_t public_key[paseto_v4_PUBLIC_PUBLICKEYBYTES];
    uint8_t secret_key[paseto_v4_PUBLIC_SECRETKEYBYTES];
    char claims[512];
    size_t claims_len;
    char* token;
};

static int claims_hold(const uint8_t* msg, size_t len) {
    json_error_t error;
    json_t* root = json_loadb((const char*)msg, len, 0, &error);
    const char* iss = json_string_value(json_object_get(root, "iss"));
    const char* aud = json_string_value(json_object_get(root, "aud"));
    long long exp = bench_parse_time(json_string_value(json_object_get(root, "exp")));
    int ok = iss != NULL && aud != NULL && strcmp(iss, BENCH_ISSUER) == 0 && strcmp(aud, BENCH_AUDIENCE) == 0 &&
             exp > (long long)time(NULL);
    json_decref(root);
    return ok ? 0 : -1;
}

static int encrypt_once(void* p) {
    struct paseto_ctx* c = p;
    char* token = paseto_v4_local_encrypt((const uint8_t*)c->claims, c->claims_len, c->local_key, NULL, 0, NULL, 0,
                                          NULL, 0);
    paseto_free(token);
    return token == NULL ? -1 : 0;
}

static int decrypt_once(void* p) {
    struct paseto_ctx* c = p;
    size_t len = 0;
    uint8_t* msg = paseto_v4_local_decrypt(c->token, &len, c->local_key, NULL, NULL, NULL, 0);
    int rc = msg == NULL ? -1 : claims_hold(msg, len);
    paseto_free(msg);
    return rc;
}

static int sign_once(void* p) {
    struct paseto_ctx* c = p;
    char* token = paseto_v4_public_sign((const uint8_t*)c->claims, c->claims_len, c->secret_key, NULL, 0, NULL, 0);
    paseto_free(token);
    return token == NULL ? -1 : 0;
}

static int verify_once(void* p) {
    struct paseto_ctx* c = p;
    size_t len = 0;
    uint8_t* msg = paseto_v4_public_verify(c->token, &len, c->public_key, NULL, NULL, NULL, 0);
    int rc = msg == NULL ? -1 : claims_hold(msg, len);
    paseto_free(msg);
    return rc;
}

static int setup(struct paseto_ctx* c) {
    uint8_t seed[paseto_v4_PUBLIC_SEEDBYTES];
    memset(c, 0, sizeof *c);
    if (!paseto_init()) return -1;
    bench_claims_text(c->claims, sizeof c->claims);
    c->claims_len = strlen(c->claims);
    randombytes_buf(c->local_key, sizeof c->local_key);
    randombytes_buf(seed, sizeof seed);
    if (!paseto_v4_public_generate_keys(seed, sizeof seed, c->public_key, sizeof c->public_key, c->secret_key,
                                        sizeof c->secret_key))
        return -1;
    sodium_memzero(seed, sizeof seed);
    return 0;
}

void bench_paseto_local(void) {
    struct paseto_ctx c;
    if (setup(&c) == 0)
        c.token = paseto_v4_local_encrypt((const uint8_t*)c.claims, c.claims_len, c.local_key, NULL, 0, NULL, 0,
                                          NULL, 0);
    if (c.token == NULL || decrypt_once(&c) != 0) {
        bench_skip("PASETO v4.local", "libpaseto could not encrypt and decrypt this token");
        paseto_free(c.token);
        return;
    }
    bench_row("PASETO v4.local", "encrypt", "decrypt", bench_median_us(encrypt_once, &c),
              bench_median_us(decrypt_once, &c), strlen(c.token));
    paseto_free(c.token);
    sodium_memzero(&c, sizeof c);
}

void bench_paseto_public(void) {
    struct paseto_ctx c;
    if (setup(&c) == 0)
        c.token = paseto_v4_public_sign((const uint8_t*)c.claims, c.claims_len, c.secret_key, NULL, 0, NULL, 0);
    if (c.token == NULL || verify_once(&c) != 0) {
        bench_skip("PASETO v4.public", "libpaseto could not sign and verify this token");
        paseto_free(c.token);
        return;
    }
    bench_row("PASETO v4.public", "sign", "verify", bench_median_us(sign_once, &c), bench_median_us(verify_once, &c),
              strlen(c.token));
    paseto_free(c.token);
    sodium_memzero(&c, sizeof c);
}
