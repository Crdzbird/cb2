/*
 * The JWT rows of cb2_c_bench, through libjwt 3.
 *
 * A builder holds the key and the claims (iss, sub, aud, jti, scope as
 * strings, iat and exp stamped at each call), so one call issues a
 * token. A checker holds the key, the expected issuer and audience, and
 * checks the expiry, so one call is a validating decode.
 */
#include "bench.h"

#include <jwt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct jwt_ctx {
    jwk_set_t* keys;
    jwt_builder_t* builder;
    jwt_checker_t* checker;
    char* token;
};

static int claim(jwt_builder_t* builder, const char* name, const char* value) {
    jwt_value_t v;
    memset(&v, 0, sizeof v);
    v.type = JWT_VALUE_STR;
    v.name = name;
    v.str_val = value;
    return jwt_builder_claim_set(builder, &v) == JWT_VALUE_ERR_NONE ? 0 : -1;
}

static int build_once(void* p) {
    struct jwt_ctx* c = p;
    char* token = jwt_builder_generate(c->builder);
    free(token);
    return token == NULL ? -1 : 0;
}

static int check_once(void* p) {
    struct jwt_ctx* c = p;
    return jwt_checker_verify(c->checker, c->token);
}

static int setup(struct jwt_ctx* c, jwk_key_type_t kty, const char* param, jwt_alg_t alg) {
    const jwk_item_t* key;
    memset(c, 0, sizeof *c);
    c->keys = jwks_create_generate(kty, param, alg, JWK_KEY_NONE);
    if (c->keys == NULL || jwks_error_any(c->keys)) return -1;
    key = jwks_item_get(c->keys, 0);
    c->builder = jwt_builder_new();
    c->checker = jwt_checker_new();
    if (key == NULL || jwks_item_error(key) || c->builder == NULL || c->checker == NULL) return -1;
    if (jwt_builder_setkey(c->builder, alg, key) != 0 || jwt_checker_setkey(c->checker, alg, key) != 0) return -1;
    if (claim(c->builder, "iss", BENCH_ISSUER) != 0 || claim(c->builder, "sub", BENCH_SUBJECT) != 0 ||
        claim(c->builder, "aud", BENCH_AUDIENCE) != 0 || claim(c->builder, "jti", BENCH_JTI) != 0 ||
        claim(c->builder, "scope", "read") != 0)
        return -1;
    if (jwt_builder_enable_iat(c->builder, 1) < 0 || jwt_builder_time_offset(c->builder, JWT_CLAIM_EXP, BENCH_LIFETIME))
        return -1;
    if (jwt_checker_claim_set(c->checker, JWT_CLAIM_ISS, BENCH_ISSUER) != 0 ||
        jwt_checker_claim_set(c->checker, JWT_CLAIM_AUD, BENCH_AUDIENCE) != 0)
        return -1;
    c->token = jwt_builder_generate(c->builder);
    if (c->token == NULL) return -1;
    return check_once(c);
}

static void teardown(struct jwt_ctx* c) {
    free(c->token);
    jwt_checker_free(c->checker);
    jwt_builder_free(c->builder);
    jwks_free(c->keys);
}

static void run(const char* format, jwk_key_type_t kty, const char* param, jwt_alg_t alg) {
    struct jwt_ctx c;
    char reason[256];
    const char* why = "a round trip failed";
    if (setup(&c, kty, param, alg) != 0) {
        if (c.keys != NULL && jwks_error_any(c.keys)) why = jwks_error_msg(c.keys);
        snprintf(reason, sizeof reason, "libjwt says: %s", why);
        bench_skip(format, reason);
        teardown(&c);
        return;
    }
    bench_row(format, "generate", "verify", bench_median_us(build_once, &c), bench_median_us(check_once, &c),
              strlen(c.token));
    teardown(&c);
}

void bench_jwt_local(void) {
    run("JWT HS256", JWK_KEY_TYPE_OCT, "256", JWT_ALG_HS256);
}

void bench_jwt_public(void) {
    run("JWT EdDSA (Ed25519)", JWK_KEY_TYPE_OKP, "Ed25519", JWT_ALG_EDDSA);
    run("JWT ES256", JWK_KEY_TYPE_EC, "P-256", JWT_ALG_ES256);
    run("JWT ML-DSA-65", JWK_KEY_TYPE_AKP, NULL, JWT_ALG_ML_DSA_65);
}
