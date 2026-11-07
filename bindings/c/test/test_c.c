/*
 * The C ABI exercised from C: keys, raw tokens, claims tokens with
 * rules and both replay callbacks, holder proofs of both modes, key wrapping and
 * sealing, the boundary contract of the header, and every verdict the
 * bridges rely on. Exits non-zero on the first failed check.
 */

#include "cb2_c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);              \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static int seen_count = 0;
static char seen[8][64];

static int remember(void* user, const char* jti, size_t len) {
    (void)user;
    for (int i = 0; i < seen_count; i++) {
        if (strlen(seen[i]) == len && memcmp(seen[i], jti, len) == 0) return 0;
    }
    if (seen_count < 8 && len < 64) {
        memcpy(seen[seen_count], jti, len);
        seen[seen_count][len] = '\0';
        seen_count++;
    }
    return 1;
}

static int accept_all(void* user, const char* jti, size_t len) {
    (void)user; (void)jti; (void)len;
    return 1;
}

static const char* CLAIMS = "{\"iss\":\"https://issuer.example\",\"sub\":\"user-1\",\"aud\":\"api\",\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\",\"role\":\"admin\"}";
static const char* RULES = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000}";

static void test_local(void) {
    cb2_local_key* k = NULL;
    CHECK(cb2_local_key_generate(&k) == CB2_OK && k != NULL);
    char* paserk = cb2_local_key_to_paserk(k);
    CHECK(paserk != NULL && strncmp(paserk, "kcb2.local.", 11) == 0 && strlen(paserk) == 54);
    char* id = cb2_local_key_paserk_id(k);
    char* kid = cb2_local_key_key_id(k);
    CHECK(id != NULL && kid != NULL && strcmp(id, kid) == 0 && strncmp(id, "kcb2.lid.", 9) == 0);
    cb2_local_key* same = NULL;
    CHECK(cb2_local_key_from_paserk(paserk, strlen(paserk), &same) == CB2_OK);
    char* id2 = cb2_local_key_paserk_id(same);
    CHECK(strcmp(id, id2) == 0);
    cb2_free(id2);
    cb2_free(kid);
    cb2_free_secret(paserk);

    const uint8_t msg[] = "hello";
    const uint8_t footer[] = "{\"kid\":\"x\"}";
    char* token = NULL;
    size_t tlen = 0;
    CHECK(cb2_local_seal(k, msg, 5, footer, sizeof footer - 1, NULL, 0, &token, &tlen) == CB2_OK);
    CHECK(token != NULL && tlen == strlen(token) && strncmp(token, "cb2.local.", 10) == 0);
    uint8_t* out = NULL;
    size_t olen = 0;
    CHECK(cb2_local_open(same, token, tlen, footer, sizeof footer - 1, NULL, 0, 0, &out, &olen) == CB2_OK);
    CHECK(olen == 5 && memcmp(out, msg, 5) == 0);
    cb2_free(out);
    CHECK(cb2_local_open(same, token, tlen, NULL, 0, NULL, 0, 0, &out, &olen) == CB2_INVALID);
    token[tlen - 1] = token[tlen - 1] == 'A' ? 'B' : 'A';
    CHECK(cb2_local_open(same, token, tlen, footer, sizeof footer - 1, NULL, 0, 0, &out, &olen) == CB2_INVALID);
    cb2_free(token);

    char* ct = NULL;
    CHECK(cb2_token_seal(k, CLAIMS, strlen(CLAIMS), NULL, 0, &ct, &tlen) == CB2_OK);
    char* claims = NULL;
    size_t clen = 0;
    CHECK(cb2_token_open(k, ct, tlen, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_OK);
    CHECK(claims != NULL && strstr(claims, "\"role\":\"admin\"") != NULL && strstr(claims, "\"jti\":\"id-1\"") != NULL);
    cb2_free(claims);
    char* peeked = NULL;
    CHECK(cb2_peek_key_id(ct, tlen, &peeked) == CB2_OK && peeked != NULL && strcmp(peeked, id) == 0);
    cb2_free(peeked);
    CHECK(cb2_token_open(k, ct, tlen, "{}", 2, NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_RULES_INCOMPLETE);
    const char* other = "{\"issuer\":\"https://issuer.example\",\"audience\":\"other\",\"now\":1700000000}";
    CHECK(cb2_token_open(k, ct, tlen, other, strlen(other), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_AUDIENCE_MISMATCH);
    const char* late = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":4102444801}";
    CHECK(cb2_token_open(k, ct, tlen, late, strlen(late), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_EXPIRED);
    const char* replay = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"replay\":true}";
    CHECK(cb2_token_open(k, ct, tlen, replay, strlen(replay), NULL, 0, remember, NULL, NULL, &claims, &clen) == CB2_OK);
    cb2_free(claims);
    CHECK(cb2_token_open(k, ct, tlen, replay, strlen(replay), NULL, 0, remember, NULL, NULL, &claims, &clen) == CB2_REPLAYED);
    const char* seen_rules = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"seen_jti\":[\"id-1\"]}";
    CHECK(cb2_token_open(k, ct, tlen, seen_rules, strlen(seen_rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_REPLAYED);
    const char* lifetime = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"max_lifetime\":60}";
    CHECK(cb2_token_open(k, ct, tlen, lifetime, strlen(lifetime), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_LIFETIME_EXCEEDED);
    CHECK(cb2_token_open(k, ct, tlen, "not json", 8, NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_ARGUMENT);
    CHECK(cb2_token_seal(k, "{\"sub\":\"a\\u200bb\",\"exp\":\"2099-01-01T00:00:00+00:00\"}", 50, NULL, 0, &claims, &clen) == CB2_ARGUMENT);
    cb2_free(ct);

    cb2_local_key* wrapping = NULL;
    CHECK(cb2_local_key_generate(&wrapping) == CB2_OK);
    char* wrapped = NULL;
    CHECK(cb2_wrap(wrapping, k, &wrapped) == CB2_OK && strncmp(wrapped, "kcb2.local-wrap.", 16) == 0 && strlen(wrapped) == 144);
    cb2_local_key* unwrapped = NULL;
    CHECK(cb2_unwrap(wrapped, strlen(wrapped), wrapping, &unwrapped) == CB2_OK);
    char* id3 = cb2_local_key_paserk_id(unwrapped);
    CHECK(strcmp(id3, id) == 0);
    cb2_free(id3);
    CHECK(cb2_unwrap(wrapped, strlen(wrapped), k, &unwrapped) == CB2_INVALID);
    cb2_free(wrapped);
    cb2_local_key_free(unwrapped);
    cb2_local_key_free(wrapping);

    CHECK(cb2_local_key_set_key_id(k, "rotation-1", 10) == CB2_OK);
    kid = cb2_local_key_key_id(k);
    CHECK(kid != NULL && strcmp(kid, "rotation-1") == 0);
    cb2_free(kid);
    CHECK(cb2_local_key_set_key_id(k, "a\xe2\x80\x8b", 4) == CB2_ARGUMENT);
    cb2_local_key_clear_key_id(k);
    CHECK(cb2_local_key_key_id(k) == NULL);
    cb2_free(id);
    cb2_local_key_free(same);
    cb2_local_key_free(k);
    uint8_t weak[32];
    memset(weak, 7, 32);
    CHECK(cb2_local_key_from_bytes(weak, 32, &k) == CB2_ARGUMENT);
    CHECK(strcmp(cb2_error_name(CB2_ARGUMENT), "argument") == 0 && strcmp(cb2_error_name(0), "ok") == 0);
    CHECK(strcmp(cb2_error_name(CB2_PROOF_REPLAYED), "proof_replayed") == 0 && strcmp(cb2_error_name(99), "unknown") == 0);
}

/* The local holder mode: the issuer writes a fresh proof key into cnf of a
 * cb2.local token, the client proves with the same key. */
static void test_holder_local(void) {
    cb2_local_key* k = NULL;
    cb2_local_key* proof_key = NULL;
    cb2_local_key* stranger = NULL;
    CHECK(cb2_local_key_generate(&k) == CB2_OK);
    CHECK(cb2_local_key_generate(&proof_key) == CB2_OK);
    CHECK(cb2_local_key_generate(&stranger) == CB2_OK);
    char* cnf = cb2_local_key_to_paserk(proof_key);
    char bound[512];
    snprintf(bound, sizeof bound, "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":\"2099-01-01T00:00:00+00:00\",\"cnf\":\"%s\"}", cnf);
    char* access = NULL;
    size_t alen = 0;
    char* claims = NULL;
    size_t clen = 0;
    CHECK(cb2_token_seal(k, bound, strlen(bound), NULL, 0, &access, &alen) == CB2_OK);
    CHECK(cb2_token_open(k, access, alen, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_MISSING_PROOF);
    cb2_local_key* client = NULL;
    CHECK(cb2_local_key_from_paserk(cnf, strlen(cnf), &client) == CB2_OK);
    char* proof = NULL;
    size_t plen = 0;
    CHECK(cb2_holder_prove_local(client, "GET", 3, "https://api.example/v1/me", 25, NULL, 0, access, alen, "p-1", 3, 1700000000, 60, &proof, &plen) == CB2_OK);
    CHECK(proof != NULL && strncmp(proof, "cb2.holder-local.", 17) == 0 && plen == strlen(proof) && plen < 450);
    char rules[2048];
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"HTTPS://API.EXAMPLE:443/v1/me?x=1\"}}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_RULES_INCOMPLETE);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, accept_all, NULL, &claims, &clen) == CB2_OK);
    cb2_free(claims);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"POST\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_MISMATCH);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[\"p-1\"]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_REPLAYED);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000100,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_EXPIRED);
    cb2_free(proof);
    CHECK(cb2_holder_prove_local(stranger, "GET", 3, "https://api.example/v1/me", 25, NULL, 0, access, alen, "p-2", 3, 1700000000, 60, &proof, &plen) == CB2_OK);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_INVALID);
    cb2_free(proof);
    CHECK(cb2_holder_prove_local(client, "GET", 3, "not a uri", 9, NULL, 0, access, alen, "p-3", 3, 1700000000, 60, &proof, &plen) == CB2_ARGUMENT);
    if (cb2_has_public()) {
        cb2_secret_key* issuer = NULL;
        CHECK(cb2_secret_key_generate(&issuer) == CB2_OK);
        char* signed_token = NULL;
        size_t slen = 0;
        CHECK(cb2_token_sign(issuer, bound, strlen(bound), NULL, 0, &signed_token, &slen) == CB2_ARGUMENT);
        cb2_secret_key_free(issuer);
    }
    cb2_free(access);
    cb2_free(cnf);
    cb2_local_key_free(client);
    cb2_local_key_free(stranger);
    cb2_local_key_free(proof_key);
    cb2_local_key_free(k);
}

static void test_public(void) {
    if (!cb2_has_public()) {
        printf("cb2.public unavailable in this build; skipping\n");
        return;
    }
    cb2_secret_key* sk = NULL;
    CHECK(cb2_secret_key_generate(&sk) == CB2_OK);
    cb2_public_key* pk = NULL;
    CHECK(cb2_secret_key_public_key(sk, &pk) == CB2_OK);
    char* pub = cb2_public_key_to_paserk(pk);
    CHECK(pub != NULL && strlen(pub) == 2658);
    cb2_public_key* pk2 = NULL;
    CHECK(cb2_public_key_from_paserk(pub, strlen(pub), &pk2) == CB2_OK);
    char* token = NULL;
    size_t tlen = 0;
    CHECK(cb2_token_sign(sk, CLAIMS, strlen(CLAIMS), NULL, 0, &token, &tlen) == CB2_OK);
    char* claims = NULL;
    size_t clen = 0;
    CHECK(cb2_token_verify(pk2, token, tlen, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_OK);
    cb2_free(claims);
    cb2_secret_key* stranger = NULL;
    CHECK(cb2_secret_key_generate(&stranger) == CB2_OK);
    cb2_public_key* spk = NULL;
    CHECK(cb2_secret_key_public_key(stranger, &spk) == CB2_OK);
    CHECK(cb2_token_verify(spk, token, tlen, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_INVALID);
    cb2_free(token);

    /* A bound token and its holder proof: the client is "stranger". */
    char* client_pub = cb2_public_key_to_paserk(spk);
    char bound[4096];
    snprintf(bound, sizeof bound, "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":\"2099-01-01T00:00:00+00:00\",\"cnf\":\"%s\"}", client_pub);
    cb2_local_key* k = NULL;
    CHECK(cb2_local_key_generate(&k) == CB2_OK);
    char* access = NULL;
    size_t alen = 0;
    CHECK(cb2_token_seal(k, bound, strlen(bound), NULL, 0, &access, &alen) == CB2_OK);
    CHECK(cb2_token_open(k, access, alen, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_MISSING_PROOF);
    char* proof = NULL;
    size_t plen = 0;
    CHECK(cb2_holder_prove(stranger, "GET", 3, "https://api.example/v1/me", 25, NULL, 0, access, alen, "p-1", 3, 1700000000, 60, &proof, &plen) == CB2_OK);
    CHECK(proof != NULL && strncmp(proof, "cb2.holder-public.", 18) == 0);
    char rules[8192];
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"HTTPS://API.EXAMPLE:443/v1/me?x=1\"}}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_RULES_INCOMPLETE);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, accept_all, NULL, &claims, &clen) == CB2_OK);
    cb2_free(claims);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"POST\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_MISMATCH);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[\"p-1\"]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_REPLAYED);
    snprintf(rules, sizeof rules, "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000100,\"proof\":\"%s\",\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"},\"proof_seen_jti\":[]}", proof);
    CHECK(cb2_token_open(k, access, alen, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_PROOF_EXPIRED);
    const char* ignore = "{\"issuer\":\"https://issuer.example\",\"audience\":\"api\",\"now\":1700000000,\"ignore_cnf\":true}";
    CHECK(cb2_token_open(k, access, alen, ignore, strlen(ignore), NULL, 0, NULL, NULL, NULL, &claims, &clen) == CB2_OK);
    cb2_free(claims);
    char* norm = NULL;
    CHECK(cb2_holder_normalize_target("HTTPS://API.Example:443/a?b#c", 29, &norm) == CB2_OK && strcmp(norm, "https://api.example/a") == 0);
    cb2_free(norm);
    CHECK(cb2_holder_normalize_target("nope", 4, &norm) == CB2_ARGUMENT);
    cb2_free(proof);
    cb2_free(access);
    cb2_free(client_pub);
    cb2_free(pub);
    cb2_local_key_free(k);
    cb2_public_key_free(spk);
    cb2_secret_key_free(stranger);
    cb2_public_key_free(pk2);
    cb2_public_key_free(pk);
    cb2_secret_key_free(sk);
}

static void test_seal(void) {
    if (!cb2_has_seal()) {
        printf("kcb2.seal unavailable in this build; skipping\n");
        return;
    }
    cb2_recipient_key* r = NULL;
    CHECK(cb2_recipient_key_generate(&r) == CB2_OK);
    cb2_recipient_public_key* rp = NULL;
    CHECK(cb2_recipient_key_public_key(r, &rp) == CB2_OK);
    char* rec = cb2_recipient_public_key_to_paserk(rp);
    CHECK(rec != NULL && strlen(rec) == 1637 && strncmp(rec, "kcb2.recipient.", 15) == 0);
    char* secret = cb2_recipient_key_to_paserk(r);
    CHECK(secret != NULL && strlen(secret) == 65);
    cb2_recipient_key* r2 = NULL;
    CHECK(cb2_recipient_key_from_paserk(secret, strlen(secret), &r2) == CB2_OK);
    cb2_free_secret(secret);
    cb2_local_key* k = NULL;
    CHECK(cb2_local_key_generate(&k) == CB2_OK);
    char* sealed = NULL;
    CHECK(cb2_seal(rp, k, &sealed) == CB2_OK && strlen(sealed) == 1632);
    cb2_local_key* back = NULL;
    CHECK(cb2_unseal(sealed, strlen(sealed), r2, &back) == CB2_OK);
    char* a = cb2_local_key_paserk_id(k);
    char* b = cb2_local_key_paserk_id(back);
    CHECK(strcmp(a, b) == 0);
    cb2_free(a);
    cb2_free(b);
    cb2_recipient_key* other = NULL;
    CHECK(cb2_recipient_key_generate(&other) == CB2_OK);
    CHECK(cb2_unseal(sealed, strlen(sealed), other, &back) == CB2_INVALID);
    char* rid = cb2_recipient_public_key_paserk_id(rp);
    char* rid2 = cb2_recipient_key_paserk_id(r2);
    CHECK(strcmp(rid, rid2) == 0 && strncmp(rid, "kcb2.rid.", 9) == 0);
    cb2_free(rid);
    cb2_free(rid2);
    cb2_free(sealed);
    cb2_free(rec);
    cb2_local_key_free(back);
    cb2_local_key_free(k);
    cb2_recipient_key_free(other);
    cb2_recipient_key_free(r2);
    cb2_recipient_public_key_free(rp);
    cb2_recipient_key_free(r);
}

/* The boundary contract of cb2_c.h: the version query, NULL handles and
 * outputs refused, NULL accepted by every free function, and an output
 * left as it was when a call fails. */
static void test_boundary(void) {
    CHECK(cb2_abi_version() == CB2_C_ABI_VERSION);
    char version[32];
    snprintf(version, sizeof version, "%d.%d.%d", CB2_C_VERSION_MAJOR, CB2_C_VERSION_MINOR, CB2_C_VERSION_PATCH);
    CHECK(strcmp(cb2_version(), version) == 0);
    CHECK(cb2_local_key_generate(NULL) == CB2_ARGUMENT);
    CHECK(cb2_local_key_to_paserk(NULL) == NULL && cb2_local_key_paserk_id(NULL) == NULL && cb2_local_key_key_id(NULL) == NULL);
    CHECK(cb2_local_key_set_key_id(NULL, "a", 1) == CB2_ARGUMENT);
    cb2_local_key_clear_key_id(NULL);
    cb2_local_key_free(NULL);
    cb2_secret_key_free(NULL);
    cb2_public_key_free(NULL);
    cb2_recipient_key_free(NULL);
    cb2_recipient_public_key_free(NULL);
    cb2_free(NULL);
    cb2_free_secret(NULL);
    char* token = NULL;
    size_t len = 0;
    uint8_t* msg = NULL;
    CHECK(cb2_local_seal(NULL, (const uint8_t*)"m", 1, NULL, 0, NULL, 0, &token, &len) == CB2_ARGUMENT);
    CHECK(cb2_token_open(NULL, "x", 1, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &token, &len) == CB2_ARGUMENT);
    CHECK(cb2_peek_key_id("x", 1, NULL) == CB2_ARGUMENT);
    CHECK(cb2_holder_normalize_target("https://a.example/", 18, NULL) == CB2_ARGUMENT);
    cb2_local_key* k = NULL;
    CHECK(cb2_local_key_generate(&k) == CB2_OK);
    CHECK(cb2_local_seal(k, (const uint8_t*)"m", 1, NULL, 0, NULL, 0, NULL, &len) == CB2_ARGUMENT);
    CHECK(cb2_local_seal(k, (const uint8_t*)"m", 1, NULL, 0, NULL, 0, &token, &len) == CB2_OK);
    CHECK(cb2_local_open(k, token, len, NULL, 0, NULL, 0, 0, &msg, NULL) == CB2_ARGUMENT);
    CHECK(cb2_wrap(k, NULL, &token) == CB2_ARGUMENT && token != NULL);
    char* kept = token;
    CHECK(cb2_local_open(k, "cb2.local.x", 11, NULL, 0, NULL, 0, 0, &msg, &len) == CB2_INVALID && msg == NULL);
    CHECK(cb2_token_open(k, "cb2.local.x", 11, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &token, &len) != CB2_OK);
    CHECK(token == kept);
    cb2_free(token);
    cb2_local_key_free(k);
}

int main(void) {
    printf("cb2_c %s, public %d, seal %d\n", cb2_version(), cb2_has_public(), cb2_has_seal());
    test_boundary();
    test_local();
    test_holder_local();
    test_public();
    test_seal();
    if (failures != 0) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("cb2_c: all checks passed\n");
    return 0;
}
