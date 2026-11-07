/*
 * cb2_c_example: a short tour of the cb2 C library from a plain C program.
 *
 *   cb2_c_example [all|local|public|refuse|holder]
 *
 *   local   issue a cb2.local claims token and open it
 *   public  sign a cb2.public claims token and verify it (when the
 *           library was built with cb2.public)
 *   refuse  show the verdicts for a wrong audience, a tampered token and
 *           an expired token
 *   holder  bind a cb2.local access token to a proof key, prove possession
 *           for one request and check the proof, then replay it
 *
 * With no argument every step runs. The exit status is 0 when every step
 * behaved as described and 1 otherwise.
 */

#include <cb2_c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ISSUER "https://issuer.example"
#define AUDIENCE "api"

static int report(const char* step, int code) {
    fprintf(stderr, "%s failed: %s\n", step, cb2_error_name(code));
    return 1;
}

/* The claims of a token that expires in ten minutes. */
static void make_claims(char* buf, size_t cap, const char* extra) {
    time_t exp = time(NULL) + 600;
    char when[32];
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%S+00:00", gmtime(&exp));
    snprintf(buf, cap,
             "{\"iss\":\"" ISSUER "\",\"sub\":\"user-1\",\"aud\":\"" AUDIENCE "\",\"exp\":\"%s\","
             "\"jti\":\"token-1\",\"scope\":\"read\"%s}",
             when, extra);
}

static const char RULES[] = "{\"issuer\":\"" ISSUER "\",\"audience\":\"" AUDIENCE "\"}";

static int step_local(void) {
    cb2_local_key* key = NULL;
    char claims[512];
    char* token = NULL;
    size_t token_len = 0;
    char* opened = NULL;
    int rc = cb2_local_key_generate(&key);
    if (rc != CB2_OK) return report("local key", rc);
    make_claims(claims, sizeof claims, "");
    rc = cb2_token_seal(key, claims, strlen(claims), NULL, 0, &token, &token_len);
    if (rc == CB2_OK) rc = cb2_token_open(key, token, token_len, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &opened, NULL);
    if (rc == CB2_OK) {
        printf("local   issued  %.40s... (%zu bytes)\n", token, token_len);
        printf("local   opened  %s\n", opened);
    }
    cb2_free(opened);
    cb2_free(token);
    cb2_local_key_free(key);
    return rc == CB2_OK ? 0 : report("local", rc);
}

static int step_public(void) {
    cb2_secret_key* issuer = NULL;
    cb2_public_key* verifier = NULL;
    char claims[512];
    char* token = NULL;
    size_t token_len = 0;
    char* opened = NULL;
    int rc;
    if (!cb2_has_public()) {
        printf("public  skipped: this library was built without cb2.public\n");
        return 0;
    }
    rc = cb2_secret_key_generate(&issuer);
    if (rc == CB2_OK) rc = cb2_secret_key_public_key(issuer, &verifier);
    if (rc == CB2_OK) {
        make_claims(claims, sizeof claims, "");
        rc = cb2_token_sign(issuer, claims, strlen(claims), NULL, 0, &token, &token_len);
    }
    if (rc == CB2_OK)
        rc = cb2_token_verify(verifier, token, token_len, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &opened, NULL);
    if (rc == CB2_OK) {
        printf("public  signed  %.40s... (%zu bytes)\n", token, token_len);
        printf("public  opened  %s\n", opened);
    }
    cb2_free(opened);
    cb2_free(token);
    cb2_public_key_free(verifier);
    cb2_secret_key_free(issuer);
    return rc == CB2_OK ? 0 : report("public", rc);
}

/* Opens token under rules and checks that the verdict is the expected one. */
static int expect(const cb2_local_key* key, const char* token, size_t len, const char* rules, int want, const char* what) {
    char* opened = NULL;
    int rc = cb2_token_open(key, token, len, rules, strlen(rules), NULL, 0, NULL, NULL, NULL, &opened, NULL);
    cb2_free(opened);
    printf("refuse  %-16s %s\n", what, cb2_error_name(rc));
    return rc == want ? 0 : 1;
}

static int step_refuse(void) {
    cb2_local_key* key = NULL;
    char claims[512];
    char* token = NULL;
    size_t token_len = 0;
    int bad = 0;
    int rc = cb2_local_key_generate(&key);
    if (rc != CB2_OK) return report("refuse key", rc);
    make_claims(claims, sizeof claims, "");
    rc = cb2_token_seal(key, claims, strlen(claims), NULL, 0, &token, &token_len);
    if (rc != CB2_OK) {
        cb2_local_key_free(key);
        return report("refuse seal", rc);
    }
    bad |= expect(key, token, token_len, "{\"issuer\":\"" ISSUER "\",\"audience\":\"billing\"}", CB2_AUDIENCE_MISMATCH,
                  "wrong audience");
    bad |= expect(key, token, token_len, "{\"issuer\":\"" ISSUER "\",\"audience\":\"" AUDIENCE "\",\"now\":4102444800}",
                  CB2_EXPIRED, "in the year 2100");
    token[20] = token[20] == 'A' ? 'B' : 'A';
    bad |= expect(key, token, token_len, RULES, CB2_INVALID, "one byte changed");
    cb2_free(token);
    cb2_local_key_free(key);
    return bad;
}

/* A proof replay store: remembers proof ids, refuses one it has seen. */
struct seen_ids {
    char ids[4][64];
    int count;
};

static int remember_proof(void* user, const char* jti, size_t len) {
    struct seen_ids* seen = user;
    int i;
    for (i = 0; i < seen->count; i++) {
        if (strlen(seen->ids[i]) == len && memcmp(seen->ids[i], jti, len) == 0) return 0;
    }
    if (seen->count == 4 || len >= sizeof seen->ids[0]) return 0;
    memcpy(seen->ids[seen->count], jti, len);
    seen->ids[seen->count][len] = '\0';
    seen->count++;
    return 1;
}

static int check_proof(const cb2_local_key* issuer, const char* access, size_t access_len, const char* proof,
                       struct seen_ids* seen) {
    char rules[2048];
    char* opened = NULL;
    int rc;
    snprintf(rules, sizeof rules,
             "{\"issuer\":\"" ISSUER "\",\"audience\":\"" AUDIENCE "\",\"proof\":\"%s\","
             "\"request\":{\"htm\":\"GET\",\"htu\":\"https://api.example/v1/me\"}}",
             proof);
    rc = cb2_token_open(issuer, access, access_len, rules, strlen(rules), NULL, 0, NULL, remember_proof, seen, &opened,
                        NULL);
    cb2_free(opened);
    return rc;
}

static int step_holder(void) {
    cb2_local_key* issuer = NULL;
    cb2_local_key* proof_key = NULL;
    cb2_local_key* client = NULL;
    char* cnf = NULL;
    char extra[128];
    char claims[512];
    char* access = NULL;
    size_t access_len = 0;
    char* proof = NULL;
    char* opened = NULL;
    struct seen_ids seen = {{{0}}, 0};
    int first = CB2_INTERNAL;
    int again = CB2_INTERNAL;
    int bare = CB2_INTERNAL;
    int rc = cb2_local_key_generate(&issuer);
    if (rc == CB2_OK) rc = cb2_local_key_generate(&proof_key);
    if (rc == CB2_OK) {
        cnf = cb2_local_key_to_paserk(proof_key);
        rc = cnf == NULL ? CB2_INTERNAL : CB2_OK;
    }
    if (rc == CB2_OK) {
        snprintf(extra, sizeof extra, ",\"cnf\":\"%s\"", cnf);
        make_claims(claims, sizeof claims, extra);
        rc = cb2_token_seal(issuer, claims, strlen(claims), NULL, 0, &access, &access_len);
    }
    if (rc == CB2_OK) rc = cb2_local_key_from_paserk(cnf, strlen(cnf), &client);
    if (rc == CB2_OK)
        rc = cb2_holder_prove_local(client, "GET", 3, "https://api.example/v1/me", 25, NULL, 0, access, access_len,
                                    "proof-1", 7, (int64_t)time(NULL), 60, &proof, NULL);
    if (rc == CB2_OK) {
        bare = cb2_token_open(issuer, access, access_len, RULES, strlen(RULES), NULL, 0, NULL, NULL, NULL, &opened, NULL);
        first = check_proof(issuer, access, access_len, proof, &seen);
        again = check_proof(issuer, access, access_len, proof, &seen);
        printf("holder  proof   %.40s... (%zu bytes)\n", proof, strlen(proof));
        printf("holder  token without a proof  %s\n", cb2_error_name(bare));
        printf("holder  token with the proof   %s\n", cb2_error_name(first));
        printf("holder  the same proof again   %s\n", cb2_error_name(again));
    }
    cb2_free(opened);
    cb2_free(proof);
    cb2_free(access);
    cb2_free_secret(cnf);
    cb2_local_key_free(client);
    cb2_local_key_free(proof_key);
    cb2_local_key_free(issuer);
    if (rc != CB2_OK) return report("holder", rc);
    return bare == CB2_MISSING_PROOF && first == CB2_OK && again == CB2_PROOF_REPLAYED ? 0 : 1;
}

int main(int argc, char** argv) {
    const char* which = argc > 1 ? argv[1] : "all";
    int all = strcmp(which, "all") == 0;
    int bad = 0;
    if (cb2_abi_version() != CB2_C_ABI_VERSION) {
        fprintf(stderr, "libcb2_c has ABI %d, this program was built for %d\n", cb2_abi_version(), CB2_C_ABI_VERSION);
        return 1;
    }
    if (!all && strcmp(which, "local") != 0 && strcmp(which, "public") != 0 && strcmp(which, "refuse") != 0 &&
        strcmp(which, "holder") != 0) {
        fprintf(stderr, "usage: %s [all|local|public|refuse|holder]\n", argv[0]);
        return 2;
    }
    printf("cb2_c %s (ABI %d), cb2.public %s\n", cb2_version(), cb2_abi_version(), cb2_has_public() ? "yes" : "no");
    if (all || strcmp(which, "local") == 0) bad |= step_local();
    if (all || strcmp(which, "public") == 0) bad |= step_public();
    if (all || strcmp(which, "refuse") == 0) bad |= step_refuse();
    if (all || strcmp(which, "holder") == 0) bad |= step_holder();
    fputs(bad ? "something went wrong\n" : "every step behaved as expected\n", stdout);
    return bad;
}
