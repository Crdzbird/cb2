/*
 * cb2_c_bench: cb2 through its C library against JWT (libjwt) and PASETO
 * (libpaseto) on the same claims, each through its own C API.
 *
 * Prints two Markdown tables, shared key and public key formats, with
 * the median microseconds per call to issue a token and to check it, and
 * the token size. A competitor that was not found when the bench was
 * configured prints a row saying so instead of numbers.
 */
#define _POSIX_C_SOURCE 200809L

#include "bench.h"

#include <cb2_c.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDS 101
#define ROUND_NS 2e6
#define WARMUP_NS 3e8
#define MAX_PER_ROUND 1000000L

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static double round_ns(bench_op op, void* ctx, long calls) {
    double start = now_ns();
    long i;
    for (i = 0; i < calls; i++) {
        if (op(ctx) != 0) return -1;
    }
    return now_ns() - start;
}

static int by_value(const void* a, const void* b) {
    double x = *(const double*)a;
    double y = *(const double*)b;
    return (x > y) - (x < y);
}

double bench_median_us(bench_op op, void* ctx) {
    double samples[ROUNDS];
    double took;
    double start;
    long calls = 1;
    int i;
    for (;;) {
        took = round_ns(op, ctx, calls);
        if (took < 0) return -1;
        if (took >= ROUND_NS || calls >= MAX_PER_ROUND) break;
        calls *= 2;
    }
    start = now_ns();
    while (now_ns() - start < WARMUP_NS) {
        if (round_ns(op, ctx, calls) < 0) return -1;
    }
    for (i = 0; i < ROUNDS; i++) {
        took = round_ns(op, ctx, calls);
        if (took < 0) return -1;
        samples[i] = took / (double)calls / 1000.0;
    }
    qsort(samples, ROUNDS, sizeof samples[0], by_value);
    return samples[ROUNDS / 2];
}

static void print_us(double us) {
    if (us < 0) {
        printf(" failed |");
        return;
    }
    printf(" %.2f |", us);
}

void bench_row(const char* format, const char* issue, const char* check, double issue_us, double check_us,
               size_t token_bytes) {
    printf("| %s | %s | %s |", format, issue, check);
    print_us(issue_us);
    print_us(check_us);
    printf(" %zu |\n", token_bytes);
    fflush(stdout);
}

void bench_skip(const char* format, const char* reason) {
    printf("| %s | not measured: %s | | | | |\n", format, reason);
    fflush(stdout);
}

time_t bench_now(void) {
    static time_t fixed = 0;
    if (fixed == 0) fixed = time(NULL);
    return fixed;
}

static void rfc3339(char* buf, size_t cap, time_t at) {
    strftime(buf, cap, "%Y-%m-%dT%H:%M:%S+00:00", gmtime(&at));
}

void bench_claims_text(char* buf, size_t cap) {
    char iat[32];
    char exp[32];
    rfc3339(iat, sizeof iat, bench_now());
    rfc3339(exp, sizeof exp, bench_now() + BENCH_LIFETIME);
    snprintf(buf, cap,
             "{\"iss\":\"" BENCH_ISSUER "\",\"sub\":\"" BENCH_SUBJECT "\",\"aud\":\"" BENCH_AUDIENCE "\","
             "\"exp\":\"%s\",\"iat\":\"%s\",\"jti\":\"" BENCH_JTI "\",\"scope\":\"read\"}",
             exp, iat);
}

static long long days_from_civil(int y, int m, int d) {
    long long era;
    long long yoe;
    long long doy;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}

long long bench_parse_time(const char* text) {
    int y, mo, d, h, mi, s;
    if (text == NULL || strlen(text) != 25 || strcmp(text + 19, "+00:00") != 0) return -1;
    if (sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &s) != 6) return -1;
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

static const char RULES[] = "{\"issuer\":\"" BENCH_ISSUER "\",\"audience\":\"" BENCH_AUDIENCE "\"}";

struct cb2_ctx {
    cb2_local_key* local;
    cb2_secret_key* secret;
    cb2_public_key* verifier;
    char claims[512];
    size_t claims_len;
    char* token;
    size_t token_len;
};

static int seal_once(void* p) {
    struct cb2_ctx* c = p;
    char* token = NULL;
    int rc = cb2_token_seal(c->local, c->claims, c->claims_len, NULL, 0, &token, NULL);
    cb2_free(token);
    return rc;
}

static int open_once(void* p) {
    struct cb2_ctx* c = p;
    char* claims = NULL;
    int rc = cb2_token_open(c->local, c->token, c->token_len, RULES, sizeof RULES - 1, NULL, 0, NULL, NULL, NULL,
                            &claims, NULL);
    cb2_free(claims);
    return rc;
}

static int sign_once(void* p) {
    struct cb2_ctx* c = p;
    char* token = NULL;
    int rc = cb2_token_sign(c->secret, c->claims, c->claims_len, NULL, 0, &token, NULL);
    cb2_free(token);
    return rc;
}

static int verify_once(void* p) {
    struct cb2_ctx* c = p;
    char* claims = NULL;
    int rc = cb2_token_verify(c->verifier, c->token, c->token_len, RULES, sizeof RULES - 1, NULL, 0, NULL, NULL,
                              NULL, &claims, NULL);
    cb2_free(claims);
    return rc;
}

static void bench_cb2_local(void) {
    struct cb2_ctx c;
    int ok;
    memset(&c, 0, sizeof c);
    bench_claims_text(c.claims, sizeof c.claims);
    c.claims_len = strlen(c.claims);
    ok = cb2_local_key_generate(&c.local) == CB2_OK &&
         cb2_token_seal(c.local, c.claims, c.claims_len, NULL, 0, &c.token, &c.token_len) == CB2_OK &&
         open_once(&c) == CB2_OK;
    if (ok)
        bench_row("cb2.local", "seal", "open", bench_median_us(seal_once, &c), bench_median_us(open_once, &c),
                  c.token_len);
    if (!ok) bench_skip("cb2.local", "the round trip failed");
    cb2_free(c.token);
    cb2_local_key_free(c.local);
}

static void bench_cb2_public(void) {
    struct cb2_ctx c;
    int ok;
    if (!cb2_has_public()) {
        bench_skip("cb2.public", "this libcb2_c was built without cb2.public");
        return;
    }
    memset(&c, 0, sizeof c);
    bench_claims_text(c.claims, sizeof c.claims);
    c.claims_len = strlen(c.claims);
    ok = cb2_secret_key_generate(&c.secret) == CB2_OK && cb2_secret_key_public_key(c.secret, &c.verifier) == CB2_OK &&
         cb2_token_sign(c.secret, c.claims, c.claims_len, NULL, 0, &c.token, &c.token_len) == CB2_OK &&
         verify_once(&c) == CB2_OK;
    if (ok)
        bench_row("cb2.public", "sign", "verify", bench_median_us(sign_once, &c), bench_median_us(verify_once, &c),
                  c.token_len);
    if (!ok) bench_skip("cb2.public", "the round trip failed");
    cb2_free(c.token);
    cb2_public_key_free(c.verifier);
    cb2_secret_key_free(c.secret);
}

static void table_head(const char* title) {
    printf("\n%s\n\n", title);
    printf("| format | issue | check | issue (us) | check (us) | token (bytes) |\n");
    printf("|---|---|---|--:|--:|--:|\n");
}

int main(void) {
    printf("cb2_c %s, median of %d rounds after a warm-up, microseconds per call\n", cb2_version(), ROUNDS);
    table_head("Shared key");
    bench_cb2_local();
#ifdef CB2_C_BENCH_JWT
    bench_jwt_local();
#endif
#ifndef CB2_C_BENCH_JWT
    bench_skip("JWT HS256", "libjwt was not found at configure time");
#endif
#ifdef CB2_C_BENCH_PASETO
    bench_paseto_local();
#endif
#ifndef CB2_C_BENCH_PASETO
    bench_skip("PASETO v4.local", "libpaseto was not found at configure time");
#endif
    table_head("Public key");
    bench_cb2_public();
#ifdef CB2_C_BENCH_JWT
    bench_jwt_public();
#endif
#ifndef CB2_C_BENCH_JWT
    bench_skip("JWT EdDSA, ES256", "libjwt was not found at configure time");
#endif
#ifdef CB2_C_BENCH_PASETO
    bench_paseto_public();
#endif
#ifndef CB2_C_BENCH_PASETO
    bench_skip("PASETO v4.public", "libpaseto was not found at configure time");
#endif
    return 0;
}
