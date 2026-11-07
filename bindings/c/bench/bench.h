/*
 * The timing harness and the shared claims of cb2_c_bench.
 *
 * Every format issues a token for the same claims and checks it on the
 * way back, the check being a validating decode: the signature or tag,
 * then the issuer, the audience and the expiry.
 */
#ifndef CB2_C_BENCH_H
#define CB2_C_BENCH_H

#include <stddef.h>
#include <time.h>

#define BENCH_ISSUER "https://issuer.example"
#define BENCH_SUBJECT "user-1"
#define BENCH_AUDIENCE "api"
#define BENCH_JTI "4f1c2a9e-7b1d-4c55-9d0e-2a6b8c3f1e77"
#define BENCH_LIFETIME 600

/* One operation of a row: returns 0 on success. */
typedef int (*bench_op)(void* ctx);

/* The median microseconds per call of op after a warm-up, or -1 when op
 * failed at any point. */
double bench_median_us(bench_op op, void* ctx);

/* Prints one row of the results table. issue_us or check_us below 0
 * prints as a failure. */
void bench_row(const char* format, const char* issue, const char* check, double issue_us, double check_us,
               size_t token_bytes);

/* Prints a row for a format that could not be measured, with the reason. */
void bench_skip(const char* format, const char* reason);

/* The issue and expiry times every format uses, fixed at start-up. */
time_t bench_now(void);

/* The claims as JSON text with RFC 3339 times, the form cb2 and PASETO
 * use, written into buf. */
void bench_claims_text(char* buf, size_t cap);

/* Parses an RFC 3339 time of the form bench_claims_text writes. Returns
 * -1 when the text is not one. */
long long bench_parse_time(const char* text);

/* The competitor rows, built when their library was found. */
void bench_jwt_local(void);
void bench_jwt_public(void);
void bench_paseto_local(void);
void bench_paseto_public(void);

#endif
