#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
static int cmp(const void* a, const void* b) { double x = *(const double*)a, y = *(const double*)b; return (x > y) - (x < y); }
int main(void) {
    const char* names[] = {"ML-DSA-44", "ML-DSA-65", "Falcon-padded-512", "Falcon-512", "MAYO-1", "MAYO-2", "OV-Is", "OV-Ip", "SNOVA_24_5_4", "SNOVA_25_8_3"};
    uint8_t msg[217]; memset(msg, 'a', sizeof msg);
    printf("%-18s %8s %8s %10s %10s\n", "scheme", "sig B", "pk B", "sign us", "verify us");
    for (size_t k = 0; k < sizeof names / sizeof *names; ++k) {
        OQS_SIG* s = OQS_SIG_new(names[k]);
        if (!s) { printf("%-18s not enabled\n", names[k]); continue; }
        uint8_t* pk = malloc(s->length_public_key); uint8_t* sk = malloc(s->length_secret_key); uint8_t* sig = malloc(s->length_signature);
        OQS_SIG_keypair(s, pk, sk);
        enum { N = 201 };
        double ts[N], tv[N]; size_t len = 0;
        for (int i = 0; i < N; ++i) {
            double a = now_us(); OQS_SIG_sign(s, sig, &len, msg, sizeof msg, sk); double b = now_us();
            if (OQS_SIG_verify(s, msg, sizeof msg, sig, len, pk) != OQS_SUCCESS) { printf("verify failed\n"); return 1; }
            double c = now_us(); ts[i] = b - a; tv[i] = c - b;
        }
        qsort(ts, N, sizeof *ts, cmp); qsort(tv, N, sizeof *tv, cmp);
        printf("%-18s %8zu %8zu %10.1f %10.1f\n", names[k], s->length_signature, s->length_public_key, ts[N / 2], tv[N / 2]);
        OQS_SIG_free(s); free(pk); free(sk); free(sig);
    }
}
