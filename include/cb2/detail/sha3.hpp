#pragma once

/**
 * SHA3-256 and SHAKE256 (FIPS 202) on Keccak-f[1600], the two functions
 * X-Wing needs: SHAKE256 expands the recipient seed and SHA3-256 is the
 * combiner. They are written here rather than taken from liboqs because
 * liboqs keeps its SHA3 internal: a static liboqs happens to carry the
 * symbols, a shared one (Homebrew's, most distributions') hides them.
 *
 * Both functions share the 136-byte rate of a 512-bit capacity and
 * differ only in the domain byte, 0x06 for SHA3 and 0x1f for SHAKE.
 * Nothing branches on the data, only on lengths, which are public; the
 * state is wiped after use because it holds seeds and shared secrets.
 * Checked by tests/test_sha3.cpp against hashlib's FIPS 202 outputs and,
 * through X-Wing, against the draft's test vectors.
 */

#include <sodium.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace cb2::detail {

class Keccak {
public:
    static constexpr std::size_t RATE = 136;

    static void sha3_256(uint8_t out[32], const uint8_t* in, std::size_t n) noexcept { sponge(in, n, 0x06, out, 32); }

    static void shake256(uint8_t* out, std::size_t out_len, const uint8_t* in, std::size_t n) noexcept {
        sponge(in, n, 0x1f, out, out_len);
    }

private:
    static constexpr uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static constexpr int ROT[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
    static constexpr int LANE[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    /// Keccak-f[1600]: theta, rho and pi, chi, iota, 24 rounds.
    static void permute(uint64_t a[25]) noexcept {
        uint64_t c[5];
        for (int round = 0; round < 24; ++round) {
            for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; ++x) {
                const uint64_t d = c[(x + 4) % 5] ^ std::rotl(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
            }
            uint64_t carry = a[1];
            for (int i = 0; i < 24; ++i) {
                const uint64_t next = a[LANE[i]];
                a[LANE[i]] = std::rotl(carry, ROT[i]);
                carry = next;
            }
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; ++x) c[x] = a[y + x];
                for (int x = 0; x < 5; ++x) a[y + x] = c[x] ^ (~c[(x + 1) % 5] & c[(x + 2) % 5]);
            }
            a[0] ^= RC[round];
        }
        sodium_memzero(c, sizeof c);
    }

    static void absorb_block(uint64_t a[25], const uint8_t* p) noexcept {
        for (std::size_t i = 0; i < RATE / 8; ++i) {
            uint64_t lane = 0;
            for (std::size_t b = 0; b < 8; ++b) lane |= static_cast<uint64_t>(p[8 * i + b]) << (8 * b);
            a[i] ^= lane;
        }
    }

    static void sponge(const uint8_t* in, std::size_t n, uint8_t domain, uint8_t* out, std::size_t out_len) noexcept {
        uint64_t a[25] = {};
        for (; n >= RATE; in += RATE, n -= RATE) {
            absorb_block(a, in);
            permute(a);
        }
        uint8_t last[RATE] = {};
        if (n != 0) std::memcpy(last, in, n);
        last[n] ^= domain;
        last[RATE - 1] ^= 0x80;
        absorb_block(a, last);
        permute(a);
        for (;;) {
            const std::size_t k = out_len < RATE ? out_len : RATE;
            for (std::size_t i = 0; i < k; ++i) out[i] = static_cast<uint8_t>(a[i / 8] >> (8 * (i % 8)));
            out += k;
            out_len -= k;
            if (out_len == 0) break;
            permute(a);
        }
        sodium_memzero(a, sizeof a);
        sodium_memzero(last, sizeof last);
    }
};

}
