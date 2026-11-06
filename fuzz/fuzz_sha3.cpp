/**
 * Differential libFuzzer target for cb2's Keccak (detail/sha3.hpp)
 * against OpenSSL's EVP SHA3-256 and SHAKE256.
 *
 * The first two bytes of the input choose a SHAKE256 output length of 0
 * to 4095 bytes, so outputs cross the 136-byte rate many times; the rest
 * is the message, whose length crosses it as the corpus grows. Both
 * digests must equal OpenSSL's byte for byte, and a SHAKE256 output must
 * be a prefix of every longer output of the same message.
 *
 * Build with -DCB2_FUZZ=ON (LLVM clang); run:
 *   ./cb2_fuzz_sha3 -max_total_time=120
 */

#include <cb2/detail/sha3.hpp>

#include <openssl/evp.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

using cb2::detail::Keccak;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

std::vector<uint8_t> openssl(const EVP_MD* md, const uint8_t* in, std::size_t n, std::size_t out_len, bool xof) {
    std::vector<uint8_t> out(out_len);
    if (out_len == 0) return out;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned len = 0;
    require(ctx != nullptr && md != nullptr);
    require(EVP_DigestInit_ex(ctx, md, nullptr) == 1);
    require(EVP_DigestUpdate(ctx, in, n) == 1);
    require(xof ? EVP_DigestFinalXOF(ctx, out.data(), out_len) == 1
                : EVP_DigestFinal_ex(ctx, out.data(), &len) == 1 && len == out_len);
    EVP_MD_CTX_free(ctx);
    return out;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const std::size_t out_len = (static_cast<std::size_t>(data[0]) << 8 | data[1]) & 0x0fff;
    const uint8_t* msg = data + 2;
    const std::size_t n = size - 2;

    uint8_t digest[32];
    Keccak::sha3_256(digest, msg, n);
    static const EVP_MD* const sha3 = EVP_MD_fetch(nullptr, "SHA3-256", nullptr);
    static const EVP_MD* const shake = EVP_MD_fetch(nullptr, "SHAKE256", nullptr);
    const auto ref = openssl(sha3, msg, n, 32, false);
    require(std::memcmp(digest, ref.data(), 32) == 0);

    std::vector<uint8_t> xof(out_len + 1, 0xAA);
    Keccak::shake256(xof.data(), out_len, msg, n);
    require(xof[out_len] == 0xAA);
    xof.resize(out_len);
    require(xof == openssl(shake, msg, n, out_len, true));

    if (out_len > 0) {
        const std::size_t shorter = n % out_len;
        std::vector<uint8_t> prefix(shorter + 1, 0xAA);
        Keccak::shake256(prefix.data(), shorter, msg, n);
        require(prefix[shorter] == 0xAA);
        require(std::memcmp(prefix.data(), xof.data(), shorter) == 0);
    }
    return 0;
}
