/**
 * libFuzzer target for v5.public.
 *
 * The input is fed to verify_into as an untrusted token under a fixed
 * key pair, with and without an expected footer; the verdict must be
 * fail-closed with a wiped output region or a success whose message
 * re-signs and re-verifies. Every input is also signed as a message and
 * must round trip, and one byte of the signature region chosen by the
 * input is flipped and must be rejected.
 *
 * Build with -DPASETO5_FUZZ=ON (LLVM clang); run:
 *   ./paseto5_fuzz_public -max_total_time=120
 */

#include <paseto5/paseto5.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <vector>

#ifdef PASETO5_HAS_PQ

using paseto5::Public;
using paseto5::PublicKey;
using paseto5::SecretKey;
using paseto5::Status;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

const SecretKey& secret() {
    static const SecretKey sk = SecretKey::generate().value();
    return sk;
}

const PublicKey& pub() {
    static const PublicKey pk = secret().public_key();
    return pk;
}

bool wiped(const std::vector<uint8_t>& v) {
    return std::all_of(v.begin(), v.end(), [](uint8_t b) { return b == 0; });
}

void verify_untrusted(std::string_view token, std::span<const uint8_t> footer, std::span<const uint8_t> implicit) {
    const std::size_t cap = Public::verify_capacity(token.size(), footer.size(), implicit.size());
    std::vector<uint8_t> out(cap, 0xAA);
    std::size_t n = 1;
    const Status s = Public::verify_into(out, n, token, pub(), footer, implicit);
    require(s == Status::ok || s == Status::invalid);
    if (s != Status::ok) {
        require(n == 0);
        require(wiped(out));
        return;
    }
    auto again = Public::sign(secret(), {out.data(), n}, footer, implicit);
    require(again.is_ok());
    require(Public::verify(again.value(), pub(), footer, implicit).is_ok());
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const uint8_t footer[] = {'k', 'i', 'd'};
    static const uint8_t implicit[] = {'a', 'u', 'd'};
    const std::string_view token(reinterpret_cast<const char*>(data), size);
    verify_untrusted(token, footer, implicit);
    verify_untrusted(token, {}, {});

    auto signed_token = Public::sign(secret(), {data, size}, footer, implicit);
    require(signed_token.is_ok());
    auto verified = Public::verify(signed_token.value(), pub(), footer, implicit);
    require(verified.is_ok() && verified.value().size() == size);
    require(std::equal(verified.value().begin(), verified.value().end(), data));
    require(Public::verify(signed_token.value(), pub(), footer, {}).is_err());

    if (size > 0) {
        std::string bad = signed_token.value();
        const std::size_t body_end = bad.find('.', 10);
        const std::size_t sig_text = Public::SIG_BYTES * 4 / 3;
        const std::size_t pos = body_end - 1 - (data[0] % sig_text);
        bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
        require(Public::verify(bad, pub(), footer, implicit).is_err());
    }
    return 0;
}

#else

extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }

#endif
