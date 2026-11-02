/**
 * libFuzzer target for v5.local and k5.local-wrap.
 *
 * The input is fed to open_into as an untrusted token under a fixed key,
 * with and without an expected footer; the result must be a fail-closed
 * verdict with a wiped output region, or a success whose plaintext
 * re-seals and re-opens. The input is also sealed as a message and must
 * round trip, and one byte chosen by the input is replaced with every
 * other value and must be rejected. Finally the input is unwrapped as a
 * k5.local-wrap string.
 *
 * Build with -DPASETO5_FUZZ=ON (LLVM clang); run:
 *   ./paseto5_fuzz_local -max_total_time=120
 */

#include <paseto5/paseto5.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <vector>

using paseto5::Local;
using paseto5::LocalKey;
using paseto5::Status;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

const LocalKey& key() {
    static const LocalKey k = [] {
        uint8_t raw[32];
        for (int i = 0; i < 32; ++i) raw[i] = static_cast<uint8_t>(7 * i + 3);
        return LocalKey::from_bytes(raw).value();
    }();
    return k;
}

bool wiped(const std::vector<uint8_t>& v) {
    return std::all_of(v.begin(), v.end(), [](uint8_t b) { return b == 0; });
}

void open_untrusted(std::string_view token, std::span<const uint8_t> footer, std::span<const uint8_t> implicit) {
    const std::size_t cap = Local::open_capacity(token.size());
    std::vector<uint8_t> out(cap, 0xAA);
    std::size_t n = 1;
    const Status s = Local::open_into(out, n, token, key(), footer, implicit);
    require(s == Status::ok || s == Status::invalid);
    if (s != Status::ok) {
        require(n == 0);
        require(wiped(out));
        return;
    }
    auto again = Local::seal(key(), {out.data(), n}, footer, implicit);
    require(again.is_ok());
    auto back = Local::open(again.value(), key(), footer, implicit);
    require(back.is_ok() && back.value().size() == n);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const uint8_t footer[] = {'k', 'i', 'd'};
    static const uint8_t implicit[] = {'a', 'u', 'd'};
    const std::string_view token(reinterpret_cast<const char*>(data), size);
    open_untrusted(token, footer, implicit);
    open_untrusted(token, {}, {});
    open_untrusted(token, footer, {});

    auto sealed = Local::seal(key(), {data, size}, footer, implicit);
    require(sealed.is_ok());
    auto opened = Local::open(sealed.value(), key(), footer, implicit);
    require(opened.is_ok() && opened.value().size() == size);
    require(std::equal(opened.value().begin(), opened.value().end(), data));
    require(Local::open(sealed.value(), key(), footer, {}).is_err());

    if (size > 0) {
        std::string bad = sealed.value();
        const std::size_t pos = data[0] % bad.size();
        for (int c = 0; c < 256; ++c) {
            if (static_cast<char>(c) == sealed.value()[pos]) continue;
            bad[pos] = static_cast<char>(c);
            require(Local::open(bad, key(), footer, implicit).is_err());
        }
    }

    (void)paseto5::KeyWrap::unwrap(token, key());
    return 0;
}
