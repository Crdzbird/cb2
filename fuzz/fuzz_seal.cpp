/**
 * libFuzzer target for kcb2.seal and the X-Wing recipient keys.
 *
 * The input is opened as an untrusted kcb2.seal string under a fixed
 * recipient; it must be refused unless it opens to a key that seals and
 * opens again. The input is imported as a recipient public key and as a
 * recipient secret, raw and as kcb2.recipient and kcb2.recipient-secret
 * strings. A string that imports must write back unchanged; a public key
 * must take a seal of a fixed local key, or refuse it as an argument,
 * and the fixed recipient opens that seal exactly when the key is its
 * own; a secret must open what is sealed to its public key. Finally one
 * character of a valid
 * seal, chosen by the input, is replaced with a value the input chooses
 * and the seal must then be refused.
 *
 * Build with -DCB2_FUZZ=ON (LLVM clang); run:
 *   ./cb2_fuzz_seal -max_total_time=120
 */

#include <cb2/cb2.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#ifdef CB2_HAS_SEAL

using cb2::Error;
using cb2::LocalKey;
using cb2::RecipientKey;
using cb2::RecipientPublicKey;
using cb2::Seal;

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

const RecipientKey& recipient() {
    static const RecipientKey k = [] {
        uint8_t raw[32];
        for (int i = 0; i < 32; ++i) raw[i] = static_cast<uint8_t>(11 * i + 5);
        return RecipientKey::from_bytes(raw).value();
    }();
    return k;
}

const LocalKey& local() {
    static const LocalKey k = [] {
        uint8_t raw[32];
        for (int i = 0; i < 32; ++i) raw[i] = static_cast<uint8_t>(3 * i + 1);
        return LocalKey::from_bytes(raw).value();
    }();
    return k;
}

const std::string& sealed() {
    static const std::string s = Seal::seal(recipient().public_key(), local()).value();
    return s;
}

bool same_key(const LocalKey& a, const LocalKey& b) { return a.to_paserk() == b.to_paserk(); }

void unseal_untrusted(std::string_view text) {
    auto opened = Seal::unseal(text, recipient());
    if (opened.is_err()) {
        require(opened.error() == Error::invalid);
        return;
    }
    auto again = Seal::seal(recipient().public_key(), opened.value());
    require(again.is_ok());
    auto back = Seal::unseal(again.value(), recipient());
    require(back.is_ok() && same_key(back.value(), opened.value()));
}

void seal_to_untrusted(const RecipientPublicKey& to) {
    auto s = Seal::seal(to, local());
    require(s.is_ok() || s.error() == Error::argument);
    if (s.is_err()) return;
    require(s.value().size() == Seal::TEXT_BYTES);
    const auto mine = recipient().public_key();
    const bool same = std::equal(to.bytes().begin(), to.bytes().end(), mine.bytes().begin(), mine.bytes().end());
    require(Seal::unseal(s.value(), recipient()).is_ok() == same);
}

void round_trip(const RecipientKey& by) {
    auto s = Seal::seal(by.public_key(), local());
    require(s.is_ok());
    auto back = Seal::unseal(s.value(), by);
    require(back.is_ok() && same_key(back.value(), local()));
    auto clone = by.clone();
    require(clone.public_key().to_paserk() == by.public_key().to_paserk());
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    unseal_untrusted(text);

    if (auto pk = RecipientPublicKey::from_paserk(text); pk.is_ok()) {
        require(pk.value().to_paserk() == text);
        require(!pk.value().paserk_id().empty());
        seal_to_untrusted(pk.value());
    }
    if (auto pk = RecipientPublicKey::from_bytes({data, size}); pk.is_ok()) seal_to_untrusted(pk.value());

    if (auto sk = RecipientKey::from_paserk(text); sk.is_ok()) {
        require(std::string_view(sk.value().to_paserk()) == text);
        round_trip(sk.value());
    }
    if (size >= RecipientKey::BYTES) {
        auto sk = RecipientKey::from_bytes({data, RecipientKey::BYTES});
        require(sk.is_ok());
        round_trip(sk.value());
    }

    if (size >= 2) {
        std::string bad = sealed();
        const std::size_t pos = (static_cast<std::size_t>(data[0]) << 8 | data[1]) % bad.size();
        const char c = size >= 3 ? static_cast<char>(data[2]) : 'A';
        if (c != bad[pos]) {
            bad[pos] = c;
            require(Seal::unseal(bad, recipient()).is_err());
        }
    }
    return 0;
}

#else

extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }

#endif
