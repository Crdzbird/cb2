/**
 * libFuzzer target for holder proofs (holder.hpp, HolderProof in
 * claims.hpp) against two fixed sender-constrained cb2.local tokens, one
 * bound to a local proof key and, under liboqs, one bound to a client
 * key pair.
 *
 * For each token the input is presented as the proof of a request, both
 * through Token::open and through HolderProof; it must be refused as
 * proof_invalid. The input also names a request, a method and a target
 * split at the first newline: when a proof can be made for it, that
 * proof must open the token for the same request and be refused as
 * proof_mismatch for another method, and when it cannot the refusal must
 * be argument. One character of a valid proof, chosen by the input, is
 * replaced with a value the input chooses and the proof must then be
 * proof_invalid, as must the valid proof of the other mode.
 *
 * Target normalisation must be idempotent on every input it accepts, and
 * its output must carry no query or fragment. An authority with more
 * than one colon outside brackets has no normal form (PROTOCOL.md 13.2),
 * so "https://h:1:443/x" and "https://h:1/x" never share one.
 *
 * Build with -DCB2_FUZZ=ON (LLVM clang); run:
 *   ./cb2_fuzz_holder -max_total_time=120
 */

#include <cb2/cb2.hpp>

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using cb2::Claims;
using cb2::Error;
using cb2::Holder;
using cb2::HolderProof;
using cb2::HolderRequest;
using cb2::LocalKey;
using cb2::Result;
using cb2::Seconds;
using cb2::Token;
using cb2::ValidationRules;

namespace {

constexpr Seconds NOW = 1700000000;

void require(bool ok) {
    if (!ok) std::abort();
}

const LocalKey& key() {
    static const LocalKey k = [] {
        uint8_t raw[32];
        for (int i = 0; i < 32; ++i) raw[i] = static_cast<uint8_t>(5 * i + 9);
        return LocalKey::from_bytes(raw).value();
    }();
    return k;
}

Claims base_claims() {
    Claims c;
    c.iss = "https://issuer.example";
    c.aud = "api";
    c.sub = "user-1";
    c.exp = NOW + 3600;
    return c;
}

HolderRequest get_me() { return HolderRequest{"GET", "https://api.example/v1/me", std::nullopt}; }

ValidationRules checking(const std::string& proof, const HolderRequest& r) {
    return ValidationRules().at(NOW).expect_issuer("https://issuer.example").expect_audience("api")
        .with_holder_proof(proof, r).with_proof_replay_check([](std::string_view) { return true; });
}

struct Mode {
    std::string token;
    std::function<Result<std::string>(const HolderRequest&, std::string_view)> make;
    std::function<Result<Claims>(const ValidationRules&)> check;
    std::string valid;
};

Mode local_mode() {
    Claims c = base_claims();
    static const LocalKey proof_key = HolderProof::bind_local(c).value();
    Mode m;
    m.token = Token::seal(key(), c).value();
    const std::string token = m.token;
    m.make = [token](const HolderRequest& r, std::string_view jti) {
        return HolderProof::make_local(proof_key, r, token, jti, NOW);
    };
    m.check = [token](const ValidationRules& rules) { return HolderProof::check_local(proof_key, token, rules); };
    m.valid = m.make(get_me(), "p-1").value();
    return m;
}

#ifdef CB2_HAS_PQ
Mode public_mode() {
    static const cb2::SecretKey client = cb2::SecretKey::generate().value();
    Mode m;
    Claims c = base_claims();
    c.cnf = client.public_key().to_paserk();
    m.token = Token::seal(key(), c).value();
    const std::string token = m.token;
    m.make = [token](const HolderRequest& r, std::string_view jti) {
        return HolderProof::make(client, r, token, jti, NOW);
    };
    m.check = [token](const ValidationRules& rules) { return HolderProof::check(client.public_key(), token, rules); };
    m.valid = m.make(get_me(), "p-1").value();
    return m;
}
#endif

const std::vector<Mode>& modes() {
    static const std::vector<Mode> all = [] {
        std::vector<Mode> v;
        v.push_back(local_mode());
#ifdef CB2_HAS_PQ
        v.push_back(public_mode());
#endif
        return v;
    }();
    return all;
}

std::optional<Error> verdict(const Mode& m, const std::string& proof, const HolderRequest& r) {
    auto opened = Token::open(m.token, key(), checking(proof, r));
    auto checked = m.check(checking(proof, r));
    require(opened.is_ok() == checked.is_ok());
    if (opened.is_ok()) return std::nullopt;
    require(opened.error() == checked.error());
    return opened.error();
}

void request_from(const Mode& m, std::string_view text) {
    const std::size_t nl = text.find('\n');
    const std::string method(text.substr(0, nl));
    const std::string target(nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1));
    const HolderRequest r{method, target, std::nullopt};
    auto proof = m.make(r, "p-2");
    if (proof.is_err()) {
        require(proof.error() == Error::argument);
        return;
    }
    require(Holder::normalize_target(target).has_value());
    require(!verdict(m, proof.value(), r).has_value());
    require(verdict(m, proof.value(), HolderRequest{method + "X", target, std::nullopt}) == Error::proof_mismatch);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string text(reinterpret_cast<const char*>(data), size);
    const auto& all = modes();
    for (std::size_t i = 0; i < all.size(); ++i) {
        const Mode& m = all[i];
        require(verdict(m, text, get_me()) == Error::proof_invalid);
        request_from(m, text);
        if (size >= 2) {
            std::string bad = m.valid;
            const std::size_t pos = (static_cast<std::size_t>(data[0]) << 8 | data[1]) % bad.size();
            const char c = size >= 3 ? static_cast<char>(data[2]) : 'A';
            if (c != bad[pos]) {
                bad[pos] = c;
                require(verdict(m, bad, get_me()) == Error::proof_invalid);
            }
        }
        const Mode& other = all[(i + 1) % all.size()];
        if (&other != &m) require(verdict(m, other.valid, get_me()) == Error::proof_invalid);
    }

    if (const auto once = Holder::normalize_target(text); once) {
        require(once->find_first_of("?#") == std::string::npos);
        const auto twice = Holder::normalize_target(*once);
        require(twice.has_value() && *twice == *once);
    }
    return 0;
}
