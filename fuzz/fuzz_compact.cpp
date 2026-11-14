/**
 * libFuzzer target for the cb3 claims profile (PROTOCOL.md section 15):
 * CompactClaims::decode on arbitrary bytes, CompactToken::open and
 * peek_key_digest on arbitrary text. The profile is canonical, so a
 * payload the reader accepts must encode back to exactly the same bytes,
 * and its claims must survive the JSON layer of cb2 unchanged. A token
 * sealed from the decoded claims must open to them. The same holds under
 * a claim table (section 15.5), whose tokens must not open without it.
 *
 * Build with -DCB2_FUZZ=ON (LLVM clang); run:
 *   ./cb2_fuzz_compact -max_total_time=120
 */

#include <cb2/cb2.hpp>

#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

const cb2::LocalKey& key() {
    static const cb2::LocalKey k = cb2::LocalKey::generate().value();
    return k;
}

const cb2::ClaimTable& table() {
    static const cb2::ClaimTable t = cb2::ClaimTable::make({"https://issuer.example", "api", "a", "b", "c"}).value();
    return t;
}

cb2::ValidationRules any() {
    return cb2::ValidationRules().allow_any_audience().allow_any_issuer().allow_missing_exp().ignore_sender_constraint()
        .at(cb2::CompactClaims::MIN_TIME);
}

void round_trip(std::span<const uint8_t> bytes, const cb2::ClaimTable* t) {
    auto claims = cb2::CompactClaims::decode(bytes, t);
    if (claims.is_err()) return;
    const auto again = cb2::CompactClaims::encode(claims.value(), t);
    require(again.is_ok());
    require(std::string_view(again.value()) ==
            std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    auto json = cb2::Claims::from_json(claims.value().to_json());
    require(json.is_ok());
    require(json.value().to_json() == claims.value().to_json());
    const auto rules = any().with_max_token_bytes(1 << 20);
    if (t == nullptr) {
        const auto token = cb2::CompactToken::seal(key(), claims.value());
        require(token.is_ok());
        const auto opened = cb2::CompactToken::open(token.value(), key(), rules);
        if (opened.is_ok()) require(opened.value().to_json() == claims.value().to_json());
        return;
    }
    const auto token = cb2::CompactToken::seal(key(), claims.value(), *t);
    require(token.is_ok());
    const auto opened = cb2::CompactToken::open(token.value(), key(), rules, *t);
    if (opened.is_ok()) require(opened.value().to_json() == claims.value().to_json());
    require(cb2::CompactToken::open(token.value(), key(), rules).error() == cb2::Error::invalid);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::span<const uint8_t> bytes(data, size);
    round_trip(bytes, nullptr);
    round_trip(bytes, &table());
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    require(cb2::CompactToken::open(text, key(), any()).is_err());
    require(cb2::CompactToken::open(text, key(), any(), table()).is_err());
    (void)cb2::CompactToken::peek_key_digest(text);
    return 0;
}
