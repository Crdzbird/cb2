/**
 * libFuzzer target for the claims layer: the strict JSON reader and
 * writer, the RFC 3339 parser, Claims::from_json and the validator, and
 * Token::peek_key_id on arbitrary text. Whatever parses must serialise
 * and parse again to the same thing.
 *
 * Build with -DCB2_FUZZ=ON (LLVM clang); run:
 *   ./cb2_fuzz_claims -max_total_time=120
 */

#include <cb2/cb2.hpp>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);

    cb2::json::Value v;
    if (cb2::json::Reader::parse(text, v)) {
        std::string out;
        cb2::json::Writer::value(out, v);
        cb2::json::Value again;
        require(cb2::json::Reader::parse(out, again));
        std::string out2;
        cb2::json::Writer::value(out2, again);
        require(out == out2);
    }

    auto claims = cb2::Claims::from_json(text);
    if (claims.is_ok()) {
        const std::string j = claims.value().to_json();
        auto back = cb2::Claims::from_json(j);
        require(back.is_ok());
        require(back.value().to_json() == j);
        (void)cb2::ValidationRules().at(1700000000).expect_audience("api").allow_any_issuer().check(claims.value());
        (void)cb2::ValidationRules().allow_missing_exp().with_clock_skew(60).allow_any_audience()
            .allow_any_issuer().with_replay_check([](std::string_view) { return false; }).check(claims.value());
        (void)cb2::ValidationRules().check(claims.value());
    }

    cb2::Seconds t = 0;
    if (cb2::Rfc3339::parse(text, t)) {
        cb2::Seconds t2 = 0;
        require(cb2::Rfc3339::parse(cb2::Rfc3339::format(t), t2));
        require(t == t2);
    }

    (void)cb2::Token::peek_key_id(text);
    return 0;
}
