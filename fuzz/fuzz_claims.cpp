/**
 * libFuzzer target for the claims layer: the strict JSON reader and
 * writer, the RFC 3339 parser, Claims::from_json and the validator, and
 * Token::peek_key_id on arbitrary text. Whatever parses must serialise
 * and parse again to the same thing.
 *
 * Build with -DPASETO5_FUZZ=ON (LLVM clang); run:
 *   ./paseto5_fuzz_claims -max_total_time=120
 */

#include <paseto5/paseto5.hpp>

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

    paseto5::json::Value v;
    if (paseto5::json::Reader::parse(text, v)) {
        std::string out;
        paseto5::json::Writer::value(out, v);
        paseto5::json::Value again;
        require(paseto5::json::Reader::parse(out, again));
        std::string out2;
        paseto5::json::Writer::value(out2, again);
        require(out == out2);
    }

    auto claims = paseto5::Claims::from_json(text);
    if (claims.is_ok()) {
        const std::string j = claims.value().to_json();
        auto back = paseto5::Claims::from_json(j);
        require(back.is_ok());
        require(back.value().to_json() == j);
        (void)paseto5::ValidationRules().at(1700000000).expect_audience("api").check(claims.value());
        (void)paseto5::ValidationRules().allow_missing_exp().with_clock_skew(60).check(claims.value());
    }

    paseto5::Seconds t = 0;
    if (paseto5::Rfc3339::parse(text, t)) {
        paseto5::Seconds t2 = 0;
        require(paseto5::Rfc3339::parse(paseto5::Rfc3339::format(t), t2));
        require(t == t2);
    }

    (void)paseto5::Token::peek_key_id(text);
    return 0;
}
