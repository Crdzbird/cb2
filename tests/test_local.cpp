#include "test_runner.hpp"
#include "test_util.hpp"

#include <algorithm>
#include <cstring>
#include <string>

using paseto5::Local;
using paseto5::LocalKey;
using paseto5::Status;
using tu::Bytes;

namespace {

LocalKey key_a() { return LocalKey::from_bytes(tu::pattern(32, 0x70)).value(); }
LocalKey key_b() { return LocalKey::from_bytes(tu::pattern(32, 0x90)).value(); }

bool only_token_chars(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.';
    });
}

}

TEST_CASE("local/round trip at many lengths with footer and implicit variations") {
    const LocalKey k = key_a();
    const Bytes footer = tu::bytes_of("{\"kid\":\"kcb2.lid.test\"}");
    const Bytes implicit = tu::bytes_of("{\"audience\":\"api\"}");
    for (size_t n : {0u, 1u, 2u, 3u, 4u, 31u, 32u, 33u, 63u, 64u, 65u, 127u, 128u, 1000u, 4096u, 70000u}) {
        const Bytes msg = tu::pattern(n, 0x11);
        for (int variant = 0; variant < 4; ++variant) {
            const std::span<const uint8_t> f = variant & 1 ? tu::sp(footer) : std::span<const uint8_t>{};
            const std::span<const uint8_t> i = variant & 2 ? tu::sp(implicit) : std::span<const uint8_t>{};
            auto tok = Local::seal(k, msg, f, i);
            REQUIRE(tok.is_ok());
            CHECK(tok.value().size() == Local::token_len(n, f.size()));
            CHECK(tok.value().rfind("cb2.local.", 0) == 0);
            CHECK(only_token_chars(tok.value()));
            CHECK((tok.value().find('.', 10) != std::string::npos) == !f.empty());
            auto back = Local::open(tok.value(), k, f, i);
            REQUIRE(back.is_ok());
            CHECK(Bytes(back.value().begin(), back.value().end()) == msg);
        }
    }
}

TEST_CASE("local/token length and open capacity are exact") {
    CHECK(Local::token_len(0, 0) == 10 + 86);
    CHECK(Local::token_len(1, 0) == 10 + 87);
    CHECK(Local::token_len(0, 1) == 10 + 86 + 1 + 2);
    CHECK(Local::token_len(paseto5::MAX_INPUT_BYTES + 1, 0) == 0);
    CHECK(Local::open_capacity(10) == 0);
    CHECK(Local::open_capacity(96) == 64);
    CHECK(Local::open_capacity(Local::max_token_len() + 1) == 0);
}

TEST_CASE("local/nonces are fresh") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("same");
    auto a = Local::seal(k, msg);
    auto b = Local::seal(k, msg);
    REQUIRE(a.is_ok() && b.is_ok());
    CHECK(a.value() != b.value());
}

TEST_CASE("local/the test nonce hook is deterministic") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("hello");
    const Bytes nonce = tu::pattern(32, 0x01);
    std::string a(Local::token_len(msg.size(), 0), '\0'), b = a;
    size_t na = 0, nb = 0;
    CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(a.data()), a.size()}, na, k, msg, {}, {}, nonce) == Status::ok);
    CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(b.data()), b.size()}, nb, k, msg, {}, {}, nonce) == Status::ok);
    CHECK(na == a.size() && a == b);
    CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(b.data()), b.size()}, nb, k, msg, {}, {}, tu::pattern(31, 1)) == Status::argument);
}

TEST_CASE("local/every byte of a short token tampered is rejected and the output wiped") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("m");
    const Bytes footer = tu::bytes_of("f");
    const Bytes implicit = tu::bytes_of("i");
    auto tok = Local::seal(k, msg, footer, implicit);
    REQUIRE(tok.is_ok());
    const std::string& t = tok.value();
    static constexpr char REPLACEMENTS[] = {'A', 'z', '9', '_', '.', '=', ' '};
    for (size_t pos = 0; pos < t.size(); ++pos) {
        for (const char r : REPLACEMENTS) {
            if (t[pos] == r) continue;
            std::string bad = t;
            bad[pos] = r;
            std::vector<uint8_t> out(Local::open_capacity(bad.size()), 0xAA);
            size_t n = 99;
            const Status s = Local::open_into(out, n, bad, k, footer, implicit);
            CHECK(s == Status::invalid);
            CHECK(n == 0);
            CHECK(std::all_of(out.begin(), out.end(), [](uint8_t b) { return b == 0; }));
        }
    }
    for (size_t cut = 0; cut < t.size(); ++cut) {
        CHECK(Local::open(t.substr(0, cut), k, footer, implicit).is_err());
    }
    CHECK(Local::open(t + "A", k, footer, implicit).is_err());
    CHECK(Local::open(t + ".", k, footer, implicit).is_err());
    CHECK(Local::open(t, k, footer, implicit).is_ok());
}

TEST_CASE("local/wrong key, implicit and footer all fail with the single invalid verdict") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("payload");
    const Bytes footer = tu::bytes_of("footer");
    const Bytes implicit = tu::bytes_of("implicit");
    auto tok = Local::seal(k, msg, footer, implicit);
    REQUIRE(tok.is_ok());
    auto wrong_key = Local::open(tok.value(), key_b(), footer, implicit);
    CHECK(wrong_key.is_err() && wrong_key.error() == paseto5::Error::invalid);
    auto wrong_implicit = Local::open(tok.value(), k, footer, tu::bytes_of("implicix"));
    CHECK(wrong_implicit.is_err() && wrong_implicit.error() == paseto5::Error::invalid);
    auto no_implicit = Local::open(tok.value(), k, footer, {});
    CHECK(no_implicit.is_err() && no_implicit.error() == paseto5::Error::invalid);
    auto wrong_footer = Local::open(tok.value(), k, tu::bytes_of("footex"), implicit);
    CHECK(wrong_footer.is_err() && wrong_footer.error() == paseto5::Error::invalid);
    auto no_footer = Local::open(tok.value(), k, {}, implicit);
    CHECK(no_footer.is_err() && no_footer.error() == paseto5::Error::invalid);
    auto plain = Local::seal(k, msg);
    REQUIRE(plain.is_ok());
    auto extra_footer = Local::open(plain.value(), k, footer, {});
    CHECK(extra_footer.is_err() && extra_footer.error() == paseto5::Error::invalid);
    auto footer_in_text = Local::open(plain.value() + "." + "Zm9vdGVy", k, footer, {});
    CHECK(footer_in_text.is_err() && footer_in_text.error() == paseto5::Error::invalid);
}

TEST_CASE("local/other headers are rejected by the header check") {
    const LocalKey k = key_a();
    auto tok = Local::seal(k, tu::bytes_of("x"));
    REQUIRE(tok.is_ok());
    std::string v4 = tok.value();
    v4.replace(0, 10, "v4.local.");
    CHECK(Local::open(v4, k).is_err());
    std::string upper = tok.value();
    upper[0] = 'V';
    CHECK(Local::open(upper, k).is_err());
    std::string pub = tok.value();
    pub.replace(0, 10, "cb2.public.");
    CHECK(Local::open(pub, k).is_err());
    CHECK(Local::open("", k).is_err());
    CHECK(Local::open("cb2.local.", k).is_err());
    CHECK(Local::open("cb2.local..", k).is_err());
}

TEST_CASE("local/argument errors never depend on the token") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("abc");
    std::vector<uint8_t> out(Local::token_len(3, 0) - 1);
    size_t n = 5;
    CHECK(Local::seal_into(out, n, k, msg) == Status::argument);
    CHECK(n == 0);
    std::vector<uint8_t> big(Local::token_len(3, 0));
    CHECK(Local::seal_into(big, n, k, {big.data(), 3}) == Status::argument);
    std::vector<uint8_t> huge_implicit(paseto5::MAX_INPUT_BYTES + 1);
    CHECK(Local::seal_into(big, n, k, msg, {}, huge_implicit) == Status::argument);
    auto tok = Local::seal(k, msg);
    REQUIRE(tok.is_ok());
    std::vector<uint8_t> small(Local::open_capacity(tok.value().size()) - 1);
    CHECK(Local::open_into(small, n, tok.value(), k) == Status::argument);
    std::vector<uint8_t> overlapping(tok.value().begin(), tok.value().end());
    overlapping.resize(overlapping.size() + 64);
    const std::string_view view(reinterpret_cast<const char*>(overlapping.data()), tok.value().size());
    CHECK(Local::open_into(overlapping, n, view, k) == Status::argument);
}

TEST_CASE("local/body layout is nonce, ciphertext, tag") {
    const LocalKey k = key_a();
    const Bytes msg = tu::bytes_of("twelve bytes");
    auto tok = Local::seal(k, msg);
    REQUIRE(tok.is_ok());
    const std::string body = tok.value().substr(10);
    Bytes raw(body.size());
    size_t n = 0;
    REQUIRE(paseto5::detail::b64::decode(raw.data(), raw.size(), body.data(), body.size(), n));
    CHECK(n == 32 + 12 + 32);
}

TEST_CASE("local/a one mebibyte message round trips") {
    const LocalKey k = key_a();
    const Bytes msg = tu::pattern(1u << 20, 0x42);
    auto tok = Local::seal(k, msg, {}, tu::bytes_of("ctx"));
    REQUIRE(tok.is_ok());
    auto refused = Local::open(tok.value(), k, {}, tu::bytes_of("ctx"));
    CHECK(refused.is_err() && refused.error() == paseto5::Error::too_large);
    auto back = Local::open(tok.value(), k, {}, tu::bytes_of("ctx"), tok.value().size());
    REQUIRE(back.is_ok());
    CHECK(back.value().size() == msg.size());
    CHECK(std::equal(msg.begin(), msg.end(), back.value().begin()));
}

TEST_CASE("local/the allocating open refuses an oversize token before reading it") {
    const LocalKey k = key_a();
    const std::string just_over = std::string(Local::HEADER) + std::string(paseto5::DEFAULT_RAW_MAX_TOKEN_BYTES, 'A');
    auto r = Local::open(just_over, k);
    CHECK(r.is_err() && r.error() == paseto5::Error::too_large);
    auto raised = Local::open(just_over, k, {}, {}, just_over.size());
    CHECK(raised.is_err() && raised.error() == paseto5::Error::invalid);
    const std::string at_limit = std::string(Local::HEADER) + std::string(paseto5::DEFAULT_RAW_MAX_TOKEN_BYTES - Local::HEADER.size(), 'A');
    auto limit = Local::open(at_limit, k);
    CHECK(limit.is_err() && limit.error() == paseto5::Error::invalid);
    const Bytes msg(paseto5::DEFAULT_RAW_MAX_TOKEN_BYTES, 0x5a);
    auto big = Local::seal(k, msg);
    REQUIRE(big.is_ok());
    auto refused = Local::open(big.value(), k);
    CHECK(refused.is_err() && refused.error() == paseto5::Error::too_large);
    auto allowed = Local::open(big.value(), k, {}, {}, big.value().size());
    REQUIRE(allowed.is_ok());
    CHECK(allowed.value().size() == msg.size());
    CHECK(paseto5::DEFAULT_RAW_MAX_TOKEN_BYTES == (std::size_t{1} << 20));
}
