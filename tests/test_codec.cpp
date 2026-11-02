#include "test_runner.hpp"
#include "test_util.hpp"

#include <paseto5/detail/base64url.hpp>
#include <paseto5/detail/local_core.hpp>
#include <paseto5/detail/pae.hpp>

#include <cstring>
#include <string>

namespace b64 = paseto5::detail::b64;
using tu::Bytes;

namespace {

constexpr int SODIUM_VARIANT = sodium_base64_VARIANT_URLSAFE_NO_PADDING;

std::string sodium_encode(std::span<const uint8_t> in) {
    std::string s(sodium_base64_ENCODED_LEN(in.size(), SODIUM_VARIANT), '\0');
    sodium_bin2base64(s.data(), s.size(), in.data(), in.size(), SODIUM_VARIANT);
    s.resize(std::strlen(s.c_str()));
    return s;
}

bool sodium_decode(std::string_view in, Bytes& out) {
    out.assign(in.size() + 1, 0);
    size_t n = 0;
    const char* end = nullptr;
    if (sodium_base642bin(out.data(), out.size(), in.data(), in.size(), nullptr, &n, &end,
                          SODIUM_VARIANT) != 0)
        return false;
    if (end != in.data() + in.size()) return false;
    out.resize(n);
    return true;
}

std::string my_encode(std::span<const uint8_t> in) {
    std::string s(b64::encoded_len(in.size()), '\0');
    b64::encode(s.data(), in.data(), in.size());
    return s;
}

bool my_decode(std::string_view in, Bytes& out) {
    out.assign(in.size() + 1, 0);
    size_t n = 0;
    if (!b64::decode(out.data(), out.size(), in.data(), in.size(), n)) return false;
    out.resize(n);
    return true;
}

struct CollectSink {
    Bytes out;
    void update(const uint8_t* p, size_t n) { out.insert(out.end(), p, p + n); }
};

}

TEST_CASE("codec/base64url encodes exactly as libsodium for lengths 0..200") {
    for (size_t n = 0; n <= 200; ++n) {
        const Bytes in = tu::pattern(n, static_cast<uint8_t>(n));
        CHECK(my_encode(in) == sodium_encode(in));
        Bytes back;
        CHECK(my_decode(my_encode(in), back));
        CHECK(back == in);
    }
}

TEST_CASE("codec/base64url decoder agrees with libsodium on random and malformed text") {
    static constexpr char EXTRA[] = "=+/ .\n\t\x80\xff";
    for (int iter = 0; iter < 5000; ++iter) {
        std::string s;
        const auto len = static_cast<size_t>(randombytes_uniform(24));
        for (size_t k = 0; k < len; ++k) {
            if (randombytes_uniform(20) == 0) s += EXTRA[randombytes_uniform(sizeof EXTRA - 1)];
            else s += b64::ALPHABET[randombytes_uniform(64)];
        }
        Bytes a, b;
        const bool mine = my_decode(s, a);
        const bool ref = sodium_decode(s, b);
        CHECK(mine == ref);
        if (mine && ref) CHECK(a == b);
    }
}

TEST_CASE("codec/base64url rejects padding, length 1 mod 4 and spare bits") {
    Bytes out;
    CHECK(!my_decode("AQ==", out));
    CHECK(!my_decode("A", out));
    CHECK(!my_decode("AAAAA", out));
    CHECK(my_decode("AQ", out));
    CHECK(out.size() == 1 && out[0] == 1);
    CHECK(!my_decode("AR", out));
    CHECK(my_decode("AAE", out));
    CHECK(out.size() == 2);
    CHECK(!my_decode("AAF", out));
    CHECK(!my_decode("AB+D", out));
    CHECK(!my_decode("AB/D", out));
    CHECK(my_decode("", out));
    CHECK(out.empty());
    CHECK(b64::decoded_len(5) == static_cast<size_t>(-1));
    CHECK(b64::decoded_len(4) == 3);
    CHECK(b64::decoded_len(3) == 2);
    CHECK(b64::decoded_len(2) == 1);
    CHECK(b64::encoded_len(1) == 2 && b64::encoded_len(2) == 3 && b64::encoded_len(3) == 4);
}

TEST_CASE("codec/base64url decode fails closed when the capacity is short") {
    uint8_t out[2];
    size_t n = 7;
    CHECK(!b64::decode(out, sizeof out, "AAAA", 4, n));
    CHECK(n == 0);
}

TEST_CASE("codec/pae matches the definition") {
    CollectSink s;
    paseto5::detail::pae_stream(s, {});
    CHECK(s.out == Bytes(8, 0));

    CollectSink e;
    paseto5::detail::pae_stream(e, {std::span<const uint8_t>{}});
    Bytes want(16, 0);
    want[0] = 1;
    CHECK(e.out == want);

    CollectSink p;
    const Bytes para = tu::bytes_of("Paragon");
    paseto5::detail::pae_stream(p, {tu::sp(para)});
    Bytes want2(16, 0);
    want2[0] = 1;
    want2[8] = 7;
    want2.insert(want2.end(), para.begin(), para.end());
    CHECK(p.out == want2);
    CHECK(paseto5::detail::pae_len({7}) == p.out.size());

    CollectSink two;
    const Bytes a = tu::bytes_of("ab"), b = tu::bytes_of("cde");
    paseto5::detail::pae_stream(two, {tu::sp(a), tu::sp(b)});
    CHECK(two.out.size() == 8 + 8 + 2 + 8 + 3);
    CHECK(two.out[0] == 2 && two.out[8] == 2 && two.out[18] == 3);
}

TEST_CASE("codec/pae top bit of every length is clear") {
    uint8_t le[8];
    paseto5::detail::put_le64(le, static_cast<size_t>(-1));
    CHECK((le[7] & 0x80) == 0);
    CHECK(le[0] == 0xFF);
}

TEST_CASE("codec/buffered sink produces the same stream as direct updates") {
    for (int iter = 0; iter < 200; ++iter) {
        Bytes pieces[4];
        for (auto& p : pieces) p = tu::pattern(randombytes_uniform(400), static_cast<uint8_t>(iter));
        CollectSink direct;
        paseto5::detail::pae_stream(direct, {tu::sp(pieces[0]), tu::sp(pieces[1]), tu::sp(pieces[2]), tu::sp(pieces[3])});
        CollectSink inner;
        paseto5::detail::BufferedSink<CollectSink> buffered(inner);
        paseto5::detail::pae_stream(buffered, {tu::sp(pieces[0]), tu::sp(pieces[1]), tu::sp(pieces[2]), tu::sp(pieces[3])});
        buffered.flush();
        CHECK(inner.out == direct.out);
    }
}
