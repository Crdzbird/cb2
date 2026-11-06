#include "test_runner.hpp"
#include "test_util.hpp"

#include <cb2/detail/sha3.hpp>

#include <algorithm>
#include <string>
#include <vector>

using cb2::detail::Keccak;
using tu::Bytes;

namespace {

/// Expected outputs from Python's hashlib (FIPS 202), at and around the
/// 136-byte rate and over several squeezed blocks.
struct HashCase {
    Bytes in;
    const char* hex;
};

struct XofCase {
    Bytes in;
    std::size_t out_len;
    const char* hex;
};

const std::vector<HashCase>& sha3_cases() {
    static const std::vector<HashCase> v = {
    {tu::Bytes(), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {tu::bytes_of("abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
    {Bytes(200, 0xa3), "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"},
    {tu::pattern(1, 0x11), "8d5cc459ce36eda1a075fb2a80696f455c96693ca7e619d1ebaa384c56ce4436"},
    {tu::pattern(135, 0x11), "ac5dc6cf538901077a8ad424c4666382c74fd97a0e57c7796ecd9f52dc70edba"},
    {tu::pattern(136, 0x11), "ee7c57294d9f30757ea7b0c1f9e2c3e5f448943f178d2074937af1783a4fd1c9"},
    {tu::pattern(137, 0x11), "2af00e77514001f1725812920b8240af3e22c2147f62fc6210e021a4e63dba67"},
    {tu::pattern(271, 0x11), "0533d2284da98715bcff02b17335ce9a58b3009d4e903f5724175e883f4dc55a"},
    {tu::pattern(272, 0x11), "3549034fdb1ea1dbc349a6cf3e4ce5b05db001158fb392fed74325fbf6067449"},
    {tu::pattern(273, 0x11), "78cc74e118fd2a6e6dac2894805dd040d1399a74f0be8a74419dd618ffb998c4"},
    {tu::pattern(1000, 0x11), "329201e0b7cd84353fb13206b34bd61862ea33543805d81da3a850ab647d5412"},
    };
    return v;
}

const std::vector<XofCase>& shake_cases() {
    static const std::vector<XofCase> v = {
    {tu::Bytes(), 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
    {tu::bytes_of("abc"), 64, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"},
    {tu::pattern(32, 0x70), 96, "340f3da85f6e5a9e52eebdd09a50664eb569fa093f63e6808c0d28408c48edbbd92e617b93f6ffe81978a8c4be0e9f85dec1dda0dfe63e94bcde2d6774bc1e8cc7088383ccea66e582f2b763f5c60a9514f84f14c99c8b63a9f9729f7a8d1ae4"},
    {tu::pattern(136, 0x11), 136, "71b392927d447bdf7e9462134772ef9ced84e0e2f5a2910b26e74325408ddf23091003793ecd2afc50b7b6ff47c376c8e61459a7548603f28a59d13eec9e1845c2fe2e1fdae26112b1ad813f45e59d398ff0d3dd062f2225fa22c4c6544d018223fd7e75eee26cf09cf27f1f3692e0126f904deba2bed4f8979f5c77c083bc6ffeff7a08aea1cb5b"},
    {tu::pattern(137, 0x11), 300, "425caa0b5115343582a0f9537870c639f662f49ce0e9818f997a90971b0abebef3011d8375d39f079d0fd3952d7d28ebd7d18d2095f5ed174dde4fb239850205677c795d07bb12a1691d88c852f91d4d818f1770389b6436ae9d28428181609339cf6649ad16218f31a9db6f6403ea8dc9ca15b68fa12dffaa7206b0df84b51dde17752146b38eee0b67ecd9264e14a892e0d2e12c7cb9c7a951147518e90ef47e3158812d18da3c5c3cea59a836850d3c2f3a4d9e2617950a2bceb5a80ba85f36e7bf408f518b5899cfd5ea4bcd5b3935fc39b3bcada5ee06636888e915e6f7635823004801349bfd6633d984374af111936402feb18e6a25570fa06a835dc2536f21db547d9b9aceb12d4dbbc0b1c656ea8a48a05753deb30788e7dd534ac11d1f5f74b0b4a593ee7b8d06"},
    {tu::pattern(500, 0x05), 137, "e647cab0ebf0c88086c6d7dff3ecadfd613e4447c55b07047f909469a7d24435db5b2bd2e06ece28609219b30a6d60ef1f4a9fa44266f1ee5c985d4152d0a239b7dded9034f5afb9884f5a2298a542bee93e15edcf8c083e02ed8d7e3f43635842e6e3edac78e51b208312c90f544fa468a21583453075e5e5c146147beb08910404599994c8bcaf12"},
    };
    return v;
}

}

TEST_CASE("sha3/SHA3-256 matches FIPS 202 at and around the rate") {
    for (const HashCase& c : sha3_cases()) {
        uint8_t out[32];
        Keccak::sha3_256(out, c.in.data(), c.in.size());
        CHECK(tu::hex({out, 32}) == c.hex);
    }
}

TEST_CASE("sha3/SHAKE256 matches FIPS 202 for short, block-sized and multi-block outputs") {
    for (const XofCase& c : shake_cases()) {
        Bytes out(c.out_len);
        Keccak::shake256(out.data(), out.size(), c.in.data(), c.in.size());
        CHECK(tu::hex(out) == c.hex);
    }
}

TEST_CASE("sha3/a SHAKE256 output is a prefix of every longer one") {
    const Bytes seed = tu::pattern(32, 0x70);
    Bytes longest(700);
    Keccak::shake256(longest.data(), longest.size(), seed.data(), seed.size());
    for (std::size_t n : {std::size_t{1}, std::size_t{96}, std::size_t{135}, std::size_t{136}, std::size_t{137}, std::size_t{272}, std::size_t{699}}) {
        Bytes out(n);
        Keccak::shake256(out.data(), out.size(), seed.data(), seed.size());
        CHECK(std::equal(out.begin(), out.end(), longest.begin()));
    }
}
