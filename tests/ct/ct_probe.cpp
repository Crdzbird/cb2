/**
 * The constant-time probe, in the ctgrind style: secret bytes are marked
 * undefined with memcheck's client requests and the operations that use
 * them run under Valgrind, which reports every conditional jump, and
 * every memory address, that depends on them. The library declares a
 * value public only where it is public by construction (detail::declassify
 * in secure.hpp); everything before that point stays under observation.
 *
 * What is marked:
 *   Keccak             the input of SHA3-256 and SHAKE256, one block and several
 *   cb2.local          the key and the message, through seal and open, a short
 *                      message on libsodium and a long one on OpenSSL, and a
 *                      tampered token that must be refused
 *   cb2.public         the Ed25519 seed through sign, then verify
 *   kcb2.seal          the local key and the X-Wing ephemeral secrets through
 *                      seal; the ML-KEM decryption key, the implicit-rejection
 *                      secret and the X25519 secret through unseal
 * What is not: the ML-DSA-65 secret. FIPS 204 signing rejection-samples
 * on a value derived from it by design and liboqs does not declassify
 * that verdict; ML-DSA in liboqs carries its own constant-time checks.
 * Key generation is not probed either: ML-KEM and ML-DSA expand their
 * public matrix from a seed and rejection-sample it on purpose.
 *
 * Build with -DCB2_CT_PROBE=ON on Linux with Valgrind installed; run:
 *   valgrind --error-exitcode=1 --suppressions=tests/ct/ct_probe.supp ./cb2_ct_probe
 * Without <valgrind/memcheck.h> the markers compile to nothing and the
 * probe only checks that each operation still gives the right answer.
 */

#include <cb2/cb2.hpp>
#include <cb2/detail/sha3.hpp>

#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define CB2_PROBE_SECRET(p, n) (void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n))
#define CB2_PROBE_PUBLIC(p, n) (void)VALGRIND_MAKE_MEM_DEFINED((p), (n))
#define CB2_PROBE_ACTIVE (RUNNING_ON_VALGRIND != 0)
#endif
#endif
#ifndef CB2_PROBE_SECRET
#define CB2_PROBE_SECRET(p, n) ((void)(p), (void)(n))
#define CB2_PROBE_PUBLIC(p, n) ((void)(p), (void)(n))
#define CB2_PROBE_ACTIVE false
#endif

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using cb2::LocalKey;
using cb2::detail::Keccak;
using cb2::detail::KeyAccess;

namespace {

void require(bool ok, const char* what) {
    if (ok) return;
    std::fprintf(stderr, "ct_probe: %s failed\n", what);
    std::exit(2);
}

void secret(const uint8_t* p, std::size_t n) { CB2_PROBE_SECRET(const_cast<uint8_t*>(p), n); }

std::vector<uint8_t> pattern(std::size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(seed + 31 * i);
    return v;
}

void probe_keccak() {
    for (const std::size_t n : {std::size_t{32}, std::size_t{134}, std::size_t{300}}) {
        std::vector<uint8_t> in = pattern(n, 1);
        CB2_PROBE_SECRET(in.data(), in.size());
        uint8_t digest[32];
        uint8_t xof[300];
        Keccak::sha3_256(digest, in.data(), in.size());
        Keccak::shake256(xof, sizeof xof, in.data(), in.size());
        CB2_PROBE_PUBLIC(digest, sizeof digest);
        CB2_PROBE_PUBLIC(xof, sizeof xof);
    }
}

void probe_local() {
    const LocalKey key = LocalKey::from_bytes(pattern(32, 7)).value();
    secret(KeyAccess::local(key), LocalKey::BYTES);
    const std::vector<uint8_t> footer = {'k', 'i', 'd'};
    for (const std::size_t n : {std::size_t{64}, std::size_t{1000}}) {
        std::vector<uint8_t> msg = pattern(n, 3);
        CB2_PROBE_SECRET(msg.data(), msg.size());
        auto token = cb2::Local::seal(key, msg, footer, {});
        require(token.is_ok(), "local seal");
        auto opened = cb2::Local::open(token.value(), key, footer, {});
        require(opened.is_ok(), "local open");
        CB2_PROBE_PUBLIC(opened.value().data(), opened.value().size());
        CB2_PROBE_PUBLIC(msg.data(), msg.size());
        require(opened.value().size() == n && std::memcmp(opened.value().data(), msg.data(), n) == 0,
                "local round trip");
        std::string bad = token.value();
        const std::size_t pos = cb2::Local::HEADER.size() + 40;
        bad[pos] = bad[pos] == 'A' ? 'B' : 'A';
        require(cb2::Local::open(bad, key, footer, {}).is_err(), "local tamper");
    }
}

#ifdef CB2_HAS_PQ
void probe_public() {
    const cb2::SecretKey sk = cb2::SecretKey::generate().value();
    secret(KeyAccess::ed_secret(sk), crypto_sign_SEEDBYTES);
    const std::vector<uint8_t> msg = pattern(80, 5);
    auto token = cb2::Public::sign(sk, msg, {}, {});
    require(token.is_ok(), "public sign");
    require(cb2::Public::verify(token.value(), sk.public_key(), {}, {}).is_ok(), "public verify");
}
#endif

#ifdef CB2_HAS_SEAL
void probe_seal() {
    using cb2::detail::XWing;
    const cb2::RecipientKey recipient = cb2::RecipientKey::from_bytes(pattern(32, 9)).value();
    const LocalKey key = LocalKey::from_bytes(pattern(32, 11)).value();
    secret(KeyAccess::local(key), LocalKey::BYTES);
    std::vector<uint8_t> eseed = pattern(XWing::ESEED_BYTES, 13);
    const std::vector<uint8_t> nonce = pattern(32, 17);
    CB2_PROBE_SECRET(eseed.data(), eseed.size());
    auto sealed = cb2::Seal::seal_with_randomness_for_testing(recipient.public_key(), key, eseed, nonce);
    require(sealed.is_ok(), "kcb2.seal seal");

    const uint8_t* expanded = recipient.expanded_for_testing().data();
    constexpr std::size_t DK_PKE_BYTES = 1152;
    secret(expanded, DK_PKE_BYTES);
    secret(expanded + XWing::ML_SK_BYTES - 32, 32);
    secret(expanded + XWing::ML_SK_BYTES, 32);
    auto back = cb2::Seal::unseal(sealed.value(), recipient);
    require(back.is_ok(), "kcb2.seal unseal");
    CB2_PROBE_PUBLIC(KeyAccess::local(back.value()), LocalKey::BYTES);
    CB2_PROBE_PUBLIC(KeyAccess::local(key), LocalKey::BYTES);
    require(std::memcmp(KeyAccess::local(back.value()), KeyAccess::local(key), LocalKey::BYTES) == 0,
            "kcb2.seal round trip");
}
#endif

}

int main() {
    require(cb2::detail::ensure_sodium(), "libsodium");
    probe_keccak();
    probe_local();
#ifdef CB2_HAS_PQ
    probe_public();
#endif
#ifdef CB2_HAS_SEAL
    probe_seal();
#endif
    std::printf("ct_probe: %s\n", CB2_PROBE_ACTIVE ? "ran under Valgrind" : "not under Valgrind, markers inactive");
    return 0;
}
