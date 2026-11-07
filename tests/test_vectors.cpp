/**
 * Known-answer vectors produced by cb2_gen_vectors and committed under
 * tests/vectors. Every local vector is re-sealed with the recorded nonce
 * and must reproduce the token byte for byte; every public vector must
 * verify (ML-DSA signing is randomised, so public tokens are checked, not
 * reproduced); every failure vector must fail; every claims vector must
 * yield the recorded verdict. The intermediate values a success vector
 * records (derived keys, PAE, ciphertext, tag, the Ed25519 half of a
 * signature) are recomputed from the primitives and must match, so that
 * what docs/PROTOCOL.md publishes for other implementations is what this
 * one does.
 */

#include "test_runner.hpp"
#include "test_util.hpp"

#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <vector>

using cb2::Claims;
using cb2::Error;
using cb2::Local;
using cb2::LocalKey;
using cb2::Status;
using cb2::Token;
using cb2::ValidationRules;
using cb2::json::Value;
using tu::Bytes;

namespace {

bool load(const char* file, Value& root) {
    const std::string path = std::string(CB2_VECTOR_DIR) + "/" + file;
    auto text = tu::read_file(path.c_str());
    if (!text) {
        std::printf("      missing vector file %s\n", path.c_str());
        return false;
    }
    return cb2::json::Reader::parse(*text, root, 32) && root.is_object();
}

const Value* tests_of(const Value& root) {
    const Value* t = root.get("tests");
    return t != nullptr && t->kind == Value::Kind::array ? t : nullptr;
}

ValidationRules rules_of(const Value& v) {
    ValidationRules r;
    const Value* o = v.get("rules");
    if (o == nullptr) return r;
    r.at(tu::num(*o, "now"));
    if (!tu::flag(*o, "require-exp")) r.allow_missing_exp();
    if (!tu::flag(*o, "require-audience")) r.allow_any_audience();
    if (!tu::flag(*o, "require-issuer")) r.allow_any_issuer();
    if (const Value* seen = o->get("seen-jti"); seen != nullptr) {
        std::vector<std::string> list;
        for (const Value& j : seen->items) list.push_back(j.text);
        r.with_replay_check([list](std::string_view jti) {
            for (const auto& s : list) if (s == jti) return false;
            return true;
        });
    }
    r.with_clock_skew(tu::num(*o, "clock-skew"));
    if (o->get("max-token-bytes") != nullptr) r.with_max_token_bytes(static_cast<size_t>(tu::num(*o, "max-token-bytes")));
    if (o->get("issuer") != nullptr) r.expect_issuer(tu::str(*o, "issuer"));
    if (o->get("audience") != nullptr) r.expect_audience(tu::str(*o, "audience"));
    if (o->get("subject") != nullptr) r.expect_subject(tu::str(*o, "subject"));
    return r;
}

std::string verdict_name(bool ok, Error e) { return ok ? "ok" : cb2::error_name(e); }

/// The decoded body of a token: the text between the header and the
/// footer separator, through the strict decoder.
Bytes body_of(const std::string& token, size_t header_len) {
    const std::string_view rest = std::string_view(token).substr(header_len);
    const size_t dot = rest.find('.');
    const std::string_view text = dot == std::string_view::npos ? rest : rest.substr(0, dot);
    Bytes out(text.size());
    size_t n = 0;
    if (!cb2::detail::b64::decode(out.data(), out.size(), text.data(), text.size(), n)) return {};
    out.resize(n);
    return out;
}

Bytes pae_of(std::initializer_list<std::span<const uint8_t>> pieces) {
    size_t total = 8;
    for (const auto& p : pieces) total += 8 + p.size();
    Bytes out(total);
    cb2::detail::SpanSink sink{out.data()};
    cb2::detail::pae_stream(sink, pieces);
    return out;
}

/// Recomputes a local vector's key split, ciphertext, PAE and tag from
/// the primitives and checks that the token body is nonce, ciphertext
/// and tag in that order.
void check_local_intermediates(const Value& v, const Bytes& key, const Bytes& nonce, const Bytes& payload,
                               const Bytes& footer, const Bytes& implicit, const std::string& token,
                               std::string_view h = Local::HEADER) {
    Bytes split(88);
    cb2::detail::Blake3Keyed hk(key.data());
    hk.update(cb2::bytes(h).data(), h.size());
    hk.update(nonce.data(), nonce.size());
    hk.finalize(split.data(), split.size());
    CHECK(tu::hex(std::span<const uint8_t>(split.data(), 32)) == tu::str(v, "ek"));
    CHECK(tu::hex(std::span<const uint8_t>(split.data() + 32, 24)) == tu::str(v, "n2"));
    CHECK(tu::hex(std::span<const uint8_t>(split.data() + 56, 32)) == tu::str(v, "ak"));
    Bytes c = payload;
    if (!c.empty()) CHECK(crypto_stream_xchacha20_xor(c.data(), c.data(), c.size(), split.data() + 32, split.data()) == 0);
    CHECK(tu::hex(c) == tu::str(v, "ciphertext"));
    const Bytes pae = pae_of({cb2::bytes(h), nonce, c, footer, implicit});
    CHECK(tu::hex(pae) == tu::str(v, "pae"));
    Bytes tag(32);
    cb2::detail::Blake3Keyed hm(split.data() + 56);
    hm.update(pae.data(), pae.size());
    hm.finalize(tag.data(), tag.size());
    CHECK(tu::hex(tag) == tu::str(v, "tag"));
    Bytes body = nonce;
    body.insert(body.end(), c.begin(), c.end());
    body.insert(body.end(), tag.begin(), tag.end());
    CHECK(body_of(token, h.size()) == body);
}

#ifdef CB2_HAS_PQ
/// Recomputes a public vector's PAE and checks that the recorded Ed25519
/// half is the one in the token and verifies over that PAE.
void check_public_intermediates(const Value& v, const cb2::PublicKey& pk, const Bytes& msg, const Bytes& footer,
                                const Bytes& implicit, const std::string& token) {
    const std::string_view h = cb2::Public::HEADER;
    const Bytes pae = pae_of({cb2::bytes(h), msg, footer, implicit});
    CHECK(tu::hex(pae) == tu::str(v, "pae"));
    const Bytes ed = tu::unhex(tu::str(v, "ed25519-signature"));
    CHECK(ed.size() == cb2::Public::ED_SIG_BYTES);
    CHECK(crypto_sign_verify_detached(ed.data(), pae.data(), pae.size(), pk.bytes().data()) == 0);
    const Bytes body = body_of(token, h.size());
    CHECK(body.size() == msg.size() + cb2::Public::SIG_BYTES);
    if (body.size() != msg.size() + cb2::Public::SIG_BYTES) return;
    const auto at = body.begin() + static_cast<std::ptrdiff_t>(msg.size());
    CHECK(Bytes(at, at + static_cast<std::ptrdiff_t>(cb2::Public::ED_SIG_BYTES)) == ed);
}
#endif

}

TEST_CASE("vectors/cb2.local vectors reproduce and open") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        const Bytes key = tu::unhex(tu::str(v, "key"));
        const Bytes footer = tu::bytes_of(tu::str(v, "footer"));
        const Bytes implicit = tu::bytes_of(tu::str(v, "implicit-assertion"));
        const std::string token = tu::str(v, "token");
        auto k = LocalKey::from_bytes(key);
        REQUIRE(k.is_ok());
        if (tu::flag(v, "expect-fail")) {
            auto r = Local::open(token, k.value(), footer, implicit);
            if (!(r.is_err() && r.error() == Error::invalid)) std::printf("      %s should fail\n", name.c_str());
            CHECK(r.is_err() && r.error() == Error::invalid);
            continue;
        }
        const Bytes nonce = tu::unhex(tu::str(v, "nonce"));
        const Bytes payload = tu::bytes_of(tu::str(v, "payload"));
        std::string out(Local::token_len(payload.size(), footer.size()), '\0');
        size_t n = 0;
        CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, k.value(), payload, footer, implicit, nonce) == Status::ok);
        if (out != token) std::printf("      %s token differs\n", name.c_str());
        CHECK(out == token);
        REQUIRE(v.get("ek") != nullptr);
        check_local_intermediates(v, key, nonce, payload, footer, implicit, token);
        auto back = Local::open(token, k.value(), footer, implicit);
        REQUIRE(back.is_ok());
        CHECK(Bytes(back.value().begin(), back.value().end()) == payload);
    }
    CHECK(seen >= 10);
}

TEST_CASE("vectors/cb2.local weak keys are refused on import") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* weak = root.get("weak-keys");
    REQUIRE(weak != nullptr && weak->kind == Value::Kind::array);
    int seen = 0;
    for (const Value& w : weak->items) {
        ++seen;
        auto r = LocalKey::from_bytes(tu::unhex(tu::str(w, "key")));
        CHECK(r.is_err() && cb2::error_name(r.error()) == tu::str(w, "expect"));
    }
    CHECK(seen == 3);
}

TEST_CASE("vectors/cb2.local tamper vectors all fail") {
    Value root;
    REQUIRE(load("cb2_local.json", root));
    const Value* tamper = root.get("tamper");
    REQUIRE(tamper != nullptr && tamper->is_object());
    const Bytes key = tu::unhex(tu::str(*tamper, "key"));
    const Bytes footer = tu::bytes_of(tu::str(*tamper, "footer"));
    const Bytes implicit = tu::bytes_of(tu::str(*tamper, "implicit-assertion"));
    auto k = LocalKey::from_bytes(key);
    REQUIRE(k.is_ok());
    CHECK(Local::open(tu::str(*tamper, "token"), k.value(), footer, implicit).is_ok());
    const Value* cases = tamper->get("cases");
    REQUIRE(cases != nullptr && cases->kind == Value::Kind::array);
    CHECK(cases->items.size() == tu::str(*tamper, "token").size());
    for (const Value& c : cases->items) {
        auto r = Local::open(tu::str(c, "token"), k.value(), footer, implicit);
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
}

#ifdef CB2_HAS_PQ
TEST_CASE("vectors/cb2.public vectors verify and failure vectors fail") {
    Value root;
    REQUIRE(load("cb2_public.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        auto pk = cb2::PublicKey::from_bytes(tu::unhex(tu::str(v, "public-key")));
        REQUIRE(pk.is_ok());
        const Bytes footer = tu::bytes_of(tu::str(v, "footer"));
        const Bytes implicit = tu::bytes_of(tu::str(v, "implicit-assertion"));
        const std::string token = tu::str(v, "token");
        auto r = cb2::Public::verify(token, pk.value(), footer, implicit);
        if (tu::flag(v, "expect-fail")) {
            if (!r.is_err()) std::printf("      %s should fail\n", name.c_str());
            CHECK(r.is_err() && r.error() == Error::invalid);
            continue;
        }
        if (!r.is_ok()) std::printf("      %s should verify\n", name.c_str());
        REQUIRE(r.is_ok());
        CHECK(r.value() == tu::bytes_of(tu::str(v, "payload")));
        REQUIRE(v.get("pae") != nullptr);
        check_public_intermediates(v, pk.value(), r.value(), footer, implicit, token);
        auto sk = cb2::SecretKey::from_bytes(tu::unhex(tu::str(v, "secret-key")));
        REQUIRE(sk.is_ok());
        CHECK(std::equal(pk.value().bytes().begin(), pk.value().bytes().end(), sk.value().public_key().bytes().begin()));
        auto again = cb2::Public::sign(sk.value(), r.value(), footer, implicit);
        REQUIRE(again.is_ok());
        CHECK(again.value().size() == token.size());
        CHECK(cb2::Public::verify(again.value(), pk.value(), footer, implicit).is_ok());
    }
    CHECK(seen >= 6);
    const Value* tamper = root.get("tamper");
    REQUIRE(tamper != nullptr && tamper->is_object());
    auto pk = cb2::PublicKey::from_bytes(tu::unhex(tu::str(*tamper, "public-key")));
    REQUIRE(pk.is_ok());
    const Value* cases = tamper->get("cases");
    REQUIRE(cases != nullptr);
    for (const Value& c : cases->items) {
        auto r = cb2::Public::verify(tu::str(c, "token"), pk.value(), tu::bytes_of(tu::str(*tamper, "footer")), tu::bytes_of(tu::str(*tamper, "implicit-assertion")));
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
}
#endif

#ifdef CB2_HAS_PQ
TEST_CASE("vectors/cb2.public rejected secret keys are refused on import") {
    Value root;
    REQUIRE(load("cb2_public.json", root));
    const Value* rejected = root.get("rejected-secret-keys");
    REQUIRE(rejected != nullptr && rejected->kind == Value::Kind::array);
    int seen = 0;
    for (const Value& v : rejected->items) {
        ++seen;
        auto r = cb2::SecretKey::from_bytes(tu::unhex(tu::str(v, "secret-key")));
        if (!r.is_err()) std::printf("      %s should be refused\n", tu::str(v, "name").c_str());
        CHECK(r.is_err() && cb2::error_name(r.error()) == tu::str(v, "expect"));
    }
    CHECK(seen == 5);
}
#endif

TEST_CASE("vectors/claims vectors yield the recorded verdicts") {
    Value root;
    REQUIRE(load("claims.json", root));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string name = tu::str(v, "name");
        const std::string purpose = tu::str(v, "purpose");
        const std::string token = tu::str(v, "token");
        const std::string implicit = tu::str(v, "implicit-assertion");
        const ValidationRules rules = rules_of(v);
        std::string verdict;
        if (purpose == "local") {
            auto k = LocalKey::from_bytes(tu::unhex(tu::str(v, "key")));
            REQUIRE(k.is_ok());
            if (v.get("key-id") != nullptr) k.value().set_key_id(tu::str(v, "key-id"));
            const Bytes nonce = tu::unhex(tu::str(v, "nonce"));
            if (!nonce.empty()) {
                const std::string payload = tu::str(v, "payload");
                const std::string footer = Token::footer_for(k.value().key_id());
                std::string out(Local::token_len(payload.size(), footer.size()), '\0');
                size_t n = 0;
                CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, k.value(), cb2::bytes(payload), cb2::bytes(footer), cb2::bytes(implicit), nonce) == Status::ok);
                if (tu::str(v, "verifier-key").empty()) CHECK(out == token);
            }
            auto vk = tu::str(v, "verifier-key").empty() ? k.value().clone() : LocalKey::from_bytes(tu::unhex(tu::str(v, "verifier-key"))).value();
            if (v.get("verifier-key-id") != nullptr) vk.set_key_id(tu::str(v, "verifier-key-id"));
            auto r = Token::open(token, vk, rules, implicit);
            verdict = verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
            const std::string canonical = v.get("payload-canonical") != nullptr ? tu::str(v, "payload-canonical") : tu::str(v, "payload");
            if (r.is_ok()) CHECK(r.value().to_json() == canonical);
        }
#ifdef CB2_HAS_PQ
        if (purpose == "public") {
            auto pk = cb2::PublicKey::from_bytes(tu::unhex(tu::str(v, "public-key")));
            REQUIRE(pk.is_ok());
            if (v.get("verifier-key-id") != nullptr) pk.value().set_key_id(tu::str(v, "verifier-key-id"));
            auto r = Token::verify(token, pk.value(), rules, implicit);
            verdict = verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
            if (r.is_ok()) CHECK(r.value().to_json() == tu::str(v, "payload"));
        }
#endif
        if (verdict.empty()) continue;
        if (verdict != tu::str(v, "expect")) std::printf("      %s: got %s, expected %s\n", name.c_str(), verdict.c_str(), tu::str(v, "expect").c_str());
        CHECK(verdict == tu::str(v, "expect"));
    }
    CHECK(seen >= 12);
}

namespace {

/// The verdict a proofs.json test records: its access token opened or
/// verified under its key with the document's expectations, the test's
/// rules, and the proof and request when the proof is not empty.
std::string holder_verdict(const Value& root, const Value& v) {
    const Value* t = root.get("access-tokens")->get(tu::str(v, "access-token"));
    const Value* req = v.get("request");
    const Value* o = v.get("rules");
    if (t == nullptr || req == nullptr || o == nullptr) return "<bad vector>";
    ValidationRules rules = ValidationRules().at(tu::num(*o, "now")).expect_issuer(tu::str(root, "issuer"))
        .expect_audience(tu::str(root, "audience"))
        .with_clock_skew(tu::num(*o, "clock-skew")).with_proof_lifetime(tu::num(*o, "proof-lifetime"));
    if (tu::flag(*o, "require-cnf")) rules.require_sender_constraint();
    if (tu::flag(*o, "ignore-cnf")) rules.ignore_sender_constraint();
    const std::string proof = tu::str(v, "proof");
    if (!proof.empty()) {
        cb2::HolderRequest r;
        r.method = tu::str(*req, "htm");
        r.target = tu::str(*req, "htu");
        if (req->get("nonce") != nullptr) r.nonce = tu::str(*req, "nonce");
        std::vector<std::string> list;
        if (const Value* ids = o->get("seen-jti"); ids != nullptr) for (const Value& j : ids->items) list.push_back(j.text);
        rules.with_holder_proof(proof, r).with_proof_replay_check([list](std::string_view jti) {
            for (const auto& s : list) if (s == jti) return false;
            return true;
        });
    }
    if (tu::str(*t, "purpose") == "local") {
        auto k = LocalKey::from_bytes(tu::unhex(tu::str(*t, "key")));
        if (k.is_err()) return "<bad key>";
        auto r = Token::open(tu::str(*t, "token"), k.value(), rules);
        return verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
    }
#ifdef CB2_HAS_PQ
    auto pk = cb2::PublicKey::from_bytes(tu::unhex(tu::str(*t, "issuer-public-key")));
    if (pk.is_err()) return "<bad key>";
    auto r = Token::verify(tu::str(*t, "token"), pk.value(), rules);
    return verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error());
#else
    return "unavailable";
#endif
}

/// Whether a build without ML-DSA-65 can decide a proofs.json test: a
/// local access token without a kcb2.public cnf and no public proof.
bool decidable_without_pq(const Value& root, const Value& v) {
    const Value* t = root.get("access-tokens")->get(tu::str(v, "access-token"));
    return tu::str(*t, "purpose") == "local" && tu::str(*t, "payload").find("kcb2.public.") == std::string::npos &&
           tu::str(v, "proof").rfind(cb2::Holder::PUBLIC_HEADER, 0) != 0;
}

}

TEST_CASE("vectors/holder proof vectors of the local mode reproduce and yield the recorded verdicts") {
    Value root;
    REQUIRE(load("proofs.json", root));
    const Value* tokens = root.get("access-tokens");
    REQUIRE(tokens != nullptr && tokens->is_object());
    int reproduced = 0;
    for (const auto& [which, t] : tokens->members) {
        if (tu::str(t, "purpose") != "local") continue;
        auto k = LocalKey::from_bytes(tu::unhex(tu::str(t, "key")));
        REQUIRE(k.is_ok());
        const std::string payload = tu::str(t, "payload");
        const std::string footer = Token::footer_for(k.value().key_id());
        std::string out(Local::token_len(payload.size(), footer.size()), '\0');
        size_t n = 0;
        CHECK(Local::seal_with_nonce_for_testing({reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, k.value(), cb2::bytes(payload), cb2::bytes(footer), {}, tu::unhex(tu::str(t, "nonce"))) == Status::ok);
        CHECK(out == tu::str(t, "token"));
        ++reproduced;
    }
    CHECK(reproduced >= 4);
    auto proof_key = LocalKey::from_bytes(tu::unhex(tu::str(root, "proof-key")));
    REQUIRE(proof_key.is_ok());
    const cb2::SecureString proof_text = proof_key.value().to_paserk();
    CHECK(tu::str(*tokens->get("local-bound"), "payload").find(std::string(proof_text.data(), proof_text.size())) != std::string::npos);
    const Value* proofs = root.get("local-proofs");
    REQUIRE(proofs != nullptr && proofs->kind == Value::Kind::array);
    for (const Value& p : proofs->items) {
        auto k = LocalKey::from_bytes(tu::unhex(tu::str(p, "key")));
        REQUIRE(k.is_ok());
        const std::string h = tu::str(p, "header");
        const std::string payload = tu::str(p, "payload");
        const std::string footer = tu::str(p, "footer");
        const std::string implicit = tu::str(p, "implicit-assertion");
        const Bytes nonce = tu::unhex(tu::str(p, "nonce"));
        CHECK(footer == Token::footer_for(k.value().paserk_id()));
        std::string out(cb2::detail::LocalCore::token_len(h, payload.size(), footer.size()), '\0');
        size_t n = 0;
        CHECK(cb2::detail::LocalCore::seal(h, {reinterpret_cast<uint8_t*>(out.data()), out.size()}, n, cb2::detail::KeyAccess::local(k.value()), cb2::bytes(payload), cb2::bytes(footer), cb2::bytes(implicit), nonce.data()) == Status::ok);
        CHECK(out == tu::str(p, "proof"));
    }
    CHECK(proofs->items.size() >= 10);
    const Value* inter = root.get("local-intermediates");
    REQUIRE(inter != nullptr);
    const std::string lp1 = tu::str(*inter, "proof");
    check_local_intermediates(*inter, tu::unhex(tu::str(root, "proof-key")), tu::unhex(tu::str(*inter, "nonce")),
                              tu::bytes_of(tu::str(*inter, "claims")), tu::bytes_of(tu::str(*inter, "footer")),
                              tu::bytes_of(tu::str(*inter, "implicit-assertion")), lp1, cb2::Holder::LOCAL_HEADER);
    CHECK(tu::str(*inter, "implicit-assertion") == tu::str(*tokens->get("local-bound"), "token"));
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        if (!decidable_without_pq(root, v)) continue;
        ++seen;
        const std::string verdict = holder_verdict(root, v);
        if (verdict != tu::str(v, "expect")) std::printf("      %s: got %s, expected %s\n", tu::str(v, "name").c_str(), verdict.c_str(), tu::str(v, "expect").c_str());
        CHECK(verdict == tu::str(v, "expect"));
    }
    CHECK(seen >= 25);
}

#ifdef CB2_HAS_PQ
TEST_CASE("vectors/holder proof vectors yield the recorded verdicts") {
    Value root;
    REQUIRE(load("proofs.json", root));
    const Value* tokens = root.get("access-tokens");
    REQUIRE(tokens != nullptr && tokens->is_object());
    const Value* tests = tests_of(root);
    REQUIRE(tests != nullptr);
    int seen = 0;
    for (const Value& v : tests->items) {
        ++seen;
        const std::string verdict = holder_verdict(root, v);
        if (verdict != tu::str(v, "expect")) std::printf("      %s: got %s, expected %s\n", tu::str(v, "name").c_str(), verdict.c_str(), tu::str(v, "expect").c_str());
        CHECK(verdict == tu::str(v, "expect"));
    }
    CHECK(seen >= 50);
    const Value* inter = root.get("intermediates");
    REQUIRE(inter != nullptr);
    auto client = cb2::PublicKey::from_bytes(tu::unhex(tu::str(root, "client-public-key")));
    REQUIRE(client.is_ok());
    const Bytes pae = pae_of({cb2::bytes(cb2::Holder::PUBLIC_HEADER), tu::bytes_of(tu::str(*inter, "claims")),
                              tu::bytes_of(tu::str(*inter, "footer")), tu::bytes_of(tu::str(*inter, "implicit-assertion"))});
    CHECK(tu::hex(pae) == tu::str(*inter, "pae"));
    const Bytes ed = tu::unhex(tu::str(*inter, "ed25519-signature"));
    CHECK(crypto_sign_verify_detached(ed.data(), pae.data(), pae.size(), client.value().bytes().data()) == 0);
    CHECK(tu::str(*inter, "footer") == Token::footer_for(client.value().paserk_id()));
    CHECK(tu::str(*inter, "implicit-assertion") == tu::str(*tokens->get("local"), "token"));
    const Value* norm = root.get("normalisation");
    REQUIRE(norm != nullptr && norm->kind == Value::Kind::array);
    for (const Value& c : norm->items) {
        const auto got = cb2::Holder::normalize_target(tu::str(c, "input"));
        const Value* out = c.get("output");
        REQUIRE(out != nullptr);
        if (out->kind == Value::Kind::null) CHECK(!got.has_value());
        else CHECK(got == std::optional<std::string>(out->text));
    }
}
#endif

#ifdef CB2_HAS_SEAL
TEST_CASE("vectors/seal vectors reproduce and the failures fail") {
    Value root;
    REQUIRE(load("seal.json", root));
    const Value* rec = root.get("recipient");
    const Value* sealed = root.get("sealed");
    REQUIRE(rec != nullptr && sealed != nullptr);
    auto r = cb2::RecipientKey::from_bytes(tu::unhex(tu::str(*rec, "secret")));
    REQUIRE(r.is_ok());
    CHECK(tu::hex(r.value().public_key().bytes()) == tu::str(*rec, "public-key"));
    CHECK(r.value().public_key().to_paserk() == tu::str(*rec, "kcb2.recipient"));
    CHECK(r.value().paserk_id() == tu::str(*rec, "kcb2.rid"));
    const cb2::SecureString sp = r.value().to_paserk();
    CHECK(std::string(sp.data(), sp.size()) == tu::str(*rec, "kcb2.recipient-secret"));
    auto k = LocalKey::from_bytes(tu::unhex(tu::str(*sealed, "key")));
    REQUIRE(k.is_ok());
    const Bytes eseed = tu::unhex(tu::str(*sealed, "eseed"));
    Bytes ct(cb2::detail::XWing::CT_BYTES), ss(32);
    REQUIRE(cb2::detail::XWing::encaps(r.value().public_key().bytes().data(), eseed.data(), ct.data(), ss.data()));
    CHECK(tu::hex(ct) == tu::str(*sealed, "ct"));
    CHECK(tu::hex(ss) == tu::str(*sealed, "ss"));
    auto made = cb2::Seal::seal_with_randomness_for_testing(r.value().public_key(), k.value(), eseed, tu::unhex(tu::str(*sealed, "nonce")));
    REQUIRE(made.is_ok());
    CHECK(made.value() == tu::str(*sealed, "kcb2.seal"));
    auto back = cb2::Seal::unseal(tu::str(*sealed, "kcb2.seal"), r.value());
    REQUIRE(back.is_ok());
    CHECK(back.value().paserk_id() == k.value().paserk_id());
    const Value* fails = root.get("failures");
    REQUIRE(fails != nullptr && fails->kind == Value::Kind::array);
    int seen = 0;
    for (const Value& f : fails->items) {
        ++seen;
        auto by = cb2::RecipientKey::from_bytes(tu::unhex(tu::str(f, "recipient-secret")));
        REQUIRE(by.is_ok());
        auto v = cb2::Seal::unseal(tu::str(f, "kcb2.seal"), by.value());
        if (!v.is_err()) std::printf("      %s should fail\n", tu::str(f, "name").c_str());
        CHECK(v.is_err() && v.error() == Error::invalid);
    }
    CHECK(seen >= 8);
}
#endif

TEST_CASE("vectors/paserk vectors reproduce") {
    Value root;
    REQUIRE(load("paserk.json", root));
    const Value* local = root.get("local");
    REQUIRE(local != nullptr);
    auto k = LocalKey::from_bytes(tu::unhex(tu::str(*local, "key")));
    REQUIRE(k.is_ok());
    const cb2::SecureString p = k.value().to_paserk();
    CHECK(std::string(p.data(), p.size()) == tu::str(*local, "kcb2.local"));
    CHECK(k.value().paserk_id() == tu::str(*local, "kcb2.lid"));
    const Value* wrap = root.get("local-wrap");
    REQUIRE(wrap != nullptr);
    auto wk = LocalKey::from_bytes(tu::unhex(tu::str(*wrap, "wrapping-key")));
    REQUIRE(wk.is_ok());
    auto w = cb2::KeyWrap::wrap_with_nonce_for_testing(wk.value(), k.value(), tu::unhex(tu::str(*wrap, "nonce")));
    REQUIRE(w.is_ok());
    CHECK(w.value() == tu::str(*wrap, "kcb2.local-wrap"));
    auto u = cb2::KeyWrap::unwrap(tu::str(*wrap, "kcb2.local-wrap"), wk.value());
    REQUIRE(u.is_ok());
    CHECK(u.value().paserk_id() == k.value().paserk_id());
#ifdef CB2_HAS_PQ
    const Value* pub = root.get("public");
    REQUIRE(pub != nullptr);
    auto sk = cb2::SecretKey::from_bytes(tu::unhex(tu::str(*pub, "secret-key")));
    REQUIRE(sk.is_ok());
    const cb2::PublicKey pk = sk.value().public_key();
    CHECK(pk.to_paserk() == tu::str(*pub, "kcb2.public"));
    CHECK(pk.paserk_id() == tu::str(*pub, "kcb2.pid"));
    const cb2::SecureString sp = sk.value().to_paserk();
    CHECK(std::string(sp.data(), sp.size()) == tu::str(*pub, "kcb2.secret"));
    CHECK(tu::hex(pk.bytes()) == tu::str(*pub, "public-key"));
#endif
}

namespace {

LocalKey cb3_key(const Value& v, const char* field = "key") {
    LocalKey k = LocalKey::from_bytes(tu::unhex(tu::str(v, field))).value();
    const Value* id = v.get("key-id");
    if (id != nullptr && id->kind == Value::Kind::null) k.clear_key_id();
    if (id != nullptr && id->is_string()) k.set_key_id(id->text);
    return k;
}

Bytes text_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

}

TEST_CASE("vectors/cb3.local vectors reproduce, open and record their intermediates") {
    Value root;
    REQUIRE(load("cb3.json", root));
    const Value* local = root.get("local");
    REQUIRE(local != nullptr && !local->items.empty());
    for (const Value& v : local->items) {
        const LocalKey k = cb3_key(v);
        const Claims c = Claims::from_json(tu::str(v, "claims")).value();
        const std::string payload = cb2::CompactClaims::encode(c).value();
        CHECK(tu::hex(text_bytes(payload)) == tu::str(v, "payload"));
        const std::string footer = cb2::CompactToken::footer_for(k.key_id());
        CHECK(tu::hex(text_bytes(footer)) == tu::str(v, "footer"));
        const std::string implicit = tu::str(v, "implicit-assertion");
        const auto tok = cb2::CompactToken::seal_with_nonce_for_testing(k, c, tu::unhex(tu::str(v, "nonce")), implicit);
        REQUIRE(tok.is_ok());
        CHECK(tok.value() == tu::str(v, "token"));
        const auto opened = cb2::CompactToken::open(tok.value(), k, ValidationRules().allow_any_audience().allow_any_issuer().allow_missing_exp().at(1700000000).ignore_sender_constraint(), implicit);
        REQUIRE(opened.is_ok());
        CHECK(opened.value().to_json() == tu::str(v, "claims"));
        check_local_intermediates(v, tu::unhex(tu::str(v, "key")), tu::unhex(tu::str(v, "nonce")), text_bytes(payload),
                                  text_bytes(footer), text_bytes(implicit), tok.value(),
                                  cb2::CompactToken::LOCAL_HEADER);
    }
}

TEST_CASE("vectors/cb3 opens, profile, refused and tamper vectors yield their verdicts") {
    Value root;
    REQUIRE(load("cb3.json", root));
    const LocalKey key = LocalKey::from_bytes(tu::unhex(tu::str(root, "open-key"))).value();
    for (const Value& v : root.get("opens")->items) {
        LocalKey k = LocalKey::from_bytes(tu::unhex(tu::str(root, "open-key"))).value();
        if (v.get("verifier-key-id") != nullptr) k.set_key_id(tu::str(v, "verifier-key-id"));
        const auto r = cb2::CompactToken::open(tu::str(v, "token"), k, rules_of(v));
        CHECK(verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error()) == tu::str(v, "expect"));
    }
    for (const Value& v : root.get("profile")->items) {
        const auto r = cb2::CompactClaims::decode(tu::unhex(tu::str(v, "payload")));
        CHECK(verdict_name(r.is_ok(), r.is_ok() ? Error::internal : r.error()) == tu::str(v, "expect"));
        if (r.is_ok()) CHECK(r.value().to_json() == tu::str(v, "claims"));
    }
    for (const Value& v : root.get("refused")->items) {
        const auto c = Claims::from_json(tu::str(v, "claims"));
        REQUIRE(c.is_ok());
        CHECK(cb2::CompactClaims::encode(c.value()).error() == Error::argument);
    }
    const Value* tamper = root.get("tamper");
    REQUIRE(tamper != nullptr);
    const ValidationRules any = ValidationRules().allow_any_audience().allow_any_issuer().allow_missing_exp().at(1700000000);
    CHECK(cb2::CompactToken::open(tu::str(*tamper, "token"), key, any).is_ok());
    for (const Value& c : tamper->get("cases")->items) {
        const auto r = cb2::CompactToken::open(tu::str(c, "token"), key, any);
        CHECK(r.is_err() && r.error() == Error::invalid);
    }
    const Value* relabelled = root.get("relabelled-as-cb2");
    REQUIRE(relabelled != nullptr);
    CHECK(Local::open(tu::str(*relabelled, "token"), key, cb2::bytes(tu::str(*relabelled, "footer"))).error() == Error::invalid);
}

#ifdef CB2_HAS_PQ
TEST_CASE("vectors/cb3.public vectors verify to their claims") {
    Value root;
    REQUIRE(load("cb3.json", root));
    const Value* pub = root.get("public");
    REQUIRE(pub != nullptr && !pub->items.empty());
    for (const Value& v : pub->items) {
        const auto pk = cb2::PublicKey::from_bytes(tu::unhex(tu::str(v, "public-key"))).value();
        const auto r = cb2::CompactToken::verify(tu::str(v, "token"), pk,
                                                 ValidationRules().allow_any_audience().allow_any_issuer().allow_missing_exp().at(1700000000).ignore_sender_constraint());
        REQUIRE(r.is_ok());
        CHECK(r.value().to_json() == tu::str(v, "claims"));
        CHECK(tu::hex(text_bytes(cb2::CompactClaims::encode(r.value()).value())) == tu::str(v, "payload"));
        CHECK(Token::verify(tu::str(v, "token"), pk, ValidationRules().allow_any_audience().allow_any_issuer().allow_missing_exp().at(1700000000)).error() == Error::invalid);
    }
}
#endif
