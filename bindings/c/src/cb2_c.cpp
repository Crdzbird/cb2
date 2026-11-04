/**
 * The C ABI of cb2 over the C++ library: opaque key handles, malloc'd
 * results, integer codes, claims and rules as JSON text. Every entry
 * point catches everything and reports CB2_INTERNAL for what the library
 * never produces itself.
 */

#include "cb2_c.h"

#include <cb2/cb2.hpp>

#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct cb2_local_key { cb2::LocalKey key; };
#ifdef CB2_HAS_PQ
struct cb2_secret_key { cb2::SecretKey key; };
struct cb2_public_key { cb2::PublicKey key; };
#endif
#ifdef CB2_HAS_SEAL
struct cb2_recipient_key { cb2::RecipientKey key; };
struct cb2_recipient_public_key { cb2::RecipientPublicKey key; };
#endif

namespace {

using cb2::Error;

int code_of(Error e) { return static_cast<int>(e) + 1; }

std::string_view sv(const char* p, std::size_t n) { return p == nullptr ? std::string_view() : std::string_view(p, n); }

std::span<const uint8_t> bytes_of(const uint8_t* p, std::size_t n) {
    return p == nullptr ? std::span<const uint8_t>() : std::span<const uint8_t>(p, n);
}

/// A malloc'd NUL-terminated copy; NULL when the allocation fails.
char* dup_text(std::string_view s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p == nullptr) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

int give_text(std::string_view s, char** out, std::size_t* out_len) {
    char* p = dup_text(s);
    if (p == nullptr) return CB2_INTERNAL;
    *out = p;
    if (out_len != nullptr) *out_len = s.size();
    return CB2_OK;
}

int give_bytes(std::span<const uint8_t> b, uint8_t** out, std::size_t* out_len) {
    auto* p = static_cast<uint8_t*>(std::malloc(b.size() + 1));
    if (p == nullptr) return CB2_INTERNAL;
    if (!b.empty()) std::memcpy(p, b.data(), b.size());
    p[b.size()] = 0;
    *out = p;
    *out_len = b.size();
    return CB2_OK;
}

template <class F>
int guarded(F&& f) noexcept {
    try {
        return f();
    } catch (...) {
        return CB2_INTERNAL;
    }
}

template <class Key, class Wrapper>
int wrap_key(cb2::Result<Key> r, Wrapper** out) {
    if (r.is_err()) return code_of(r.error());
    *out = new Wrapper{std::move(r).value()};
    return CB2_OK;
}

char* optional_text(const std::optional<std::string>& s) { return s ? dup_text(*s) : nullptr; }

struct Rules {
    cb2::ValidationRules rules;
    bool want_replay = false;
    bool want_proof_replay = false;
};

bool read_rules(std::string_view json, Rules& r) {
    cb2::json::Value root;
    if (json.empty()) return true;
    if (!cb2::json::Reader::parse(json, root) || !root.is_object()) return false;
    auto num = [&](const char* k, long long& v) {
        const cb2::json::Value* m = root.get(k);
        if (m == nullptr) return false;
        if (m->kind != cb2::json::Value::Kind::number) return false;
        v = std::stoll(m->text);
        return true;
    };
    auto flag = [&](const char* k) {
        const cb2::json::Value* m = root.get(k);
        return m != nullptr && m->kind == cb2::json::Value::Kind::boolean && m->b;
    };
    auto text = [&](const char* k) -> std::optional<std::string> {
        const cb2::json::Value* m = root.get(k);
        if (m == nullptr || !m->is_string()) return std::nullopt;
        return m->text;
    };
    long long n = 0;
    if (num("now", n)) r.rules.at(n);
    if (num("clock_skew", n)) r.rules.with_clock_skew(n);
    if (const cb2::json::Value* m = root.get("require_exp"); m != nullptr && m->kind == cb2::json::Value::Kind::boolean && !m->b)
        r.rules.allow_missing_exp();
    if (flag("allow_any_audience")) r.rules.allow_any_audience();
    if (flag("allow_any_issuer")) r.rules.allow_any_issuer();
    if (auto v = text("issuer")) r.rules.expect_issuer(*v);
    if (auto v = text("audience")) r.rules.expect_audience(*v);
    if (auto v = text("subject")) r.rules.expect_subject(*v);
    if (num("max_token_bytes", n) && n > 0) r.rules.with_max_token_bytes(static_cast<std::size_t>(n));
    if (num("max_lifetime", n)) r.rules.with_max_lifetime(n);
    if (flag("require_cnf")) r.rules.require_sender_constraint();
    if (flag("ignore_cnf")) r.rules.ignore_sender_constraint();
    if (num("proof_lifetime", n)) r.rules.with_proof_lifetime(n);
    r.want_replay = flag("replay");
    if (const cb2::json::Value* seen = root.get("seen_jti"); seen != nullptr && seen->kind == cb2::json::Value::Kind::array) {
        std::vector<std::string> ids;
        for (const auto& j : seen->items) if (j.is_string()) ids.push_back(j.text);
        r.rules.with_replay_check([ids](std::string_view jti) {
            for (const auto& s : ids) if (s == jti) return false;
            return true;
        });
        r.want_replay = false;
    }
    if (auto proof = text("proof")) {
        cb2::HolderRequest req;
        if (const cb2::json::Value* q = root.get("request"); q != nullptr && q->is_object()) {
            if (const cb2::json::Value* m = q->get("htm"); m != nullptr && m->is_string()) req.method = m->text;
            if (const cb2::json::Value* m = q->get("htu"); m != nullptr && m->is_string()) req.target = m->text;
            if (const cb2::json::Value* m = q->get("nonce"); m != nullptr && m->is_string()) req.nonce = m->text;
        }
        r.rules.with_holder_proof(*proof, std::move(req));
        r.want_proof_replay = true;
        if (const cb2::json::Value* seen = root.get("proof_seen_jti"); seen != nullptr && seen->kind == cb2::json::Value::Kind::array) {
            std::vector<std::string> ids;
            for (const auto& j : seen->items) if (j.is_string()) ids.push_back(j.text);
            r.rules.with_proof_replay_check([ids](std::string_view jti) {
                for (const auto& s : ids) if (s == jti) return false;
                return true;
            });
            r.want_proof_replay = false;
        }
    }
    return true;
}

/// Installs the C callbacks the rules asked for. A proof without any
/// proof replay check is left incomplete for the library to refuse.
void install_callbacks(Rules& r, cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user) {
    if (r.want_replay && replay != nullptr)
        r.rules.with_replay_check([replay, user](std::string_view jti) { return replay(user, jti.data(), jti.size()) == 1; });
    if (r.want_proof_replay && proof_replay != nullptr)
        r.rules.with_proof_replay_check([proof_replay, user](std::string_view jti) { return proof_replay(user, jti.data(), jti.size()) == 1; });
}

int finish_claims(cb2::Result<cb2::Claims> r, char** out_claims, std::size_t* out_len) {
    if (r.is_err()) return code_of(r.error());
    return give_text(r.value().to_json(), out_claims, out_len);
}

}

extern "C" {

const char* cb2_version(void) { return cb2::VERSION.data(); }

int cb2_has_public(void) {
#ifdef CB2_HAS_PQ
    return 1;
#else
    return 0;
#endif
}

int cb2_has_seal(void) {
#ifdef CB2_HAS_SEAL
    return 1;
#else
    return 0;
#endif
}

const char* cb2_error_name(int code) {
    if (code == CB2_OK) return "ok";
    if (code < 1 || code > CB2_PROOF_REPLAYED) return "unknown";
    return cb2::error_name(static_cast<Error>(code - 1));
}

void cb2_free(void* p) { std::free(p); }

void cb2_free_secret(char* s) {
    if (s == nullptr) return;
    sodium_memzero(s, std::strlen(s));
    std::free(s);
}

/* Local keys */

int cb2_local_key_generate(cb2_local_key** out) {
    return guarded([&] { return wrap_key(cb2::LocalKey::generate(), out); });
}

int cb2_local_key_from_bytes(const uint8_t* bytes, size_t len, cb2_local_key** out) {
    return guarded([&] { return wrap_key(cb2::LocalKey::from_bytes(bytes_of(bytes, len)), out); });
}

int cb2_local_key_from_paserk(const char* text, size_t len, cb2_local_key** out) {
    return guarded([&] { return wrap_key(cb2::LocalKey::from_paserk(sv(text, len)), out); });
}

char* cb2_local_key_to_paserk(const cb2_local_key* key) {
    const cb2::SecureString p = key->key.to_paserk();
    return dup_text(std::string_view(p.data(), p.size()));
}

char* cb2_local_key_paserk_id(const cb2_local_key* key) { return dup_text(key->key.paserk_id()); }
char* cb2_local_key_key_id(const cb2_local_key* key) { return optional_text(key->key.key_id()); }

int cb2_local_key_set_key_id(cb2_local_key* key, const char* id, size_t len) {
    return guarded([&] {
        if (!cb2::text::identifier_ok(sv(id, len))) return static_cast<int>(CB2_ARGUMENT);
        key->key.set_key_id(std::string(sv(id, len)));
        return static_cast<int>(CB2_OK);
    });
}

void cb2_local_key_clear_key_id(cb2_local_key* key) { key->key.clear_key_id(); }
void cb2_local_key_free(cb2_local_key* key) { delete key; }

/* Signing pairs */

#ifdef CB2_HAS_PQ
int cb2_secret_key_generate(cb2_secret_key** out) {
    return guarded([&] { return wrap_key(cb2::SecretKey::generate(), out); });
}
int cb2_secret_key_from_bytes(const uint8_t* bytes, size_t len, cb2_secret_key** out) {
    return guarded([&] { return wrap_key(cb2::SecretKey::from_bytes(bytes_of(bytes, len)), out); });
}
int cb2_secret_key_from_paserk(const char* text, size_t len, cb2_secret_key** out) {
    return guarded([&] { return wrap_key(cb2::SecretKey::from_paserk(sv(text, len)), out); });
}
char* cb2_secret_key_to_paserk(const cb2_secret_key* key) {
    const cb2::SecureString p = key->key.to_paserk();
    return dup_text(std::string_view(p.data(), p.size()));
}
int cb2_secret_key_public_key(const cb2_secret_key* key, cb2_public_key** out) {
    return guarded([&] {
        *out = new cb2_public_key{key->key.public_key()};
        return static_cast<int>(CB2_OK);
    });
}
char* cb2_secret_key_key_id(const cb2_secret_key* key) { return optional_text(key->key.key_id()); }
int cb2_secret_key_set_key_id(cb2_secret_key* key, const char* id, size_t len) {
    return guarded([&] {
        if (!cb2::text::identifier_ok(sv(id, len))) return static_cast<int>(CB2_ARGUMENT);
        key->key.set_key_id(std::string(sv(id, len)));
        return static_cast<int>(CB2_OK);
    });
}
void cb2_secret_key_clear_key_id(cb2_secret_key* key) { key->key.clear_key_id(); }
void cb2_secret_key_free(cb2_secret_key* key) { delete key; }

int cb2_public_key_from_bytes(const uint8_t* bytes, size_t len, cb2_public_key** out) {
    return guarded([&] { return wrap_key(cb2::PublicKey::from_bytes(bytes_of(bytes, len)), out); });
}
int cb2_public_key_from_paserk(const char* text, size_t len, cb2_public_key** out) {
    return guarded([&] { return wrap_key(cb2::PublicKey::from_paserk(sv(text, len)), out); });
}
char* cb2_public_key_to_paserk(const cb2_public_key* key) { return dup_text(key->key.to_paserk()); }
char* cb2_public_key_paserk_id(const cb2_public_key* key) { return dup_text(key->key.paserk_id()); }
char* cb2_public_key_key_id(const cb2_public_key* key) { return optional_text(key->key.key_id()); }
int cb2_public_key_set_key_id(cb2_public_key* key, const char* id, size_t len) {
    return guarded([&] {
        if (!cb2::text::identifier_ok(sv(id, len))) return static_cast<int>(CB2_ARGUMENT);
        key->key.set_key_id(std::string(sv(id, len)));
        return static_cast<int>(CB2_OK);
    });
}
void cb2_public_key_clear_key_id(cb2_public_key* key) { key->key.clear_key_id(); }
void cb2_public_key_free(cb2_public_key* key) { delete key; }
#else
int cb2_secret_key_generate(cb2_secret_key**) { return CB2_UNAVAILABLE; }
int cb2_secret_key_from_bytes(const uint8_t*, size_t, cb2_secret_key**) { return CB2_UNAVAILABLE; }
int cb2_secret_key_from_paserk(const char*, size_t, cb2_secret_key**) { return CB2_UNAVAILABLE; }
char* cb2_secret_key_to_paserk(const cb2_secret_key*) { return nullptr; }
int cb2_secret_key_public_key(const cb2_secret_key*, cb2_public_key**) { return CB2_UNAVAILABLE; }
char* cb2_secret_key_key_id(const cb2_secret_key*) { return nullptr; }
int cb2_secret_key_set_key_id(cb2_secret_key*, const char*, size_t) { return CB2_UNAVAILABLE; }
void cb2_secret_key_clear_key_id(cb2_secret_key*) {}
void cb2_secret_key_free(cb2_secret_key*) {}
int cb2_public_key_from_bytes(const uint8_t*, size_t, cb2_public_key**) { return CB2_UNAVAILABLE; }
int cb2_public_key_from_paserk(const char*, size_t, cb2_public_key**) { return CB2_UNAVAILABLE; }
char* cb2_public_key_to_paserk(const cb2_public_key*) { return nullptr; }
char* cb2_public_key_paserk_id(const cb2_public_key*) { return nullptr; }
char* cb2_public_key_key_id(const cb2_public_key*) { return nullptr; }
int cb2_public_key_set_key_id(cb2_public_key*, const char*, size_t) { return CB2_UNAVAILABLE; }
void cb2_public_key_clear_key_id(cb2_public_key*) {}
void cb2_public_key_free(cb2_public_key*) {}
#endif

/* Recipient pairs */

#ifdef CB2_HAS_SEAL
int cb2_recipient_key_generate(cb2_recipient_key** out) {
    return guarded([&] { return wrap_key(cb2::RecipientKey::generate(), out); });
}
int cb2_recipient_key_from_bytes(const uint8_t* bytes, size_t len, cb2_recipient_key** out) {
    return guarded([&] { return wrap_key(cb2::RecipientKey::from_bytes(bytes_of(bytes, len)), out); });
}
int cb2_recipient_key_from_paserk(const char* text, size_t len, cb2_recipient_key** out) {
    return guarded([&] { return wrap_key(cb2::RecipientKey::from_paserk(sv(text, len)), out); });
}
char* cb2_recipient_key_to_paserk(const cb2_recipient_key* key) {
    const cb2::SecureString p = key->key.to_paserk();
    return dup_text(std::string_view(p.data(), p.size()));
}
int cb2_recipient_key_public_key(const cb2_recipient_key* key, cb2_recipient_public_key** out) {
    return guarded([&] {
        *out = new cb2_recipient_public_key{key->key.public_key()};
        return static_cast<int>(CB2_OK);
    });
}
char* cb2_recipient_key_paserk_id(const cb2_recipient_key* key) { return dup_text(key->key.paserk_id()); }
void cb2_recipient_key_free(cb2_recipient_key* key) { delete key; }
int cb2_recipient_public_key_from_bytes(const uint8_t* bytes, size_t len, cb2_recipient_public_key** out) {
    return guarded([&] { return wrap_key(cb2::RecipientPublicKey::from_bytes(bytes_of(bytes, len)), out); });
}
int cb2_recipient_public_key_from_paserk(const char* text, size_t len, cb2_recipient_public_key** out) {
    return guarded([&] { return wrap_key(cb2::RecipientPublicKey::from_paserk(sv(text, len)), out); });
}
char* cb2_recipient_public_key_to_paserk(const cb2_recipient_public_key* key) { return dup_text(key->key.to_paserk()); }
char* cb2_recipient_public_key_paserk_id(const cb2_recipient_public_key* key) { return dup_text(key->key.paserk_id()); }
void cb2_recipient_public_key_free(cb2_recipient_public_key* key) { delete key; }
#else
int cb2_recipient_key_generate(cb2_recipient_key**) { return CB2_UNAVAILABLE; }
int cb2_recipient_key_from_bytes(const uint8_t*, size_t, cb2_recipient_key**) { return CB2_UNAVAILABLE; }
int cb2_recipient_key_from_paserk(const char*, size_t, cb2_recipient_key**) { return CB2_UNAVAILABLE; }
char* cb2_recipient_key_to_paserk(const cb2_recipient_key*) { return nullptr; }
int cb2_recipient_key_public_key(const cb2_recipient_key*, cb2_recipient_public_key**) { return CB2_UNAVAILABLE; }
char* cb2_recipient_key_paserk_id(const cb2_recipient_key*) { return nullptr; }
void cb2_recipient_key_free(cb2_recipient_key*) {}
int cb2_recipient_public_key_from_bytes(const uint8_t*, size_t, cb2_recipient_public_key**) { return CB2_UNAVAILABLE; }
int cb2_recipient_public_key_from_paserk(const char*, size_t, cb2_recipient_public_key**) { return CB2_UNAVAILABLE; }
char* cb2_recipient_public_key_to_paserk(const cb2_recipient_public_key*) { return nullptr; }
char* cb2_recipient_public_key_paserk_id(const cb2_recipient_public_key*) { return nullptr; }
void cb2_recipient_public_key_free(cb2_recipient_public_key*) {}
#endif

/* Raw tokens */

int cb2_local_seal(const cb2_local_key* key, const uint8_t* msg, size_t msg_len, const uint8_t* footer, size_t footer_len,
                   const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len) {
    return guarded([&] {
        auto r = cb2::Local::seal(key->key, bytes_of(msg, msg_len), bytes_of(footer, footer_len), bytes_of(implicit, implicit_len));
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out_token, out_len);
    });
}

int cb2_local_open(const cb2_local_key* key, const char* token, size_t token_len, const uint8_t* footer, size_t footer_len,
                   const uint8_t* implicit, size_t implicit_len, size_t max_token_bytes, uint8_t** out_msg, size_t* out_len) {
    return guarded([&] {
        auto r = cb2::Local::open(sv(token, token_len), key->key, bytes_of(footer, footer_len), bytes_of(implicit, implicit_len),
                                  max_token_bytes == 0 ? cb2::DEFAULT_RAW_MAX_TOKEN_BYTES : max_token_bytes);
        if (r.is_err()) return code_of(r.error());
        return give_bytes(r.value(), out_msg, out_len);
    });
}

int cb2_public_sign(const cb2_secret_key* key, const uint8_t* msg, size_t msg_len, const uint8_t* footer, size_t footer_len,
                    const uint8_t* implicit, size_t implicit_len, char** out_token, size_t* out_len) {
#ifdef CB2_HAS_PQ
    return guarded([&] {
        auto r = cb2::Public::sign(key->key, bytes_of(msg, msg_len), bytes_of(footer, footer_len), bytes_of(implicit, implicit_len));
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out_token, out_len);
    });
#else
    (void)key; (void)msg; (void)msg_len; (void)footer; (void)footer_len; (void)implicit; (void)implicit_len; (void)out_token; (void)out_len;
    return CB2_UNAVAILABLE;
#endif
}

int cb2_public_verify(const cb2_public_key* key, const char* token, size_t token_len, const uint8_t* footer, size_t footer_len,
                      const uint8_t* implicit, size_t implicit_len, size_t max_token_bytes, uint8_t** out_msg, size_t* out_len) {
#ifdef CB2_HAS_PQ
    return guarded([&] {
        auto r = cb2::Public::verify(sv(token, token_len), key->key, bytes_of(footer, footer_len), bytes_of(implicit, implicit_len),
                                     max_token_bytes == 0 ? cb2::DEFAULT_RAW_MAX_TOKEN_BYTES : max_token_bytes);
        if (r.is_err()) return code_of(r.error());
        return give_bytes(r.value(), out_msg, out_len);
    });
#else
    (void)key; (void)token; (void)token_len; (void)footer; (void)footer_len; (void)implicit; (void)implicit_len; (void)max_token_bytes; (void)out_msg; (void)out_len;
    return CB2_UNAVAILABLE;
#endif
}

/* Claims tokens */

int cb2_token_seal(const cb2_local_key* key, const char* claims_json, size_t claims_len, const uint8_t* implicit, size_t implicit_len,
                   char** out_token, size_t* out_len) {
    return guarded([&] {
        auto c = cb2::Claims::from_json(sv(claims_json, claims_len));
        if (c.is_err()) return static_cast<int>(CB2_ARGUMENT);
        const std::string_view imp(reinterpret_cast<const char*>(implicit), implicit == nullptr ? 0 : implicit_len);
        auto r = cb2::Token::seal(key->key, c.value(), imp);
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out_token, out_len);
    });
}

int cb2_token_sign(const cb2_secret_key* key, const char* claims_json, size_t claims_len, const uint8_t* implicit, size_t implicit_len,
                   char** out_token, size_t* out_len) {
#ifdef CB2_HAS_PQ
    return guarded([&] {
        auto c = cb2::Claims::from_json(sv(claims_json, claims_len));
        if (c.is_err()) return static_cast<int>(CB2_ARGUMENT);
        const std::string_view imp(reinterpret_cast<const char*>(implicit), implicit == nullptr ? 0 : implicit_len);
        auto r = cb2::Token::sign(key->key, c.value(), imp);
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out_token, out_len);
    });
#else
    (void)key; (void)claims_json; (void)claims_len; (void)implicit; (void)implicit_len; (void)out_token; (void)out_len;
    return CB2_UNAVAILABLE;
#endif
}

int cb2_token_open(const cb2_local_key* key, const char* token, size_t token_len, const char* rules_json, size_t rules_len,
                   const uint8_t* implicit, size_t implicit_len, cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                   char** out_claims, size_t* out_len) {
    return guarded([&] {
        Rules r;
        if (!read_rules(sv(rules_json, rules_len), r)) return static_cast<int>(CB2_ARGUMENT);
        install_callbacks(r, replay, proof_replay, user);
        const std::string_view imp(reinterpret_cast<const char*>(implicit), implicit == nullptr ? 0 : implicit_len);
        return finish_claims(cb2::Token::open(sv(token, token_len), key->key, r.rules, imp), out_claims, out_len);
    });
}

int cb2_token_verify(const cb2_public_key* key, const char* token, size_t token_len, const char* rules_json, size_t rules_len,
                     const uint8_t* implicit, size_t implicit_len, cb2_replay_fn replay, cb2_replay_fn proof_replay, void* user,
                     char** out_claims, size_t* out_len) {
#ifdef CB2_HAS_PQ
    return guarded([&] {
        Rules r;
        if (!read_rules(sv(rules_json, rules_len), r)) return static_cast<int>(CB2_ARGUMENT);
        install_callbacks(r, replay, proof_replay, user);
        const std::string_view imp(reinterpret_cast<const char*>(implicit), implicit == nullptr ? 0 : implicit_len);
        return finish_claims(cb2::Token::verify(sv(token, token_len), key->key, r.rules, imp), out_claims, out_len);
    });
#else
    (void)key; (void)token; (void)token_len; (void)rules_json; (void)rules_len; (void)implicit; (void)implicit_len;
    (void)replay; (void)proof_replay; (void)user; (void)out_claims; (void)out_len;
    return CB2_UNAVAILABLE;
#endif
}

int cb2_peek_key_id(const char* token, size_t token_len, char** out_id) {
    return guarded([&] {
        const auto kid = cb2::Token::peek_key_id(sv(token, token_len));
        *out_id = kid ? dup_text(kid->value) : nullptr;
        return static_cast<int>(CB2_OK);
    });
}

/* Holder proofs */

int cb2_holder_prove(const cb2_secret_key* client, const char* htm, size_t htm_len, const char* htu, size_t htu_len,
                     const char* nonce, size_t nonce_len, const char* access_token, size_t access_len,
                     const char* jti, size_t jti_len, int64_t now, int64_t lifetime, char** out_proof, size_t* out_len) {
#ifdef CB2_HAS_PQ
    return guarded([&] {
        cb2::HolderRequest req;
        req.method = std::string(sv(htm, htm_len));
        req.target = std::string(sv(htu, htu_len));
        if (nonce != nullptr) req.nonce = std::string(sv(nonce, nonce_len));
        auto r = cb2::HolderProof::make(client->key, req, sv(access_token, access_len), sv(jti, jti_len), now, lifetime);
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out_proof, out_len);
    });
#else
    (void)client; (void)htm; (void)htm_len; (void)htu; (void)htu_len; (void)nonce; (void)nonce_len; (void)access_token; (void)access_len;
    (void)jti; (void)jti_len; (void)now; (void)lifetime; (void)out_proof; (void)out_len;
    return CB2_UNAVAILABLE;
#endif
}

int cb2_holder_normalize_target(const char* uri, size_t len, char** out) {
    return guarded([&] {
        const auto t = cb2::Holder::normalize_target(sv(uri, len));
        if (!t) return static_cast<int>(CB2_ARGUMENT);
        return give_text(*t, out, nullptr);
    });
}

/* Wrapping and sealing */

int cb2_wrap(const cb2_local_key* wrapping, const cb2_local_key* key, char** out) {
    return guarded([&] {
        auto r = cb2::KeyWrap::wrap(wrapping->key, key->key);
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out, nullptr);
    });
}

int cb2_unwrap(const char* text, size_t len, const cb2_local_key* wrapping, cb2_local_key** out) {
    return guarded([&] { return wrap_key(cb2::KeyWrap::unwrap(sv(text, len), wrapping->key), out); });
}

int cb2_seal(const cb2_recipient_public_key* to, const cb2_local_key* key, char** out) {
#ifdef CB2_HAS_SEAL
    return guarded([&] {
        auto r = cb2::Seal::seal(to->key, key->key);
        if (r.is_err()) return code_of(r.error());
        return give_text(r.value(), out, nullptr);
    });
#else
    (void)to; (void)key; (void)out;
    return CB2_UNAVAILABLE;
#endif
}

int cb2_unseal(const char* text, size_t len, const cb2_recipient_key* by, cb2_local_key** out) {
#ifdef CB2_HAS_SEAL
    return guarded([&] { return wrap_key(cb2::Seal::unseal(sv(text, len), by->key), out); });
#else
    (void)text; (void)len; (void)by; (void)out;
    return CB2_UNAVAILABLE;
#endif
}

}
