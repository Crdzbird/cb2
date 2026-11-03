/**
 * cb2 playground: a line-oriented session with the library.
 *
 * Generate and import keys, seal and open cb2.local tokens, sign and
 * verify cb2.public tokens, build claims and check them under rules,
 * wrap keys, peek at a token's footer, tamper with a token and watch the
 * verdict change. Every command prints what it did as "name = value"
 * lines; verdicts print as "verdict = ok" or "verdict = <error name>".
 *
 * Interactive: ./build/cb2_playground
 * Scripted:    ./build/cb2_playground playground/demo.cb2
 *
 * A script is the same commands, one per line, with # comments; "assert
 * <verdict>" checks the last verdict and the process exits non-zero if any
 * assert fails or a command is malformed, so a script doubles as a test.
 * The token "$" in any argument stands for the last token produced.
 */

#include <cb2/cb2.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace {

using cb2::Error;
using Args = std::vector<std::string>;

struct Session {
    std::map<std::string, cb2::LocalKey> local;
#ifdef CB2_HAS_PQ
    std::map<std::string, cb2::SecretKey> secret;
    std::map<std::string, cb2::PublicKey> pub;
#endif
    std::set<std::string> seen_jti;
    std::string last_token;
    std::string last_verdict = "none";
    int failures = 0;
};

std::span<const uint8_t> sp(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

void say(std::string_view name, std::string_view value) {
    std::printf("%.*s = %.*s\n", static_cast<int>(name.size()), name.data(),
                static_cast<int>(value.size()), value.data());
}

void verdict(Session& s, std::string_view v) {
    s.last_verdict = std::string(v);
    say("verdict", v);
}

void verdict(Session& s, Error e) { verdict(s, cb2::error_name(e)); }

bool fail(Session& s, std::string_view what) {
    std::printf("error: %.*s\n", static_cast<int>(what.size()), what.data());
    ++s.failures;
    return false;
}

std::string hex(std::span<const uint8_t> b) {
    static constexpr char DIGITS[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t x : b) {
        out += DIGITS[x >> 4];
        out += DIGITS[x & 15];
    }
    return out;
}

std::string show_bytes(std::span<const uint8_t> b) {
    const std::string_view text(reinterpret_cast<const char*>(b.data()), b.size());
    bool plain = cb2::text::valid_utf8(text);
    for (uint8_t x : b) {
        if (x < 0x20 || x == 0x7f) plain = false;
    }
    if (plain) return "\"" + std::string(text) + "\"";
    return "hex:" + hex(b);
}

Args split(std::string_view line) {
    Args out;
    std::string cur;
    bool quoted = false;
    bool have = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (quoted) {
            if (c == '\\' && i + 1 < line.size()) {
                cur += line[++i];
                continue;
            }
            if (c == '"') {
                quoted = false;
                continue;
            }
            cur += c;
            continue;
        }
        if (c == '"') {
            quoted = true;
            have = true;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            if (have) {
                out.push_back(cur);
                cur.clear();
                have = false;
            }
            continue;
        }
        cur += c;
        have = true;
    }
    if (have) out.push_back(cur);
    return out;
}

std::optional<std::pair<std::string, std::string>> key_value(std::string_view arg) {
    const std::size_t eq = arg.find('=');
    if (eq == std::string_view::npos || eq == 0) return std::nullopt;
    return std::pair{std::string(arg.substr(0, eq)), std::string(arg.substr(eq + 1))};
}

bool all_digits(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

cb2::Seconds now_seconds() { return static_cast<cb2::Seconds>(std::time(nullptr)); }

/// "+3600" and "-60" are relative to now, digits are Unix seconds, anything
/// else must be RFC 3339.
bool parse_time(std::string_view s, cb2::Seconds& out) {
    if (!s.empty() && (s[0] == '+' || s[0] == '-') && all_digits(s.substr(1))) {
        const long long n = std::atoll(std::string(s.substr(1)).c_str());
        out = now_seconds() + (s[0] == '+' ? n : -n);
        return true;
    }
    if (all_digits(s)) {
        out = std::atoll(std::string(s).c_str());
        return true;
    }
    return cb2::Rfc3339::parse(s, out);
}

std::string time_text(cb2::Seconds t) {
    return std::to_string(t) + " (" + cb2::Rfc3339::format(t) + ")";
}

const cb2::LocalKey* find_local(Session& s, const std::string& name) {
    const auto it = s.local.find(name);
    return it == s.local.end() ? nullptr : &it->second;
}

#ifdef CB2_HAS_PQ
const cb2::SecretKey* find_secret(Session& s, const std::string& name) {
    const auto it = s.secret.find(name);
    return it == s.secret.end() ? nullptr : &it->second;
}

std::optional<cb2::PublicKey> find_public(Session& s, const std::string& name) {
    const auto it = s.pub.find(name);
    if (it != s.pub.end()) return it->second;
    if (const cb2::SecretKey* sk = find_secret(s, name)) return sk->public_key();
    return std::nullopt;
}
#endif

void describe_local(const std::string& name, const cb2::LocalKey& k) {
    const cb2::SecureString p = k.to_paserk();
    say("key", name);
    say("kcb2.local", std::string_view(p.data(), p.size()));
    say("kcb2.lid", k.paserk_id());
    say("kid", k.key_id() ? *k.key_id() : "none");
}

#ifdef CB2_HAS_PQ
void describe_secret(const std::string& name, const cb2::SecretKey& k) {
    const cb2::SecureString p = k.to_paserk();
    const cb2::PublicKey pk = k.public_key();
    say("key", name);
    say("kcb2.secret", std::string_view(p.data(), p.size()));
    say("kcb2.public", pk.to_paserk());
    say("kcb2.pid", pk.paserk_id());
    say("kid", k.key_id() ? *k.key_id() : "none");
}

void describe_public(const std::string& name, const cb2::PublicKey& k) {
    say("key", name);
    say("kcb2.public", k.to_paserk());
    say("kcb2.pid", k.paserk_id());
    say("kid", k.key_id() ? *k.key_id() : "none");
}
#endif

void help() {
    std::puts(
        "commands (quote arguments that contain spaces; $ is the last token)\n"
        "  keygen local [name]            new 32-byte key, stored under name (default local)\n"
        "  keygen public [name]           new Ed25519 + ML-DSA-65 pair (default signer)\n"
        "  import <kcb2 string> [name]    kcb2.local, kcb2.secret or kcb2.public\n"
        "  keys                           list the stored keys\n"
        "  kid <key> <id>|none            set or clear the key id bound into the footer\n"
        "  seal <key> <msg> [footer] [implicit]      raw cb2.local token\n"
        "  open <key> <token> [footer] [implicit]    message or verdict\n"
        "  sign <key> <msg> [footer] [implicit]      raw cb2.public token\n"
        "  verify <key> <token> [footer] [implicit]  message or verdict\n"
        "  claims <key> [iss=] [aud=] [sub=] [jti=] [exp=] [nbf=] [iat=] [name=value]...\n"
        "                                 [implicit=] seal (local key) or sign (secret key)\n"
        "                                 times: +3600, Unix seconds or RFC 3339\n"
        "  check <key> <token> [iss=] [aud=] [sub=] [any-iss] [any-aud] [skew=] [now=]\n"
        "                                 [replay] [no-exp] [max=] [implicit=]  open or verify\n"
        "  peek <token>                   header, body size, footer and kid, nothing verified\n"
        "  tamper <token> [index]         flip one character (default: last of the body)\n"
        "  wrap <wrapping key> <key>      kcb2.local-wrap string\n"
        "  unwrap <wrapping key> <string> [name]\n"
        "  time                           the clock the playground uses\n"
        "  assert <verdict>               scripts: fail unless the last verdict matches\n"
        "  echo <text>                    print text\n"
        "  help, quit");
}

bool cmd_keygen(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "keygen local|public [name]");
    if (a[1] == "local") {
        const std::string name = a.size() > 2 ? a[2] : "local";
        auto k = cb2::LocalKey::generate();
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_local(name, k.value());
        s.local.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
    if (a[1] == "public") {
#ifdef CB2_HAS_PQ
        const std::string name = a.size() > 2 ? a[2] : "signer";
        auto k = cb2::SecretKey::generate();
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_secret(name, k.value());
        s.secret.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
#else
        verdict(s, Error::unavailable);
#endif
        return true;
    }
    return fail(s, "keygen local|public [name]");
}

bool cmd_import(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "import <kcb2 string> [name]");
    const std::string& text = a[1];
    if (text.rfind("kcb2.local.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "local";
        auto k = cb2::LocalKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_local(name, k.value());
        s.local.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
#ifdef CB2_HAS_PQ
    if (text.rfind("kcb2.secret.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "signer";
        auto k = cb2::SecretKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_secret(name, k.value());
        s.secret.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
    if (text.rfind("kcb2.public.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "verifier";
        auto k = cb2::PublicKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_public(name, k.value());
        s.pub.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
#endif
    verdict(s, Error::argument);
    return true;
}

bool cmd_keys(Session& s, const Args&) {
    for (const auto& [name, k] : s.local) say(name, "local, kid " + (k.key_id() ? *k.key_id() : "none"));
#ifdef CB2_HAS_PQ
    for (const auto& [name, k] : s.secret) say(name, "secret, kid " + (k.key_id() ? *k.key_id() : "none"));
    for (const auto& [name, k] : s.pub) say(name, "public, kid " + (k.key_id() ? *k.key_id() : "none"));
#endif
    return true;
}

bool cmd_kid(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "kid <key> <id>|none");
    bool found = false;
    if (auto it = s.local.find(a[1]); it != s.local.end()) {
        found = true;
        if (a[2] == "none") it->second.clear_key_id();
        else it->second.set_key_id(a[2]);
    }
#ifdef CB2_HAS_PQ
    if (auto it = s.secret.find(a[1]); it != s.secret.end()) {
        found = true;
        if (a[2] == "none") it->second.clear_key_id();
        else it->second.set_key_id(a[2]);
    }
    if (auto it = s.pub.find(a[1]); it != s.pub.end()) {
        found = true;
        if (a[2] == "none") it->second.clear_key_id();
        else it->second.set_key_id(a[2]);
    }
#endif
    if (!found) return fail(s, "no key named " + a[1]);
    say("kid", a[2]);
    say("footer", cb2::Token::footer_for(a[2] == "none" ? std::nullopt : std::optional<std::string>(a[2])));
    return true;
}

void took(Session& s, const std::string& token) {
    s.last_token = token;
    say("token", token);
    say("length", std::to_string(token.size()));
}

bool cmd_seal(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "seal <key> <msg> [footer] [implicit]");
    const cb2::LocalKey* k = find_local(s, a[1]);
    if (k == nullptr) return fail(s, "no local key named " + a[1]);
    const std::string_view footer = a.size() > 3 ? std::string_view(a[3]) : std::string_view{};
    const std::string_view implicit = a.size() > 4 ? std::string_view(a[4]) : std::string_view{};
    auto t = cb2::Local::seal(*k, sp(a[2]), sp(footer), sp(implicit));
    if (t.is_err()) {
        verdict(s, t.error());
        return true;
    }
    took(s, t.value());
    verdict(s, "ok");
    return true;
}

bool cmd_open(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "open <key> <token> [footer] [implicit]");
    const cb2::LocalKey* k = find_local(s, a[1]);
    if (k == nullptr) return fail(s, "no local key named " + a[1]);
    const std::string_view footer = a.size() > 3 ? std::string_view(a[3]) : std::string_view{};
    const std::string_view implicit = a.size() > 4 ? std::string_view(a[4]) : std::string_view{};
    auto m = cb2::Local::open(a[2], *k, sp(footer), sp(implicit));
    if (m.is_err()) {
        verdict(s, m.error());
        return true;
    }
    say("message", show_bytes(m.value()));
    verdict(s, "ok");
    return true;
}

bool cmd_sign(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "sign <key> <msg> [footer] [implicit]");
#ifdef CB2_HAS_PQ
    const cb2::SecretKey* k = find_secret(s, a[1]);
    if (k == nullptr) return fail(s, "no secret key named " + a[1]);
    const std::string_view footer = a.size() > 3 ? std::string_view(a[3]) : std::string_view{};
    const std::string_view implicit = a.size() > 4 ? std::string_view(a[4]) : std::string_view{};
    auto t = cb2::Public::sign(*k, sp(a[2]), sp(footer), sp(implicit));
    if (t.is_err()) {
        verdict(s, t.error());
        return true;
    }
    took(s, t.value());
    verdict(s, "ok");
#else
    verdict(s, Error::unavailable);
#endif
    return true;
}

bool cmd_verify(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "verify <key> <token> [footer] [implicit]");
#ifdef CB2_HAS_PQ
    const std::optional<cb2::PublicKey> k = find_public(s, a[1]);
    if (!k) return fail(s, "no public or secret key named " + a[1]);
    const std::string_view footer = a.size() > 3 ? std::string_view(a[3]) : std::string_view{};
    const std::string_view implicit = a.size() > 4 ? std::string_view(a[4]) : std::string_view{};
    auto m = cb2::Public::verify(a[2], *k, sp(footer), sp(implicit));
    if (m.is_err()) {
        verdict(s, m.error());
        return true;
    }
    say("message", show_bytes(m.value()));
    verdict(s, "ok");
#else
    verdict(s, Error::unavailable);
#endif
    return true;
}

bool cmd_claims(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "claims <key> [iss=] [aud=] [sub=] [jti=] [exp=] [nbf=] [iat=] [name=value]... [implicit=]");
    cb2::Claims c;
    std::string implicit;
    for (std::size_t i = 2; i < a.size(); ++i) {
        const auto kv = key_value(a[i]);
        if (!kv) return fail(s, "expected name=value, got " + a[i]);
        const auto& [name, value] = *kv;
        if (name == "implicit") {
            implicit = value;
        } else if (name == "iss") {
            c.iss = value;
        } else if (name == "sub") {
            c.sub = value;
        } else if (name == "aud") {
            c.aud = value;
        } else if (name == "jti") {
            c.jti = value;
        } else if (name == "exp" || name == "nbf" || name == "iat") {
            cb2::Seconds t = 0;
            if (!parse_time(value, t)) return fail(s, "bad time " + value);
            if (name == "exp") c.exp = t;
            if (name == "nbf") c.nbf = t;
            if (name == "iat") c.iat = t;
        } else if (!c.set(name, value)) {
            verdict(s, Error::argument);
            return true;
        }
    }
    say("payload", c.to_json());
    say("text_ok", c.text_ok() ? "yes" : "no");
    if (const cb2::LocalKey* k = find_local(s, a[1])) {
        auto t = cb2::Token::seal(*k, c, implicit);
        if (t.is_err()) {
            verdict(s, t.error());
            return true;
        }
        say("footer", cb2::Token::footer_for(k->key_id()));
        took(s, t.value());
        verdict(s, "ok");
        return true;
    }
#ifdef CB2_HAS_PQ
    if (const cb2::SecretKey* k = find_secret(s, a[1])) {
        auto t = cb2::Token::sign(*k, c, implicit);
        if (t.is_err()) {
            verdict(s, t.error());
            return true;
        }
        say("footer", cb2::Token::footer_for(k->key_id()));
        took(s, t.value());
        verdict(s, "ok");
        return true;
    }
#endif
    return fail(s, "no local or secret key named " + a[1]);
}

bool cmd_check(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "check <key> <token> [iss=] [aud=] [sub=] [any-iss] [any-aud] [skew=] [now=] [replay] [no-exp] [max=] [implicit=]");
    cb2::ValidationRules rules;
    std::string implicit;
    for (std::size_t i = 3; i < a.size(); ++i) {
        if (a[i] == "any-iss") {
            rules.allow_any_issuer();
            continue;
        }
        if (a[i] == "any-aud") {
            rules.allow_any_audience();
            continue;
        }
        if (a[i] == "no-exp") {
            rules.allow_missing_exp();
            continue;
        }
        if (a[i] == "replay") {
            rules.with_replay_check([&s](std::string_view jti) { return s.seen_jti.insert(std::string(jti)).second; });
            continue;
        }
        const auto kv = key_value(a[i]);
        if (!kv) return fail(s, "unknown option " + a[i]);
        const auto& [name, value] = *kv;
        if (name == "implicit") {
            implicit = value;
        } else if (name == "iss") {
            rules.expect_issuer(value);
        } else if (name == "aud") {
            rules.expect_audience(value);
        } else if (name == "sub") {
            rules.expect_subject(value);
        } else if (name == "skew" && all_digits(value)) {
            rules.with_clock_skew(std::atoll(value.c_str()));
        } else if (name == "max" && all_digits(value)) {
            rules.with_max_token_bytes(static_cast<std::size_t>(std::atoll(value.c_str())));
        } else if (name == "now") {
            cb2::Seconds t = 0;
            if (!parse_time(value, t)) return fail(s, "bad time " + value);
            rules.at(t);
        } else {
            return fail(s, "unknown option " + a[i]);
        }
    }
    say("rules", std::string(rules.complete() ? "complete" : "incomplete") + ", now " + time_text(rules.now()));
    cb2::Result<cb2::Claims> r = cb2::Result<cb2::Claims>::err(Error::argument);
    if (const cb2::LocalKey* k = find_local(s, a[1])) {
        r = cb2::Token::open(a[2], *k, rules, implicit);
    } else {
#ifdef CB2_HAS_PQ
        const std::optional<cb2::PublicKey> pk = find_public(s, a[1]);
        if (!pk) return fail(s, "no key named " + a[1]);
        r = cb2::Token::verify(a[2], *pk, rules, implicit);
#else
        return fail(s, "no local key named " + a[1]);
#endif
    }
    if (r.is_err()) {
        verdict(s, r.error());
        return true;
    }
    say("claims", r.value().to_json());
    if (r.value().exp) say("exp", time_text(*r.value().exp));
    verdict(s, "ok");
    return true;
}

bool cmd_peek(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "peek <token>");
    const std::string& t = a[1];
    std::string_view header;
    if (t.rfind("cb2.local.", 0) == 0) header = "cb2.local.";
    if (t.rfind("cb2.public.", 0) == 0) header = "cb2.public.";
    if (header.empty()) {
        say("header", "not a cb2 token");
        verdict(s, Error::invalid);
        return true;
    }
    say("header", header);
    const std::size_t dot = t.find('.', header.size());
    const std::string_view body(t.data() + header.size(),
                                (dot == std::string::npos ? t.size() : dot) - header.size());
    say("body", std::to_string(body.size()) + " characters, " +
                    std::to_string(cb2::detail::b64::decoded_len(body.size())) + " bytes");
    if (dot == std::string::npos) {
        say("footer", "none");
    } else {
        const std::string_view f(t.data() + dot + 1, t.size() - dot - 1);
        const std::size_t need = cb2::detail::b64::decoded_len(f.size());
        std::vector<uint8_t> raw(need == static_cast<std::size_t>(-1) ? 0 : need);
        std::size_t n = 0;
        if (!raw.empty() && cb2::detail::b64::decode(raw.data(), raw.size(), f.data(), f.size(), n)) {
            say("footer", show_bytes({raw.data(), n}));
        } else {
            say("footer", "undecodable");
        }
    }
    const auto kid = cb2::Token::peek_key_id(t);
    say("kid", kid ? kid->value : "none");
    say("note", "nothing above is verified");
    return true;
}

bool cmd_tamper(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "tamper <token> [index]");
    std::string t = a[1];
    if (t.empty()) return fail(s, "empty token");
    std::size_t at = t.size() - 1;
    const std::size_t h = t.find('.', 4);
    const std::size_t dot = h == std::string::npos ? std::string::npos : t.find('.', h + 1);
    if (dot != std::string::npos && dot > 0) at = dot - 1;
    if (a.size() > 2) {
        if (!all_digits(a[2])) return fail(s, "index must be a number");
        at = static_cast<std::size_t>(std::atoll(a[2].c_str()));
        if (at >= t.size()) return fail(s, "index past the end of the token");
    }
    t[at] = t[at] == 'A' ? 'B' : 'A';
    say("index", std::to_string(at));
    took(s, t);
    return true;
}

bool cmd_wrap(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "wrap <wrapping key> <key>");
    const cb2::LocalKey* w = find_local(s, a[1]);
    const cb2::LocalKey* k = find_local(s, a[2]);
    if (w == nullptr || k == nullptr) return fail(s, "both arguments must name local keys");
    auto r = cb2::KeyWrap::wrap(*w, *k);
    if (r.is_err()) {
        verdict(s, r.error());
        return true;
    }
    took(s, r.value());
    verdict(s, "ok");
    return true;
}

bool cmd_unwrap(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "unwrap <wrapping key> <string> [name]");
    const cb2::LocalKey* w = find_local(s, a[1]);
    if (w == nullptr) return fail(s, "no local key named " + a[1]);
    const std::string name = a.size() > 3 ? a[3] : "unwrapped";
    auto r = cb2::KeyWrap::unwrap(a[2], *w);
    if (r.is_err()) {
        verdict(s, r.error());
        return true;
    }
    describe_local(name, r.value());
    s.local.insert_or_assign(name, std::move(r).value());
    verdict(s, "ok");
    return true;
}

bool cmd_assert(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "assert <verdict>");
    if (s.last_verdict == a[1]) {
        say("assert", a[1]);
        return true;
    }
    return fail(s, "assert failed: expected " + a[1] + ", got " + s.last_verdict);
}

bool run(Session& s, const std::string& line) {
    Args a = split(line);
    if (a.empty() || a[0][0] == '#') return true;
    for (std::string& arg : a) {
        if (arg == "$") arg = s.last_token;
    }
    const std::string& c = a[0];
    if (c == "help") {
        help();
        return true;
    }
    if (c == "keygen") return cmd_keygen(s, a);
    if (c == "import") return cmd_import(s, a);
    if (c == "keys") return cmd_keys(s, a);
    if (c == "kid") return cmd_kid(s, a);
    if (c == "seal") return cmd_seal(s, a);
    if (c == "open") return cmd_open(s, a);
    if (c == "sign") return cmd_sign(s, a);
    if (c == "verify") return cmd_verify(s, a);
    if (c == "claims") return cmd_claims(s, a);
    if (c == "check") return cmd_check(s, a);
    if (c == "peek") return cmd_peek(s, a);
    if (c == "tamper") return cmd_tamper(s, a);
    if (c == "wrap") return cmd_wrap(s, a);
    if (c == "unwrap") return cmd_unwrap(s, a);
    if (c == "assert") return cmd_assert(s, a);
    if (c == "time") {
        say("now", time_text(now_seconds()));
        return true;
    }
    if (c == "echo") {
        std::string text;
        for (std::size_t i = 1; i < a.size(); ++i) text += (i > 1 ? " " : "") + a[i];
        std::puts(text.c_str());
        return true;
    }
    return fail(s, "unknown command " + c + " (try help)");
}

bool is_terminal() {
#if defined(__unix__) || defined(__APPLE__)
    return isatty(0) != 0;
#else
    return false;
#endif
}

}

int main(int argc, char** argv) {
    std::ifstream file;
    std::istream* in = &std::cin;
    if (argc > 1) {
        file.open(argv[1]);
        if (!file) {
            std::fprintf(stderr, "cannot open %s\n", argv[1]);
            return 2;
        }
        in = &file;
    }
    const bool prompt = argc <= 1 && is_terminal();
    Session s;
    if (prompt) std::puts("cb2 playground; help lists the commands, quit leaves");
    std::string line;
    while (true) {
        if (prompt) {
            std::fputs("cb2> ", stdout);
            std::fflush(stdout);
        }
        if (!std::getline(*in, line)) break;
        if (line == "quit" || line == "exit") break;
        if (!prompt) std::printf("> %s\n", line.c_str());
        run(s, line);
    }
    if (s.failures > 0) {
        std::printf("%d failure(s)\n", s.failures);
        return 1;
    }
    return 0;
}
