#pragma once

/**
 * The playground session: a line-oriented command interpreter over the
 * cb2 library, shared by the command-line playground and the web page.
 * run() executes one line and appends its output to Session::out as
 * "name = value" lines; a verdict line reports ok or an error name, an
 * "error:" line reports a malformed command and counts a failure. The
 * token "$" in any argument stands for the last token produced, "$proof"
 * for the last holder proof and "$sealed" for the last sealed key. Inside
 * double quotes, \" \\ \n \t, \uXXXX or \u{X...} (a code point) and
 * \xNN (a raw byte) are resolved, so an ASCII script can carry any text.
 */

#include <cb2/cb2.hpp>

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cb2_playground {


using cb2::Error;
using Args = std::vector<std::string>;

struct Session {
    std::map<std::string, cb2::LocalKey> local;
#ifdef CB2_HAS_PQ
    std::map<std::string, cb2::SecretKey> secret;
    std::map<std::string, cb2::PublicKey> pub;
#endif
#ifdef CB2_HAS_SEAL
    std::map<std::string, cb2::RecipientKey> recipient;
    std::map<std::string, cb2::RecipientPublicKey> recipient_pub;
    std::string last_sealed;
#endif
    std::set<std::string> seen_jti;
    std::set<std::string> seen_proof_jti;
    std::string last_token;
    std::string last_proof;
    int proof_count = 0;
    std::string last_verdict = "none";
    std::string out;
    int failures = 0;
};

inline std::span<const uint8_t> sp(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

inline void emit(Session& s, std::string_view text) {
    s.out.append(text);
    s.out.push_back('\n');
}

inline void say(Session& s, std::string_view name, std::string_view value) {
    s.out.append(name);
    s.out.append(" = ");
    s.out.append(value);
    s.out.push_back('\n');
}

inline void verdict(Session& s, std::string_view v) {
    s.last_verdict = std::string(v);
    say(s, "verdict", v);
}

inline void verdict(Session& s, Error e) { verdict(s, cb2::error_name(e)); }

inline bool fail(Session& s, std::string_view what) {
    s.out.append("error: ");
    emit(s, what);
    ++s.failures;
    return false;
}

inline std::string hex(std::span<const uint8_t> b) {
    static constexpr char DIGITS[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t x : b) {
        out += DIGITS[x >> 4];
        out += DIGITS[x & 15];
    }
    return out;
}

inline std::string show_bytes(std::span<const uint8_t> b) {
    const std::string_view text(reinterpret_cast<const char*>(b.data()), b.size());
    bool plain = cb2::text::valid_utf8(text);
    for (uint8_t x : b) {
        if (x < 0x20 || x == 0x7f) plain = false;
    }
    if (plain) return "\"" + std::string(text) + "\"";
    return "hex:" + hex(b);
}

inline void append_utf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xc0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xe0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    } else {
        out += static_cast<char>(0xf0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (cp & 0x3f));
    }
}

inline int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// Resolves the escape at line[i] (the character after the backslash)
/// into cur and advances i past it: \uXXXX and \u{X...} are code points,
/// \xNN is one raw byte, \n and \t are themselves, anything else keeps
/// the character.
inline void resolve_escape(std::string_view line, std::size_t& i, std::string& cur) {
    const char c = line[i];
    if (c == 'n') { cur += '\n'; return; }
    if (c == 't') { cur += '\t'; return; }
    if (c == 'x') {
        if (i + 2 < line.size() && hex_digit(line[i + 1]) >= 0 && hex_digit(line[i + 2]) >= 0) {
            cur += static_cast<char>(hex_digit(line[i + 1]) * 16 + hex_digit(line[i + 2]));
            i += 2;
            return;
        }
        cur += c;
        return;
    }
    if (c != 'u') { cur += c; return; }
    unsigned cp = 0;
    std::size_t j = i + 1;
    if (j < line.size() && line[j] == '{') {
        ++j;
        int digits = 0;
        while (j < line.size() && line[j] != '}' && hex_digit(line[j]) >= 0 && digits < 6) {
            cp = cp * 16 + static_cast<unsigned>(hex_digit(line[j]));
            ++j;
            ++digits;
        }
        if (j >= line.size() || line[j] != '}' || digits == 0) { cur += 'u'; return; }
        i = j;
    } else {
        if (j + 4 > line.size()) { cur += 'u'; return; }
        for (std::size_t k = 0; k < 4; ++k) {
            const int d = hex_digit(line[j + k]);
            if (d < 0) { cur += 'u'; return; }
            cp = cp * 16 + static_cast<unsigned>(d);
        }
        i = j + 3;
    }
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
    append_utf8(cur, cp);
}

inline Args split(std::string_view line) {
    Args out;
    std::string cur;
    bool quoted = false;
    bool have = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (quoted) {
            if (c == '\\' && i + 1 < line.size()) {
                ++i;
                resolve_escape(line, i, cur);
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

inline std::optional<std::pair<std::string, std::string>> key_value(std::string_view arg) {
    const std::size_t eq = arg.find('=');
    if (eq == std::string_view::npos || eq == 0) return std::nullopt;
    return std::pair{std::string(arg.substr(0, eq)), std::string(arg.substr(eq + 1))};
}

inline bool all_digits(std::string_view s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

inline cb2::Seconds now_seconds() { return static_cast<cb2::Seconds>(std::time(nullptr)); }

/// "+3600" and "-60" are relative to now, digits are Unix seconds, anything
/// else must be RFC 3339.
inline bool parse_time(std::string_view s, cb2::Seconds& out) {
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

inline std::string time_text(cb2::Seconds t) {
    return std::to_string(t) + " (" + cb2::Rfc3339::format(t) + ")";
}

inline const cb2::LocalKey* find_local(Session& s, const std::string& name) {
    const auto it = s.local.find(name);
    return it == s.local.end() ? nullptr : &it->second;
}

#ifdef CB2_HAS_PQ
inline const cb2::SecretKey* find_secret(Session& s, const std::string& name) {
    const auto it = s.secret.find(name);
    return it == s.secret.end() ? nullptr : &it->second;
}

inline std::optional<cb2::PublicKey> find_public(Session& s, const std::string& name) {
    const auto it = s.pub.find(name);
    if (it != s.pub.end()) return it->second;
    if (const cb2::SecretKey* sk = find_secret(s, name)) return sk->public_key();
    return std::nullopt;
}
#endif

#ifdef CB2_HAS_SEAL
inline const cb2::RecipientKey* find_recipient(Session& s, const std::string& name) {
    const auto it = s.recipient.find(name);
    return it == s.recipient.end() ? nullptr : &it->second;
}

inline std::optional<cb2::RecipientPublicKey> find_recipient_public(Session& s, const std::string& name) {
    const auto it = s.recipient_pub.find(name);
    if (it != s.recipient_pub.end()) return it->second;
    if (const cb2::RecipientKey* r = find_recipient(s, name)) return r->public_key();
    return std::nullopt;
}

inline void describe_recipient(Session& s, const std::string& name, const cb2::RecipientKey& k) {
    const cb2::SecureString p = k.to_paserk();
    say(s, "key", name);
    say(s, "kcb2.recipient-secret", std::string_view(p.data(), p.size()));
    say(s, "kcb2.recipient", k.public_key().to_paserk());
    say(s, "kcb2.rid", k.paserk_id());
}

inline void describe_recipient_public(Session& s, const std::string& name, const cb2::RecipientPublicKey& k) {
    say(s, "key", name);
    say(s, "kcb2.recipient", k.to_paserk());
    say(s, "kcb2.rid", k.paserk_id());
}
#endif

inline void describe_local(Session& s, const std::string& name, const cb2::LocalKey& k) {
    const cb2::SecureString p = k.to_paserk();
    say(s, "key", name);
    say(s, "kcb2.local", std::string_view(p.data(), p.size()));
    say(s, "kcb2.lid", k.paserk_id());
    say(s, "kid", k.key_id() ? *k.key_id() : "none");
}

#ifdef CB2_HAS_PQ
inline void describe_secret(Session& s, const std::string& name, const cb2::SecretKey& k) {
    const cb2::SecureString p = k.to_paserk();
    const cb2::PublicKey pk = k.public_key();
    say(s, "key", name);
    say(s, "kcb2.secret", std::string_view(p.data(), p.size()));
    say(s, "kcb2.public", pk.to_paserk());
    say(s, "kcb2.pid", pk.paserk_id());
    say(s, "kid", k.key_id() ? *k.key_id() : "none");
}

inline void describe_public(Session& s, const std::string& name, const cb2::PublicKey& k) {
    say(s, "key", name);
    say(s, "kcb2.public", k.to_paserk());
    say(s, "kcb2.pid", k.paserk_id());
    say(s, "kid", k.key_id() ? *k.key_id() : "none");
}
#endif

inline void help(Session& s) {
    emit(s,
        "commands (quote arguments that contain spaces; $ is the last token;\n"
        "inside quotes \\uXXXX, \\u{X..}, \\xNN, \\n, \\t, \\\" and \\\\ are resolved)\n"
        "  keygen local [name]            new 32-byte key, stored under name (default local)\n"
        "  keygen public [name]           new Ed25519 + ML-DSA-65 pair (default signer)\n"
        "  keygen recipient [name]        new X-Wing pair for sealing keys (default recipient)\n"
        "  import <kcb2 string> [name]    kcb2.local, kcb2.secret, kcb2.public, kcb2.recipient[-secret]\n"
        "  keys                           list the stored keys\n"
        "  show <key>                     the kcb2 strings and id of a stored key\n"
        "  kid <key> <id>|none            set or clear the key id bound into the footer\n"
        "  seal <key> <msg> [footer] [implicit]      raw cb2.local token\n"
        "  open <key> <token> [footer] [implicit]    message or verdict\n"
        "  sign <key> <msg> [footer] [implicit]      raw cb2.public token\n"
        "  verify <key> <token> [footer] [implicit]  message or verdict\n"
        "  claims <key> [iss=] [aud=] [sub=] [jti=] [exp=] [nbf=] [iat=] [cnf=<key>]\n"
        "                                 [name=value]... [name:=json]... [implicit=]  seal (local key)\n"
        "                                 or sign (secret key); times: +3600, Unix seconds or RFC 3339;\n"
        "                                 cnf names a stored signing pair or public key to bind\n"
        "  proof <secret key> <token> htm= htu= [nonce=] [jti=] [now=] [lifetime=]\n"
        "                                 holder proof for the token and request; $proof is the last one\n"
        "  check <key> <token> [iss=] [aud=] [sub=] [any-iss] [any-aud] [skew=] [now=]\n"
        "                                 [replay] [no-exp] [max=] [lifetime=] [implicit=]  open or verify\n"
        "                                 [proof|proof=] [htm=] [htu=] [nonce=] [proof-lifetime=]\n"
        "                                 [require-cnf] [ignore-cnf]  the holder proof and its request\n"
        "  peek <token>                   header, body size, footer and kid, nothing verified;\n"
        "                                 for cb2.public the message and claims, in clear, unverified\n"
        "  lookup <token>                 the stored keys whose id matches the footer's kid, unverified\n"
        "  tamper <token> [index]         flip one character (default: last of the body)\n"
        "  wrap <wrapping key> <key>      kcb2.local-wrap string\n"
        "  unwrap <wrapping key> <string> [name]\n"
        "  sealkey <recipient> <key>      kcb2.seal string: the key sealed to the recipient; $sealed is the last one\n"
        "  unsealkey <recipient> <string> [name]  the recipient's secret opens it\n"
        "  text <string>                  bytes, code points and the identifier policy's verdict\n"
        "  time                           the clock the playground uses and the random source\n"
        "  assert <verdict>               scripts: fail unless the last verdict matches\n"
        "  echo <text>                    print text\n"
        "  help, quit");
}

inline std::string hex4(unsigned cp) {
    static constexpr char DIGITS[] = "0123456789ABCDEF";
    std::string h;
    for (int shift = 20; shift >= 0; shift -= 4) {
        const unsigned d = (cp >> shift) & 15;
        if (!h.empty() || d != 0 || shift < 16) h += DIGITS[d];
    }
    return "U+" + h;
}

/// The code points of s, each marked with ! when the identifier policy
/// refuses it; "not UTF-8" when s is malformed.
inline std::string codepoints(std::string_view s) {
    if (!cb2::text::valid_utf8(s)) return "not UTF-8";
    std::string out;
    std::size_t i = 0;
    unsigned cp = 0;
    while (i < s.size() && cb2::text::decode(s, i, cp)) {
        if (!out.empty()) out += ' ';
        out += hex4(cp);
        if (!cb2::text::identifier_char(cp)) out += '!';
    }
    return out;
}

/// The first code point of s the identifier policy refuses, if any.
inline std::optional<unsigned> first_refused(std::string_view s) {
    if (!cb2::text::valid_utf8(s)) return std::nullopt;
    std::size_t i = 0;
    unsigned cp = 0;
    while (i < s.size() && cb2::text::decode(s, i, cp)) {
        if (!cb2::text::identifier_char(cp)) return cp;
    }
    return std::nullopt;
}

inline bool cmd_text(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "text <string>");
    const std::string& t = a[1];
    say(s, "text", "\"" + t + "\"");
    say(s, "bytes", std::to_string(t.size()));
    say(s, "codepoints", codepoints(t));
    if (!cb2::text::valid_utf8(t)) {
        say(s, "identifier", "refused: not UTF-8");
    } else if (const auto bad = first_refused(t)) {
        say(s, "identifier", "refused: " + hex4(*bad) + " is a control, invisible, noncharacter or private-use code point");
    } else {
        say(s, "identifier", "ok: every code point may appear in iss, sub, aud, jti, claim names and key ids");
    }
    return true;
}

inline bool cmd_keygen(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "keygen local|public|recipient [name]");
    if (a[1] == "recipient") {
#ifdef CB2_HAS_SEAL
        const std::string name = a.size() > 2 ? a[2] : "recipient";
        auto k = cb2::RecipientKey::generate();
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_recipient(s, name, k.value());
        s.recipient.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
#else
        verdict(s, Error::unavailable);
#endif
        return true;
    }
    if (a[1] == "local") {
        const std::string name = a.size() > 2 ? a[2] : "local";
        auto k = cb2::LocalKey::generate();
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_local(s, name, k.value());
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
        describe_secret(s, name, k.value());
        s.secret.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
#else
        verdict(s, Error::unavailable);
#endif
        return true;
    }
    return fail(s, "keygen local|public|recipient [name]");
}

inline bool cmd_import(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "import <kcb2 string> [name]");
    const std::string& text = a[1];
    if (text.rfind("kcb2.local.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "local";
        auto k = cb2::LocalKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_local(s, name, k.value());
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
        describe_secret(s, name, k.value());
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
        describe_public(s, name, k.value());
        s.pub.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
#endif
#ifdef CB2_HAS_SEAL
    if (text.rfind("kcb2.recipient-secret.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "recipient";
        auto k = cb2::RecipientKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_recipient(s, name, k.value());
        s.recipient.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
    if (text.rfind("kcb2.recipient.", 0) == 0) {
        const std::string name = a.size() > 2 ? a[2] : "recipient";
        auto k = cb2::RecipientPublicKey::from_paserk(text);
        if (k.is_err()) {
            verdict(s, k.error());
            return true;
        }
        describe_recipient_public(s, name, k.value());
        s.recipient_pub.insert_or_assign(name, std::move(k).value());
        verdict(s, "ok");
        return true;
    }
#endif
    verdict(s, Error::argument);
    return true;
}

#ifdef CB2_HAS_SEAL
inline bool cmd_sealkey(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "sealkey <recipient> <local key>");
    const auto to = find_recipient_public(s, a[1]);
    if (!to) return fail(s, "no recipient named " + a[1]);
    const cb2::LocalKey* k = find_local(s, a[2]);
    if (k == nullptr) return fail(s, "no local key named " + a[2]);
    auto sealed = cb2::Seal::seal(*to, *k);
    if (sealed.is_err()) {
        verdict(s, sealed.error());
        return true;
    }
    s.last_sealed = sealed.value();
    say(s, "kcb2.seal", sealed.value());
    say(s, "length", std::to_string(sealed.value().size()));
    say(s, "to", to->paserk_id());
    verdict(s, "ok");
    return true;
}

inline bool cmd_unsealkey(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "unsealkey <recipient> <kcb2.seal string> [name]");
    const cb2::RecipientKey* by = find_recipient(s, a[1]);
    if (by == nullptr) return fail(s, "no recipient secret named " + a[1]);
    auto k = cb2::Seal::unseal(a[2], *by);
    if (k.is_err()) {
        verdict(s, k.error());
        return true;
    }
    const std::string name = a.size() > 3 ? a[3] : "unsealed";
    describe_local(s, name, k.value());
    s.local.insert_or_assign(name, std::move(k).value());
    verdict(s, "ok");
    return true;
}
#endif

inline bool cmd_keys(Session& s, const Args&) {
    for (const auto& [name, k] : s.local) say(s, name, "local, kid " + (k.key_id() ? *k.key_id() : "none"));
#ifdef CB2_HAS_PQ
    for (const auto& [name, k] : s.secret) say(s, name, "secret, kid " + (k.key_id() ? *k.key_id() : "none"));
    for (const auto& [name, k] : s.pub) say(s, name, "public, kid " + (k.key_id() ? *k.key_id() : "none"));
#endif
#ifdef CB2_HAS_SEAL
    for (const auto& [name, k] : s.recipient) say(s, name, "recipient, rid " + k.paserk_id());
    for (const auto& [name, k] : s.recipient_pub) say(s, name, "recipient public, rid " + k.paserk_id());
#endif
    return true;
}

inline bool cmd_show(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "show <key>");
    if (const cb2::LocalKey* k = find_local(s, a[1])) {
        describe_local(s, a[1], *k);
        return true;
    }
#ifdef CB2_HAS_PQ
    if (const cb2::SecretKey* k = find_secret(s, a[1])) {
        describe_secret(s, a[1], *k);
        return true;
    }
    if (const auto it = s.pub.find(a[1]); it != s.pub.end()) {
        describe_public(s, a[1], it->second);
        return true;
    }
#endif
#ifdef CB2_HAS_SEAL
    if (const cb2::RecipientKey* r = find_recipient(s, a[1])) {
        describe_recipient(s, a[1], *r);
        return true;
    }
    if (const auto it = s.recipient_pub.find(a[1]); it != s.recipient_pub.end()) {
        describe_recipient_public(s, a[1], it->second);
        return true;
    }
#endif
    return fail(s, "no key named " + a[1]);
}

/// s as one playground argument: bare when it is plain, else double
/// quoted with \\, \", \n and \t escaped.
inline std::string script_arg(std::string_view s) {
    bool plain = !s.empty();
    for (const char c : s) {
        if (c == ' ' || c == '"' || c == '\\' || c == '\n' || c == '\t' || c == '\r') plain = false;
    }
    if (plain && s != "$") return std::string(s);
    std::string q = "\"";
    for (const char c : s) {
        if (c == '\\' || c == '"') q += '\\';
        if (c == '\n') { q += "\\n"; continue; }
        if (c == '\t') { q += "\\t"; continue; }
        if (c == '\r') { q += "\\r"; continue; }
        q += c;
    }
    return q + "\"";
}

/// The import line of a key and, when its id is not the default one, the
/// kid line that restores it.
inline void export_lines(Session& s, const std::string& name, std::string_view paserk,
                         const std::optional<std::string>& kid, const std::string& default_kid) {
    emit(s, "import " + std::string(paserk) + " " + script_arg(name));
    if (!kid) emit(s, "kid " + script_arg(name) + " none");
    else if (*kid != default_kid) emit(s, "kid " + script_arg(name) + " " + script_arg(*kid));
}

inline bool cmd_export(Session& s, const Args& a) {
    if (a.size() < 2) {
        for (const auto& [name, k] : s.local) {
            const cb2::SecureString p = k.to_paserk();
            export_lines(s, name, std::string_view(p.data(), p.size()), k.key_id(), k.paserk_id());
        }
#ifdef CB2_HAS_PQ
        for (const auto& [name, k] : s.secret) {
            const cb2::SecureString p = k.to_paserk();
            export_lines(s, name, std::string_view(p.data(), p.size()), k.key_id(), k.public_key().paserk_id());
        }
        for (const auto& [name, k] : s.pub) export_lines(s, name, k.to_paserk(), k.key_id(), k.paserk_id());
#endif
#ifdef CB2_HAS_SEAL
        for (const auto& [name, k] : s.recipient) {
            const cb2::SecureString p = k.to_paserk();
            emit(s, "import " + std::string(p.data(), p.size()) + " " + script_arg(name));
        }
        for (const auto& [name, k] : s.recipient_pub) emit(s, "import " + k.to_paserk() + " " + script_arg(name));
#endif
        say(s, "keys", std::to_string(s.local.size()
#ifdef CB2_HAS_PQ
            + s.secret.size() + s.pub.size()
#endif
#ifdef CB2_HAS_SEAL
            + s.recipient.size() + s.recipient_pub.size()
#endif
        ));
        verdict(s, "ok");
        return true;
    }
    const bool public_half = a.size() > 2 && a[2] == "public";
    if (const cb2::LocalKey* k = find_local(s, a[1])) {
        if (public_half) return fail(s, "a local key has no public half");
        const cb2::SecureString p = k->to_paserk();
        say(s, "key", a[1]);
        say(s, "kcb2.local", std::string_view(p.data(), p.size()));
        say(s, "kid", k->key_id() ? *k->key_id() : "none");
        verdict(s, "ok");
        return true;
    }
#ifdef CB2_HAS_PQ
    if (const cb2::SecretKey* k = find_secret(s, a[1])) {
        say(s, "key", a[1]);
        if (public_half) {
            say(s, "kcb2.public", k->public_key().to_paserk());
        } else {
            const cb2::SecureString p = k->to_paserk();
            say(s, "kcb2.secret", std::string_view(p.data(), p.size()));
        }
        say(s, "kid", k->key_id() ? *k->key_id() : "none");
        verdict(s, "ok");
        return true;
    }
#ifdef CB2_HAS_SEAL
    if (const cb2::RecipientKey* r = find_recipient(s, a[1])) {
        say(s, "key", a[1]);
        if (public_half) {
            say(s, "kcb2.recipient", r->public_key().to_paserk());
        } else {
            const cb2::SecureString p = r->to_paserk();
            say(s, "kcb2.recipient-secret", std::string_view(p.data(), p.size()));
        }
        say(s, "kcb2.rid", r->paserk_id());
        verdict(s, "ok");
        return true;
    }
    if (const auto it = s.recipient_pub.find(a[1]); it != s.recipient_pub.end()) {
        say(s, "key", a[1]);
        say(s, "kcb2.recipient", it->second.to_paserk());
        say(s, "kcb2.rid", it->second.paserk_id());
        verdict(s, "ok");
        return true;
    }
#endif
    if (const auto it = s.pub.find(a[1]); it != s.pub.end()) {
        say(s, "key", a[1]);
        say(s, "kcb2.public", it->second.to_paserk());
        say(s, "kid", it->second.key_id() ? *it->second.key_id() : "none");
        verdict(s, "ok");
        return true;
    }
#endif
    return fail(s, "no key named " + a[1]);
}

inline bool cmd_kid(Session& s, const Args& a) {
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
    say(s, "kid", a[2]);
    say(s, "footer", cb2::Token::footer_for(a[2] == "none" ? std::nullopt : std::optional<std::string>(a[2])));
    return true;
}

inline void took(Session& s, const std::string& token) {
    s.last_token = token;
    say(s, "token", token);
    say(s, "length", std::to_string(token.size()));
}

inline bool cmd_seal(Session& s, const Args& a) {
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

inline bool cmd_open(Session& s, const Args& a) {
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
    say(s, "message", show_bytes(m.value()));
    verdict(s, "ok");
    return true;
}

inline bool cmd_sign(Session& s, const Args& a) {
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

inline bool cmd_verify(Session& s, const Args& a) {
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
    say(s, "message", show_bytes(m.value()));
    verdict(s, "ok");
#else
    verdict(s, Error::unavailable);
#endif
    return true;
}

inline bool cmd_claims(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "claims <key> [iss=] [aud=] [sub=] [jti=] [exp=] [nbf=] [iat=] [cnf=<key>] [name=value]... [name:=json]... [implicit=]");
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
        } else if (name == "cnf") {
            c.cnf = value;
#ifdef CB2_HAS_PQ
            if (const auto pk = find_public(s, value)) c.cnf = pk->to_paserk();
#endif
        } else if (name == "exp" || name == "nbf" || name == "iat") {
            cb2::Seconds t = 0;
            if (!parse_time(value, t)) return fail(s, "bad time " + value);
            if (name == "exp") c.exp = t;
            if (name == "nbf") c.nbf = t;
            if (name == "iat") c.iat = t;
        } else if (!name.empty() && name.back() == ':') {
            if (!c.set_json(std::string_view(name).substr(0, name.size() - 1), value)) {
                verdict(s, Error::argument);
                return true;
            }
        } else if (!c.set(name, value)) {
            verdict(s, Error::argument);
            return true;
        }
    }
    say(s, "payload", c.to_json());
    say(s, "text_ok", c.text_ok() ? "yes" : "no");
    if (!c.text_ok()) {
        const std::pair<const char*, const std::optional<std::string>*> named[] = {
            {"iss", &c.iss}, {"sub", &c.sub}, {"aud", &c.aud}, {"jti", &c.jti}};
        for (const auto& [field, value] : named) {
            if (*value && !cb2::text::identifier_ok(**value)) say(s, "refused", std::string(field) + ": " + codepoints(**value));
        }
        for (const auto& [cname, cvalue] : c.custom()) {
            if (!cb2::text::identifier_ok(cname)) say(s, "refused", "claim name " + cname + ": " + codepoints(cname));
        }
    }
    if (const cb2::LocalKey* k = find_local(s, a[1])) {
        auto t = cb2::Token::seal(*k, c, implicit);
        if (t.is_err()) {
            verdict(s, t.error());
            return true;
        }
        say(s, "footer", cb2::Token::footer_for(k->key_id()));
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
        say(s, "footer", cb2::Token::footer_for(k->key_id()));
        took(s, t.value());
        verdict(s, "ok");
        return true;
    }
#endif
    return fail(s, "no local or secret key named " + a[1]);
}

inline bool cmd_check(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "check <key> <token> [iss=] [aud=] [sub=] [any-iss] [any-aud] [skew=] [now=] [replay] [no-exp] [max=] [lifetime=] [implicit=] [proof|proof=] [htm=] [htu=] [nonce=] [proof-lifetime=] [require-cnf] [ignore-cnf]");
    cb2::ValidationRules rules;
    std::string implicit;
    std::string proof;
    cb2::HolderRequest request;
    for (std::size_t i = 3; i < a.size(); ++i) {
        if (a[i] == "any-iss") {
            rules.allow_any_issuer();
            continue;
        }
        if (a[i] == "proof") {
            if (s.last_proof.empty()) return fail(s, "no proof made yet");
            proof = s.last_proof;
            continue;
        }
        if (a[i] == "require-cnf") {
            rules.require_sender_constraint();
            continue;
        }
        if (a[i] == "ignore-cnf") {
            rules.ignore_sender_constraint();
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
        } else if (name == "lifetime" && all_digits(value)) {
            rules.with_max_lifetime(std::atoll(value.c_str()));
        } else if (name == "proof") {
            proof = value;
        } else if (name == "htm") {
            request.method = value;
        } else if (name == "htu") {
            request.target = value;
        } else if (name == "nonce") {
            request.nonce = value;
        } else if (name == "proof-lifetime" && all_digits(value)) {
            rules.with_proof_lifetime(std::atoll(value.c_str()));
        } else if (name == "now") {
            cb2::Seconds t = 0;
            if (!parse_time(value, t)) return fail(s, "bad time " + value);
            rules.at(t);
        } else {
            return fail(s, "unknown option " + a[i]);
        }
    }
    if (!proof.empty()) {
        if (request.method.empty() || request.target.empty()) return fail(s, "a proof needs htm= and htu=");
        rules.with_holder_proof(proof, request).with_proof_replay_check([&s](std::string_view jti) {
            return s.seen_proof_jti.insert(std::string(jti)).second;
        });
    }
    say(s, "rules", std::string(rules.complete() ? "complete" : "incomplete") + ", now " + time_text(rules.now()));
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
    say(s, "claims", r.value().to_json());
    if (r.value().exp) say(s, "exp", time_text(*r.value().exp));
    verdict(s, "ok");
    return true;
}

#ifdef CB2_HAS_PQ
inline bool cmd_proof(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "proof <secret key> <token> htm= htu= [nonce=] [jti=] [now=] [lifetime=]");
    const cb2::SecretKey* k = find_secret(s, a[1]);
    if (k == nullptr) return fail(s, "no secret key named " + a[1]);
    cb2::HolderRequest request;
    std::string jti;
    cb2::Seconds now = now_seconds();
    cb2::Seconds lifetime = cb2::Holder::DEFAULT_LIFETIME;
    for (std::size_t i = 3; i < a.size(); ++i) {
        const auto kv = key_value(a[i]);
        if (!kv) return fail(s, "expected name=value, got " + a[i]);
        const auto& [name, value] = *kv;
        if (name == "htm") {
            request.method = value;
        } else if (name == "htu") {
            request.target = value;
        } else if (name == "nonce") {
            request.nonce = value;
        } else if (name == "jti") {
            jti = value;
        } else if (name == "lifetime" && all_digits(value)) {
            lifetime = std::atoll(value.c_str());
        } else if (name == "now") {
            if (!parse_time(value, now)) return fail(s, "bad time " + value);
        } else {
            return fail(s, "unknown option " + a[i]);
        }
    }
    if (request.method.empty() || request.target.empty()) return fail(s, "proof needs htm= and htu=");
    if (jti.empty()) jti = "p-" + std::to_string(++s.proof_count);
    auto claims = cb2::HolderProof::claims_for(request, jti, now, lifetime);
    if (claims.is_err()) {
        verdict(s, claims.error());
        return true;
    }
    auto p = cb2::HolderProof::make(*k, request, a[2], jti, now, lifetime);
    if (p.is_err()) {
        verdict(s, p.error());
        return true;
    }
    say(s, "claims", claims.value().to_json());
    say(s, "footer", cb2::Token::footer_for(k->public_key().paserk_id()));
    s.last_proof = p.value();
    say(s, "proof", p.value());
    say(s, "length", std::to_string(p.value().size()));
    verdict(s, "ok");
    return true;
}
#endif

/// The two signatures at the end of a cb2.public body: Ed25519 (64) and
/// ML-DSA-65 (3309), so the message before them can be shown unverified.
inline constexpr std::size_t PUBLIC_SIG_BYTES = 64 + 3309;

/// The body of a cb2.public token, decoded, with the message shown in
/// clear and the claims parsed; none of it verified.
inline void peek_public_body(Session& s, std::string_view body) {
    const std::size_t need = cb2::detail::b64::decoded_len(body.size());
    std::vector<uint8_t> raw(need == static_cast<std::size_t>(-1) ? 0 : need);
    std::size_t n = 0;
    if (raw.empty() || !cb2::detail::b64::decode(raw.data(), raw.size(), body.data(), body.size(), n)) {
        say(s, "payload", "undecodable");
        return;
    }
    if (n < PUBLIC_SIG_BYTES) {
        say(s, "payload", "too short for the two signatures");
        return;
    }
    const std::span<const uint8_t> m(raw.data(), n - PUBLIC_SIG_BYTES);
    say(s, "payload", show_bytes(m));
    say(s, "signatures", "Ed25519 64 bytes, ML-DSA-65 3309 bytes");
    const std::string_view text(reinterpret_cast<const char*>(m.data()), m.size());
    auto c = cb2::Claims::from_json(text);
    if (c.is_ok()) {
        say(s, "claims", c.value().to_json());
        if (c.value().exp) say(s, "exp", time_text(*c.value().exp));
    } else {
        say(s, "claims", std::string("not a claims object (") + cb2::error_name(c.error()) + ")");
    }
}

inline bool cmd_peek(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "peek <token>");
    const std::string& t = a[1];
    std::string_view header;
    if (t.rfind("cb2.local.", 0) == 0) header = "cb2.local.";
    if (t.rfind("cb2.public.", 0) == 0) header = "cb2.public.";
    if (t.rfind("cb2.holder-public.", 0) == 0) header = "cb2.holder-public.";
    if (header.empty()) {
        say(s, "header", "not a cb2 token");
        verdict(s, Error::invalid);
        return true;
    }
    say(s, "header", header);
    const std::size_t dot = t.find('.', header.size());
    const std::string_view body(t.data() + header.size(),
                                (dot == std::string::npos ? t.size() : dot) - header.size());
    const std::size_t body_bytes = cb2::detail::b64::decoded_len(body.size());
    say(s, "body", std::to_string(body.size()) + " characters, " +
                    (body_bytes == static_cast<std::size_t>(-1) ? std::string("not a valid base64 length")
                                                                 : std::to_string(body_bytes) + " bytes"));
    if (header == "cb2.public." || header == "cb2.holder-public.") {
        peek_public_body(s, body);
    } else {
        say(s, "payload", "ciphertext; readable only with the key");
    }
    if (dot == std::string::npos) {
        say(s, "footer", "none");
    } else {
        const std::string_view f(t.data() + dot + 1, t.size() - dot - 1);
        const std::size_t need = cb2::detail::b64::decoded_len(f.size());
        std::vector<uint8_t> raw(need == static_cast<std::size_t>(-1) ? 0 : need);
        std::size_t n = 0;
        if (!raw.empty() && cb2::detail::b64::decode(raw.data(), raw.size(), f.data(), f.size(), n)) {
            say(s, "footer", show_bytes({raw.data(), n}));
        } else {
            say(s, "footer", "undecodable");
        }
    }
    const auto kid = cb2::Token::peek_key_id(t);
    say(s, "kid", kid ? kid->value : "none");
    say(s, "note", "nothing above is verified");
    return true;
}

/// The stored keys whose key id equals the kid in a token's footer, read
/// without verifying: how a verifier with several keys picks one.
inline bool cmd_lookup(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "lookup <token>");
    const auto kid = cb2::Token::peek_key_id(a[1]);
    if (!kid) {
        say(s, "kid", "none");
        say(s, "key", "none: no key id in the footer");
        return true;
    }
    say(s, "kid", kid->value);
    bool found = false;
    for (const auto& [name, k] : s.local) {
        if (k.key_id() && *k.key_id() == kid->value) {
            say(s, "key", name + " (local)");
            found = true;
        }
    }
#ifdef CB2_HAS_PQ
    for (const auto& [name, k] : s.secret) {
        if (k.key_id() && *k.key_id() == kid->value) {
            say(s, "key", name + " (secret)");
            found = true;
        }
    }
    for (const auto& [name, k] : s.pub) {
        if (k.key_id() && *k.key_id() == kid->value) {
            say(s, "key", name + " (public)");
            found = true;
        }
    }
#endif
    if (!found) say(s, "key", "none: no stored key has that id");
    say(s, "note", "the kid is read without verifying; the key it names must still verify the token");
    return true;
}

inline bool cmd_tamper(Session& s, const Args& a) {
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
    say(s, "index", std::to_string(at));
    took(s, t);
    return true;
}

inline bool cmd_wrap(Session& s, const Args& a) {
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

inline bool cmd_unwrap(Session& s, const Args& a) {
    if (a.size() < 3) return fail(s, "unwrap <wrapping key> <string> [name]");
    const cb2::LocalKey* w = find_local(s, a[1]);
    if (w == nullptr) return fail(s, "no local key named " + a[1]);
    const std::string name = a.size() > 3 ? a[3] : "unwrapped";
    auto r = cb2::KeyWrap::unwrap(a[2], *w);
    if (r.is_err()) {
        verdict(s, r.error());
        return true;
    }
    describe_local(s, name, r.value());
    s.local.insert_or_assign(name, std::move(r).value());
    verdict(s, "ok");
    return true;
}

inline bool cmd_assert(Session& s, const Args& a) {
    if (a.size() < 2) return fail(s, "assert <verdict>");
    if (s.last_verdict == a[1]) {
        say(s, "assert", a[1]);
        return true;
    }
    return fail(s, "assert failed: expected " + a[1] + ", got " + s.last_verdict);
}

inline bool run(Session& s, const std::string& line) {
    Args a = split(line);
    if (a.empty() || a[0][0] == '#') return true;
    for (std::string& arg : a) {
        if (arg == "$") arg = s.last_token;
        if (arg == "$proof") arg = s.last_proof;
#ifdef CB2_HAS_SEAL
        if (arg == "$sealed") arg = s.last_sealed;
#endif
    }
    const std::string& c = a[0];
    if (c == "help") {
        help(s);
        return true;
    }
    if (c == "text") return cmd_text(s, a);
    if (c == "keygen") return cmd_keygen(s, a);
    if (c == "import") return cmd_import(s, a);
    if (c == "keys") return cmd_keys(s, a);
    if (c == "show") return cmd_show(s, a);
    if (c == "export") return cmd_export(s, a);
    if (c == "kid") return cmd_kid(s, a);
    if (c == "seal") return cmd_seal(s, a);
    if (c == "open") return cmd_open(s, a);
    if (c == "sign") return cmd_sign(s, a);
    if (c == "verify") return cmd_verify(s, a);
    if (c == "claims") return cmd_claims(s, a);
    if (c == "check") return cmd_check(s, a);
#ifdef CB2_HAS_PQ
    if (c == "proof") return cmd_proof(s, a);
#endif
#ifdef CB2_HAS_SEAL
    if (c == "sealkey") return cmd_sealkey(s, a);
    if (c == "unsealkey") return cmd_unsealkey(s, a);
#endif
    if (c == "peek") return cmd_peek(s, a);
    if (c == "lookup") return cmd_lookup(s, a);
    if (c == "tamper") return cmd_tamper(s, a);
    if (c == "wrap") return cmd_wrap(s, a);
    if (c == "unwrap") return cmd_unwrap(s, a);
    if (c == "assert") return cmd_assert(s, a);
    if (c == "time") {
        say(s, "now", time_text(now_seconds()));
        say(s, "random", randombytes_implementation_name());
        return true;
    }
    if (c == "echo") {
        std::string text;
        for (std::size_t i = 1; i < a.size(); ++i) text += (i > 1 ? " " : "") + a[i];
        emit(s, text);
        return true;
    }
    return fail(s, "unknown command " + c + " (try help)");
}

}
