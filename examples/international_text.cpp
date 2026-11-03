/**
 * International text: the same tokens through two claim checks.
 *
 * Each scenario below seals a v5.local token and looks at it twice. The
 * legacy check is what a token library without a text policy does:
 * authenticate the token, parse the JSON, take every string as it comes.
 * The paseto5 check is the Token layer with the policy of docs/SPEC.md
 * section 8.4. Both share the same key, the same cipher and the same tag;
 * the only difference is what happens to the text after authentication,
 * so the difference in verdicts is the difference the policy makes.
 *
 * Every scenario states what it expects of both checks, and the program
 * exits non-zero if any expectation fails, so CI runs it as a test. The
 * output contains the international and the invisible characters as they
 * are, which is the point: look at how the spoofed strings render.
 *
 * Build: cmake -S paseto5 -B paseto5/build && cmake --build paseto5/build
 * Run:   ./paseto5/build/paseto5_example_text
 */

#include <paseto5/paseto5.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

using paseto5::Claims;
using paseto5::Error;
using paseto5::LocalKey;
using paseto5::Token;
using paseto5::ValidationRules;
namespace json = paseto5::json;
namespace text = paseto5::text;

namespace {

constexpr paseto5::Seconds NOW = 1700000000;
constexpr std::string_view EXP = "\"exp\":\"2023-11-14T23:13:20+00:00\"";

constexpr std::string_view ZWSP = "\xe2\x80\x8b";
constexpr std::string_view RLO = "\xe2\x80\xae";
constexpr std::string_view N_TILDE = "\xc3\xb1";
constexpr std::string_view JAPANESE = "\xe6\x97\xa5\xe6\x9c\xac";
constexpr std::string_view ARABIC = "\xd8\xb9\xd8\xb1\xd8\xa8\xd9\x8a";
constexpr std::string_view COMPANY = "Compa\xc3\xb1\xc3\xad" "a";
constexpr std::string_view COMPANY_ESCAPED = "Compa\\u00f1\\u00eda";
constexpr std::string_view COMPANY_DECOMPOSED = "Compan\xcc\x83i\xcc\x81" "a";
constexpr std::string_view OVERLONG_DOTS = "\xc0\xae\xc0\xae/etc/passwd";

int failures = 0;

void expect(bool ok, const char* what) {
    if (ok) return;
    ++failures;
    std::printf("    EXPECTATION FAILED: %s\n", what);
}

template <class... Parts>
std::string cat(Parts... parts) {
    std::string s;
    (s.append(std::string_view(parts)), ...);
    return s;
}

std::string codepoints(std::string_view s) {
    std::string out;
    std::size_t i = 0;
    unsigned cp = 0;
    while (i < s.size()) {
        char buf[24];
        if (text::decode(s, i, cp)) {
            std::snprintf(buf, sizeof buf, " U+%04X", cp);
        } else {
            std::snprintf(buf, sizeof buf, " byte %02X", static_cast<unsigned char>(s[i]));
            ++i;
        }
        out += buf;
    }
    return out.empty() ? out : out.substr(1);
}

void show(const char* label, std::string_view s) {
    std::printf("    %-16s \"", label);
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::printf("\"  (%zu bytes: %s)\n", s.size(), codepoints(s).c_str());
}

void line(const char* label, const std::string& value) {
    std::printf("    %-16s %s\n", label, value.c_str());
}

std::string verdict(const paseto5::Result<Claims>& r) {
    return r.is_ok() ? "ok" : paseto5::error_name(r.error());
}

std::string verdict(const paseto5::Result<std::string>& r) {
    return r.is_ok() ? "ok" : paseto5::error_name(r.error());
}

LocalKey demo_key() {
    std::vector<uint8_t> k(LocalKey::BYTES);
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(0x70 + 7 * i);
    return LocalKey::from_bytes(k).value();
}

Claims base_claims() {
    Claims c;
    c.exp = NOW + 3600;
    return c;
}

/// The legacy check: authentic or not, and the strings as the JSON holds
/// them, with no policy applied.
struct LegacyView {
    bool authentic = false;
    std::string iss;
    std::string sub;
};

LegacyView legacy_open(std::string_view token, const LocalKey& key) {
    LegacyView v;
    auto plain = paseto5::Local::open(token, key, paseto5::bytes(Token::footer_for(key.key_id())));
    if (plain.is_err()) return v;
    const std::string_view payload(reinterpret_cast<const char*>(plain.value().data()),
                                   plain.value().size());
    json::Value root;
    if (!json::Reader::parse(payload, root) || !root.is_object()) return v;
    v.authentic = true;
    if (const auto* p = root.get("iss"); p != nullptr && p->is_string()) v.iss = p->text;
    if (const auto* p = root.get("sub"); p != nullptr && p->is_string()) v.sub = p->text;
    return v;
}

/// The legacy issuer: any JSON the caller hands over is sealed as is.
std::string legacy_seal(const LocalKey& key, std::string_view payload) {
    auto t = paseto5::Local::seal(key, paseto5::bytes(payload),
                                  paseto5::bytes(Token::footer_for(key.key_id())));
    expect(t.is_ok(), "the legacy issuer seals any payload");
    return t.is_ok() ? t.value() : std::string();
}

/// A decoder that does not check for overlong forms, as careless ones
/// do not. It exists only to show what such a decoder would read.
std::string lenient_decode(std::string_view s) {
    std::string out;
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        const std::size_t len = c < 0x80 ? 1 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : 4;
        if (i + len > s.size()) break;
        unsigned cp = len == 1 ? c : c & (0xFFu >> (len + 1));
        for (std::size_t k = 1; k < len; ++k)
            cp = cp << 6 | (static_cast<unsigned char>(s[i + k]) & 0x3Fu);
        out += cp < 0x80 ? static_cast<char>(cp) : '?';
        i += len;
    }
    return out;
}

bool all_ascii(std::string_view s) {
    for (const char ch : s) {
        if (static_cast<unsigned char>(ch) >= 0x80) return false;
    }
    return true;
}

void scenario_round_trip() {
    std::puts("1. International identifiers travel byte for byte, in a token that stays ASCII");
    LocalKey k = demo_key();
    k.set_key_id(cat("llave-", N_TILDE));
    Claims c = base_claims();
    c.iss = COMPANY;
    c.sub = JAPANESE;
    c.aud = ARABIC;
    expect(c.set(cat("a", N_TILDE, "o"), "2026"), "a custom claim name may carry a tilde");
    auto tok = Token::seal(k, c);
    expect(tok.is_ok(), "international claims seal");
    if (tok.is_err()) return;
    show("issuer", COMPANY);
    show("subject", JAPANESE);
    show("audience", ARABIC);
    show("key id", *k.key_id());
    std::printf("    %-16s %zu characters, all ASCII: %s\n", "token", tok.value().size(),
                all_ascii(tok.value()) ? "yes" : "no");
    expect(all_ascii(tok.value()), "the token text is ASCII whatever the claims hold");
    const auto rules = ValidationRules().at(NOW).expect_issuer(std::string(COMPANY))
                           .expect_audience(std::string(ARABIC)).expect_subject(std::string(JAPANESE));
    auto open = Token::open(tok.value(), k, rules);
    const LegacyView lv = legacy_open(tok.value(), k);
    line("legacy check", lv.authentic ? "accepted" : "rejected");
    line("paseto5", verdict(open));
    expect(open.is_ok() && open.value().iss == COMPANY, "the issuer comes back byte for byte");
    expect(open.is_ok() && open.value().get(cat("a", N_TILDE, "o")) == std::optional<std::string_view>("2026"),
           "the custom claim comes back by its international name");
    std::puts("    Any script is carried as is; transports only ever see base64url.\n");
}

void scenario_invisible_subject() {
    std::puts("2. A subject that reads as admin but is not");
    const LocalKey k = demo_key();
    const std::string spoof = cat("admin", ZWSP);
    show("real subject", "admin");
    show("spoofed subject", spoof);
    const std::string tok = legacy_seal(k, cat("{\"sub\":\"", spoof, "\",", EXP, "}"));
    const LegacyView lv = legacy_open(tok, k);
    line("legacy check", lv.authentic ? "accepted; the audit log now shows two users called admin"
                                      : "rejected");
    expect(lv.authentic && lv.sub == spoof, "the legacy check carries the invisible character");
    Claims c = base_claims();
    c.sub = spoof;
    auto issue = Token::seal(k, c);
    auto open = Token::open(tok, k, ValidationRules().at(NOW));
    line("paseto5 issue", verdict(issue));
    line("paseto5 open", verdict(open));
    expect(issue.is_err() && issue.error() == Error::argument, "paseto5 refuses to issue it");
    expect(open.is_err() && open.error() == Error::claims_malformed, "paseto5 refuses to accept it");
    std::puts("    No token with an invisible character in an identifier is ever issued or accepted.\n");
}

void scenario_bidi_log() {
    std::puts("3. A bidi override rewrites the log line");
    const LocalKey k = demo_key();
    const std::string spoof = cat("user", RLO, "nimda");
    show("subject bytes", spoof);
    std::printf("    %-16s login ok sub=", "a log line");
    std::fwrite(spoof.data(), 1, spoof.size(), stdout);
    std::puts(" role=viewer");
    const std::string tok = legacy_seal(k, cat("{\"sub\":\"", spoof, "\",", EXP, "}"));
    const LegacyView lv = legacy_open(tok, k);
    line("legacy check", lv.authentic ? "accepted; the line above is what the operator reads" : "rejected");
    expect(lv.authentic, "the legacy check carries the bidi control");
    Claims c = base_claims();
    c.sub = spoof;
    auto issue = Token::seal(k, c);
    auto open = Token::open(tok, k, ValidationRules().at(NOW));
    line("paseto5 issue", verdict(issue));
    line("paseto5 open", verdict(open));
    expect(issue.is_err() && issue.error() == Error::argument, "paseto5 refuses to issue a bidi subject");
    expect(open.is_err() && open.error() == Error::claims_malformed, "paseto5 refuses to accept one");
    std::puts("    Every identifier reads left to right, in order, in every log and UI.\n");
}

void scenario_escape_smuggling() {
    std::puts("4. An escape smuggles what a filter on the raw payload missed");
    const LocalKey k = demo_key();
    const std::string payload = cat("{\"iss\":\"acme\\u200b\",", EXP, "}");
    line("raw payload", payload);
    line("raw bytes scan", payload.find(ZWSP) == std::string::npos
                               ? "no U+200B found: the escape is six ASCII characters"
                               : "U+200B found");
    expect(payload.find(ZWSP) == std::string::npos, "the raw payload holds no invisible bytes");
    const std::string tok = legacy_seal(k, payload);
    const LegacyView lv = legacy_open(tok, k);
    show("legacy sees iss", lv.iss);
    line("legacy check", lv.authentic ? "accepted" : "rejected");
    expect(lv.authentic && lv.iss == cat("acme", ZWSP), "the legacy check decodes the escape and keeps it");
    auto open = Token::open(tok, k, ValidationRules().at(NOW).expect_issuer("acme"));
    line("paseto5 open", verdict(open));
    expect(open.is_err() && open.error() == Error::claims_malformed,
           "paseto5 applies the policy after decoding escapes");
    std::puts("    The policy runs on code points, after every escape is resolved.\n");
}

void scenario_key_id() {
    std::puts("5. A key id that is not the key id it appears to be");
    LocalKey spoofed = demo_key();
    spoofed.set_key_id(cat("prod", ZWSP));
    LocalKey prod = demo_key();
    prod.set_key_id("prod");
    show("footer kid", *spoofed.key_id());
    const std::string tok = legacy_seal(spoofed, cat("{\"sub\":\"u\",", EXP, "}"));
    line("legacy check", "the footer names a key that a keyring keyed by what it displays confuses with prod");
    auto peek = Token::peek_key_id(tok);
    auto issue = Token::seal(spoofed, base_claims());
    auto open_spoofed = Token::open(tok, spoofed, ValidationRules().at(NOW));
    auto open_prod = Token::open(tok, prod, ValidationRules().at(NOW));
    line("paseto5 peek", peek ? "returned a key id" : "returned nothing: no key is selected");
    line("paseto5 issue", verdict(issue));
    line("paseto5 open", verdict(open_spoofed) + " with the spoofed key, " + verdict(open_prod) + " with prod");
    expect(!peek.has_value(), "peek_key_id refuses a kid that breaks the policy");
    expect(issue.is_err() && issue.error() == Error::argument, "a key with such an id cannot issue");
    expect(open_spoofed.is_err() && open_spoofed.error() == Error::argument, "nor open");
    expect(open_prod.is_err() && open_prod.error() == Error::invalid,
           "the real prod key refuses the token with the one pre-authentication verdict");
    std::puts("    The kid is checked before it selects a key and bound into the tag after.\n");
}

void scenario_overlong() {
    std::puts("6. Overlong UTF-8 is not a dot");
    const LocalKey k = demo_key();
    show("issuer bytes", OVERLONG_DOTS);
    line("a lenient decoder", "reads it as \"" + lenient_decode(OVERLONG_DOTS) + "\"");
    expect(lenient_decode(OVERLONG_DOTS) == "../etc/passwd", "the lenient decoder maps C0 AE to a dot");
    const std::string tok = legacy_seal(k, cat("{\"iss\":\"", OVERLONG_DOTS, "\",", EXP, "}"));
    const LegacyView lv = legacy_open(tok, k);
    line("legacy check", lv.authentic ? "accepted" : "rejected by paseto5's own JSON reader, which is strict");
    Claims c = base_claims();
    const bool set_ok = c.set("path", OVERLONG_DOTS);
    c.iss = OVERLONG_DOTS;
    auto issue = Token::seal(k, c);
    auto open = Token::open(tok, k, ValidationRules().at(NOW));
    line("paseto5 set", set_ok ? "accepted" : "refused: not UTF-8");
    line("paseto5 issue", verdict(issue));
    line("paseto5 open", verdict(open));
    expect(!text::valid_utf8(OVERLONG_DOTS), "overlong forms are not UTF-8");
    expect(!set_ok, "a custom value that is not UTF-8 is refused");
    expect(issue.is_err() && issue.error() == Error::argument, "an issuer that is not UTF-8 is refused");
    expect(open.is_err() && open.error() == Error::claims_malformed, "and so on the way in");
    std::puts("    One strict decoder, so no two components disagree about what a byte sequence says.\n");
}

void scenario_identity() {
    std::puts("7. Escaped and raw are one identity; composed and decomposed are two");
    const LocalKey k = demo_key();
    const std::string raw = cat("{\"iss\":\"", COMPANY, "\",", EXP, "}");
    const std::string escaped = cat("{\"iss\":\"", COMPANY_ESCAPED, "\",", EXP, "}");
    line("raw payload", raw);
    line("escaped payload", escaped);
    line("legacy check", "a check on the JSON text itself calls these two different issuers");
    expect(raw != escaped, "the two payloads differ as text");
    const auto rules = ValidationRules().at(NOW).expect_issuer(std::string(COMPANY));
    auto open_raw = Token::open(legacy_seal(k, raw), k, rules);
    auto open_escaped = Token::open(legacy_seal(k, escaped), k, rules);
    line("paseto5 open", verdict(open_raw) + " raw, " + verdict(open_escaped) + " escaped");
    expect(open_raw.is_ok() && open_escaped.is_ok(), "both spellings are the same issuer");
    show("composed", COMPANY);
    show("decomposed", COMPANY_DECOMPOSED);
    auto open_decomposed = Token::open(legacy_seal(k, raw), k,
                                      ValidationRules().at(NOW).expect_issuer(std::string(COMPANY_DECOMPOSED)));
    line("paseto5 open", verdict(open_decomposed) + " when the verifier expects the decomposed form");
    expect(open_decomposed.is_err() && open_decomposed.error() == Error::issuer_mismatch,
           "no normalisation: the comparison is byte for byte");
    std::puts("    Comparison happens on decoded code points, in constant time, with no normalisation.\n");
}

void scenario_no_oracle() {
    std::puts("8. The policy never speaks before authentication");
    const LocalKey k = demo_key();
    std::string tok = legacy_seal(k, cat("{\"iss\":\"acme\\u200b\",", EXP, "}"));
    const std::size_t at = paseto5::Local::HEADER.size() + 40;
    tok[at] = tok[at] == 'A' ? 'B' : 'A';
    auto open = Token::open(tok, k, ValidationRules().at(NOW));
    const LegacyView lv = legacy_open(tok, k);
    line("legacy check", lv.authentic ? "accepted" : "rejected");
    line("paseto5 open", verdict(open));
    expect(open.is_err() && open.error() == Error::invalid,
           "a tampered token gets the one verdict, never a text verdict");
    std::puts("    A forger cannot probe the text policy: it runs only on authenticated bytes.\n");
}

}

int main() {
    std::puts("paseto5 international text: the legacy check against the text policy\n");
    scenario_round_trip();
    scenario_invisible_subject();
    scenario_bidi_log();
    scenario_escape_smuggling();
    scenario_key_id();
    scenario_overlong();
    scenario_identity();
    scenario_no_oracle();
    if (failures != 0) {
        std::printf("%d expectation(s) failed\n", failures);
        return 1;
    }
    std::puts("8 scenarios, every expectation held");
    return 0;
}
