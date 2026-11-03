#pragma once

/**
 * Text rules for the strings a token carries.
 *
 * Every string in a cb2 token is UTF-8, so any script (Latin with
 * diacritics, Cyrillic, Greek, Arabic, Hebrew, the CJK scripts, emoji and
 * anything else Unicode encodes) is carried as is, raw in the JSON, and
 * compared byte for byte after escapes are resolved. The decoder here is
 * strict: no overlong forms, no surrogates, nothing above U+10FFFF.
 *
 * Identifiers (iss, sub, aud, jti, custom claim names and key ids) are
 * compared for equality, so they must not contain characters that are
 * invisible or that alter how neighbouring text is displayed: an issuer
 * that looks like another but differs by a zero-width or a bidi control
 * character would pass a human review and fail, or pass, the comparison
 * unexpectedly. The identifier policy rejects C0 and C1 controls, the
 * Unicode Default_Ignorable_Code_Point set (soft hyphen, zero-width
 * characters, bidi and other format controls, variation selectors, tags),
 * noncharacters and private-use code points. Everything else, including
 * every letter of every script, is accepted. The policy performs no
 * normalisation: U+00F1 and U+006E U+0303 are two different identifiers,
 * and an issuer must emit one form consistently.
 */

#include <cstddef>
#include <string_view>

namespace cb2::text {

/// Decodes one UTF-8 code point at in[i], strictly; advances i.
[[nodiscard]] inline bool decode(std::string_view in, std::size_t& i, unsigned& cp) noexcept {
    const auto c0 = static_cast<unsigned char>(in[i]);
    if (c0 < 0x80) { cp = c0; ++i; return true; }
    std::size_t len = 0;
    if (c0 >= 0xC2 && c0 <= 0xDF) { len = 2; cp = c0 & 0x1Fu; }
    if (c0 >= 0xE0 && c0 <= 0xEF) { len = 3; cp = c0 & 0x0Fu; }
    if (c0 >= 0xF0 && c0 <= 0xF4) { len = 4; cp = c0 & 0x07u; }
    if (len == 0 || i + len > in.size()) return false;
    for (std::size_t k = 1; k < len; ++k) {
        const auto c = static_cast<unsigned char>(in[i + k]);
        if ((c & 0xC0) != 0x80) return false;
        cp = cp << 6 | (c & 0x3Fu);
    }
    if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
        (cp >= 0xD800 && cp <= 0xDFFF))
        return false;
    i += len;
    return true;
}

/// Whether s is well-formed UTF-8.
[[nodiscard]] inline bool valid_utf8(std::string_view s) noexcept {
    std::size_t i = 0;
    unsigned cp = 0;
    while (i < s.size()) {
        if (!decode(s, i, cp)) return false;
    }
    return true;
}

/// C0 and C1 control characters.
[[nodiscard]] constexpr bool is_control(unsigned cp) noexcept {
    return cp < 0x20 || (cp >= 0x7F && cp <= 0x9F);
}

/// The Unicode Default_Ignorable_Code_Point property, Unicode 15.1.
[[nodiscard]] constexpr bool is_default_ignorable(unsigned cp) noexcept {
    return cp == 0x00AD || cp == 0x034F || cp == 0x061C || (cp >= 0x115F && cp <= 0x1160) ||
           (cp >= 0x17B4 && cp <= 0x17B5) || (cp >= 0x180B && cp <= 0x180F) ||
           (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) ||
           (cp >= 0x2060 && cp <= 0x206F) || cp == 0x3164 || (cp >= 0xFE00 && cp <= 0xFE0F) ||
           cp == 0xFEFF || cp == 0xFFA0 || (cp >= 0xFFF0 && cp <= 0xFFF8) ||
           (cp >= 0x1BCA0 && cp <= 0x1BCA3) || (cp >= 0x1D173 && cp <= 0x1D17A) ||
           (cp >= 0xE0000 && cp <= 0xE0FFF);
}

/// The 66 noncharacters: U+FDD0..U+FDEF and the last two code points of
/// every plane.
[[nodiscard]] constexpr bool is_noncharacter(unsigned cp) noexcept {
    return (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFEu) == 0xFFFEu;
}

/// The private-use area and the two private-use planes.
[[nodiscard]] constexpr bool is_private_use(unsigned cp) noexcept {
    return (cp >= 0xE000 && cp <= 0xF8FF) || (cp >= 0xF0000 && cp <= 0x10FFFF);
}

/// Whether a code point may appear in an identifier.
[[nodiscard]] constexpr bool identifier_char(unsigned cp) noexcept {
    return !is_control(cp) && !is_default_ignorable(cp) && !is_noncharacter(cp) &&
           !is_private_use(cp);
}

/// Whether s is well-formed UTF-8 made only of identifier characters.
[[nodiscard]] inline bool identifier_ok(std::string_view s) noexcept {
    std::size_t i = 0;
    unsigned cp = 0;
    while (i < s.size()) {
        if (!decode(s, i, cp) || !identifier_char(cp)) return false;
    }
    return true;
}

}
