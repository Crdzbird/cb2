#pragma once

/**
 * Unpadded base64url (RFC 4648 section 5) for token text. The decoder is
 * strict: only the 64 URL-safe characters, no padding, no length of 1 mod
 * 4, and the unused low bits of the final character must be zero, so each
 * byte string has exactly one accepted encoding. The codec is table driven
 * and not constant time; it is used only on public bytes (nonce, ciphertext,
 * tag, signature, footer, key ids), never on a key.
 */

#include <cstddef>
#include <cstdint>

namespace cb2::detail::b64 {

inline constexpr char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
inline constexpr uint8_t BAD = 0x80;

struct DecodeTable {
    uint8_t v[256];
    constexpr DecodeTable() noexcept : v{} {
        for (auto& x : v) x = BAD;
        for (uint8_t k = 0; k < 64; ++k) v[static_cast<unsigned char>(ALPHABET[k])] = k;
    }
};

inline constexpr DecodeTable DECODE{};

/// Characters needed to encode len bytes.
[[nodiscard]] constexpr std::size_t encoded_len(std::size_t len) noexcept {
    return len / 3 * 4 + (len % 3 == 0 ? 0 : len % 3 + 1);
}

/// Bytes a text of len characters decodes to, or SIZE_MAX when no byte
/// string encodes to that length.
[[nodiscard]] constexpr std::size_t decoded_len(std::size_t len) noexcept {
    const std::size_t rem = len % 4;
    if (rem == 1) return static_cast<std::size_t>(-1);
    return len / 4 * 3 + (rem == 0 ? 0 : rem - 1);
}

/// Writes the encoding of src[0, len) to dst and returns encoded_len(len).
/// dst and src must not overlap, except that src may start at or after
/// dst + encoded_len(len) - len (the input placed at the end of the output
/// region): each input group is read before its output is written.
inline std::size_t encode(char* dst, const uint8_t* src, std::size_t len) noexcept {
    std::size_t i = 0, w = 0;
    for (; len - i >= 3; i += 3, w += 4) {
        const uint32_t v = uint32_t{src[i]} << 16 | uint32_t{src[i + 1]} << 8 | src[i + 2];
        dst[w] = ALPHABET[v >> 18];
        dst[w + 1] = ALPHABET[(v >> 12) & 63];
        dst[w + 2] = ALPHABET[(v >> 6) & 63];
        dst[w + 3] = ALPHABET[v & 63];
    }
    const std::size_t rem = len - i;
    if (rem == 0) return w;
    const uint32_t v = uint32_t{src[i]} << 16 | (rem == 2 ? uint32_t{src[i + 1]} << 8 : 0);
    dst[w] = ALPHABET[v >> 18];
    dst[w + 1] = ALPHABET[(v >> 12) & 63];
    if (rem == 2) dst[w + 2] = ALPHABET[(v >> 6) & 63];
    return w + rem + 1;
}

/// Decodes src[0, len) into dst (capacity cap) and sets n to the decoded
/// length. Returns false, with n set to 0, on any non-canonical input or
/// when the result would exceed cap; dst may then hold partial output.
inline bool decode(uint8_t* dst, std::size_t cap, const char* src, std::size_t len,
                   std::size_t& n) noexcept {
    n = 0;
    const std::size_t need = decoded_len(len);
    if (need == static_cast<std::size_t>(-1) || need > cap) return false;
    const auto* s = reinterpret_cast<const unsigned char*>(src);
    uint32_t bad = 0;
    std::size_t i = 0, w = 0;
    for (; len - i >= 4; i += 4, w += 3) {
        const uint32_t a = DECODE.v[s[i]], b = DECODE.v[s[i + 1]];
        const uint32_t c = DECODE.v[s[i + 2]], d = DECODE.v[s[i + 3]];
        bad |= a | b | c | d;
        const uint32_t v = (a & 63) << 18 | (b & 63) << 12 | (c & 63) << 6 | (d & 63);
        dst[w] = static_cast<uint8_t>(v >> 16);
        dst[w + 1] = static_cast<uint8_t>(v >> 8);
        dst[w + 2] = static_cast<uint8_t>(v);
    }
    const std::size_t rem = len - i;
    if (rem != 0) {
        const uint32_t a = DECODE.v[s[i]], b = DECODE.v[s[i + 1]];
        const uint32_t c = rem == 3 ? DECODE.v[s[i + 2]] : 0;
        bad |= a | b | c;
        const uint32_t v = (a & 63) << 18 | (b & 63) << 12 | (c & 63) << 6;
        const uint32_t spare = rem == 2 ? (v >> 8) & 0xFF : v & 0xFF;
        bad |= spare == 0 ? 0 : BAD;
        dst[w] = static_cast<uint8_t>(v >> 16);
        if (rem == 3) dst[w + 1] = static_cast<uint8_t>(v >> 8);
    }
    if ((bad & BAD) != 0) return false;
    n = need;
    return true;
}

}
