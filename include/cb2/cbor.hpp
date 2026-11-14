#pragma once

/**
 * The strict CBOR subset of the cb3 claims profile (PROTOCOL.md section
 * 15): definite lengths only, every head in its shortest form, the major
 * types unsigned and negative integer, byte string, text string, array
 * and map, and the simple values false, true and null. No tags, no
 * floating point, no undefined, no other simple value, no indefinite
 * length and no reserved additional information. Integers are kept within
 * int64. Text is well-formed UTF-8. Map keys inside a custom claim value
 * are text strings, unique, in the order written.
 *
 * Writer appends items to a string; Reader reads them from a byte span
 * and fails on the first byte outside the profile. Every length is
 * checked against the bytes left before anything is allocated, and
 * nesting is bounded, so a hostile payload costs at most its own size.
 * The reader runs only on authenticated payloads.
 */

#include "json.hpp"
#include "text.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace cb2::cbor {

inline constexpr uint8_t MAJOR_UINT = 0;
inline constexpr uint8_t MAJOR_NINT = 1;
inline constexpr uint8_t MAJOR_BYTES = 2;
inline constexpr uint8_t MAJOR_TEXT = 3;
inline constexpr uint8_t MAJOR_ARRAY = 4;
inline constexpr uint8_t MAJOR_MAP = 5;
inline constexpr uint8_t MAJOR_TAG = 6;
inline constexpr uint8_t MAJOR_SIMPLE = 7;
inline constexpr uint8_t SIMPLE_FALSE = 20;
inline constexpr uint8_t SIMPLE_TRUE = 21;
inline constexpr uint8_t SIMPLE_NULL = 22;

/// Parses the text of a JSON number that is an integer in int64 written
/// without a sign other than one leading minus, without leading zeros and
/// without fraction or exponent. "-0" is refused, so that every integer
/// has one spelling.
[[nodiscard]] inline bool canonical_int(std::string_view s, int64_t& out) noexcept {
    const bool neg = !s.empty() && s[0] == '-';
    const std::string_view d = neg ? s.substr(1) : s;
    if (d.empty() || d.size() > 19 || (d[0] == '0' && (d.size() > 1 || neg))) return false;
    uint64_t v = 0;
    for (const char c : d) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    constexpr uint64_t MAX = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    if (v > MAX + (neg ? 1u : 0u)) return false;
    if (neg) {
        out = v == MAX + 1 ? std::numeric_limits<int64_t>::min() : -static_cast<int64_t>(v);
        return true;
    }
    out = static_cast<int64_t>(v);
    return true;
}

class Writer {
public:
    /// Appends a head: the major type and its argument in shortest form.
    static void head(std::string& out, uint8_t major, uint64_t arg) {
        const auto m = static_cast<uint8_t>(major << 5);
        if (arg < 24) {
            out += static_cast<char>(m | arg);
            return;
        }
        const int n = arg <= 0xffu ? 1 : arg <= 0xffffu ? 2 : arg <= 0xffffffffu ? 4 : 8;
        const uint8_t info = n == 1 ? 24 : n == 2 ? 25 : n == 4 ? 26 : 27;
        out += static_cast<char>(m | info);
        for (int k = n - 1; k >= 0; --k) out += static_cast<char>((arg >> (8 * k)) & 0xffu);
    }

    static void integer(std::string& out, int64_t v) {
        if (v >= 0) {
            head(out, MAJOR_UINT, static_cast<uint64_t>(v));
            return;
        }
        head(out, MAJOR_NINT, static_cast<uint64_t>(-(v + 1)));
    }

    static void text(std::string& out, std::string_view s) {
        head(out, MAJOR_TEXT, s.size());
        out.append(s);
    }

    static void bytes(std::string& out, std::span<const uint8_t> b) {
        head(out, MAJOR_BYTES, b.size());
        out.append(reinterpret_cast<const char*>(b.data()), b.size());
    }

    /// Appends a JSON value. False when it holds a number that is not an
    /// int64 integer in canonical form, which the profile cannot carry.
    [[nodiscard]] static bool value(std::string& out, const json::Value& v) {
        switch (v.kind) {
            case json::Value::Kind::null: out += static_cast<char>(0xe0 | SIMPLE_NULL); return true;
            case json::Value::Kind::boolean:
                out += static_cast<char>(0xe0 | (v.b ? SIMPLE_TRUE : SIMPLE_FALSE));
                return true;
            case json::Value::Kind::number: {
                int64_t n = 0;
                if (!canonical_int(v.text, n)) return false;
                integer(out, n);
                return true;
            }
            case json::Value::Kind::string: text(out, v.text); return true;
            case json::Value::Kind::array:
                head(out, MAJOR_ARRAY, v.items.size());
                for (const auto& item : v.items) if (!value(out, item)) return false;
                return true;
            case json::Value::Kind::object:
                head(out, MAJOR_MAP, v.members.size());
                for (const auto& [k, m] : v.members) {
                    text(out, k);
                    if (!value(out, m)) return false;
                }
                return true;
        }
        return false;
    }
};

/// One head as read: the major type, the additional information and the
/// argument (the value, the length or the count; for a simple value, its
/// number).
struct Head {
    uint8_t major = 0;
    uint8_t info = 0;
    uint64_t arg = 0;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> in) noexcept : in_(in) {}

    [[nodiscard]] bool at_end() const noexcept { return pos_ >= in_.size(); }
    [[nodiscard]] std::size_t left() const noexcept { return in_.size() - pos_; }

    /// Reads one head. Fails at the end of input, on a tag, on a reserved
    /// or indefinite additional information, on a simple value other than
    /// false, true and null, and on an argument not in its shortest form.
    [[nodiscard]] bool head(Head& h) noexcept {
        if (at_end()) return false;
        const uint8_t b = in_[pos_++];
        h.major = static_cast<uint8_t>(b >> 5);
        h.info = static_cast<uint8_t>(b & 0x1f);
        if (h.major == MAJOR_TAG) return false;
        if (h.major == MAJOR_SIMPLE) {
            h.arg = h.info;
            return h.info == SIMPLE_FALSE || h.info == SIMPLE_TRUE || h.info == SIMPLE_NULL;
        }
        if (h.info < 24) {
            h.arg = h.info;
            return true;
        }
        if (h.info > 27) return false;
        const std::size_t n = std::size_t{1} << (h.info - 24);
        if (left() < n) return false;
        uint64_t v = 0;
        for (std::size_t k = 0; k < n; ++k) v = (v << 8) | in_[pos_++];
        static constexpr uint64_t FLOOR[] = {24, 0x100, 0x10000, 0x100000000};
        if (v < FLOOR[h.info - 24]) return false;
        h.arg = v;
        return true;
    }

    /// The payload bytes of a string whose head was just read, bounded by
    /// the input left.
    [[nodiscard]] bool take(const Head& h, std::span<const uint8_t>& out) noexcept {
        if (h.arg > left()) return false;
        out = in_.subspan(pos_, static_cast<std::size_t>(h.arg));
        pos_ += static_cast<std::size_t>(h.arg);
        return true;
    }

    /// A text string whose head was just read, as well-formed UTF-8.
    [[nodiscard]] bool text_after(const Head& h, std::string& out) {
        std::span<const uint8_t> b;
        if (h.major != MAJOR_TEXT || !take(h, b)) return false;
        out.assign(reinterpret_cast<const char*>(b.data()), b.size());
        return text::valid_utf8(out);
    }

    /// An int64 integer whose head was just read.
    [[nodiscard]] static bool integer_after(const Head& h, int64_t& out) noexcept {
        constexpr uint64_t MAX = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
        if ((h.major != MAJOR_UINT && h.major != MAJOR_NINT) || h.arg > MAX) return false;
        out = h.major == MAJOR_UINT ? static_cast<int64_t>(h.arg) : -static_cast<int64_t>(h.arg) - 1;
        return true;
    }

    /// A custom claim value as JSON: integers become number text, byte
    /// strings are refused, maps need unique text keys. depth counts the
    /// containers around the value; a container at max_depth fails.
    [[nodiscard]] bool value(json::Value& v, std::size_t depth, std::size_t max_depth) {
        Head h;
        if (!head(h)) return false;
        switch (h.major) {
            case MAJOR_UINT:
            case MAJOR_NINT: {
                int64_t n = 0;
                if (!integer_after(h, n)) return false;
                v.kind = json::Value::Kind::number;
                v.text = std::to_string(n);
                return true;
            }
            case MAJOR_TEXT: v.kind = json::Value::Kind::string; return text_after(h, v.text);
            case MAJOR_ARRAY: {
                if (depth >= max_depth || h.arg > left()) return false;
                v.kind = json::Value::Kind::array;
                v.items.resize(static_cast<std::size_t>(h.arg));
                for (auto& item : v.items) if (!value(item, depth + 1, max_depth)) return false;
                return true;
            }
            case MAJOR_MAP: {
                if (depth >= max_depth || h.arg > left() / 2) return false;
                v.kind = json::Value::Kind::object;
                v.members.reserve(static_cast<std::size_t>(h.arg));
                for (uint64_t k = 0; k < h.arg; ++k) {
                    Head kh;
                    std::string key;
                    if (!head(kh) || !text_after(kh, key) || v.get(key) != nullptr) return false;
                    json::Value m;
                    if (!value(m, depth + 1, max_depth)) return false;
                    v.members.emplace_back(std::move(key), std::move(m));
                }
                return true;
            }
            case MAJOR_SIMPLE:
                v.kind = h.arg == SIMPLE_NULL ? json::Value::Kind::null : json::Value::Kind::boolean;
                v.b = h.arg == SIMPLE_TRUE;
                return true;
            default: return false;
        }
    }

private:
    std::span<const uint8_t> in_;
    std::size_t pos_ = 0;
};

}
