#pragma once

/**
 * Helpers shared by the tests and the vector generator: hex, files, the
 * vector JSON files read through the library's own strict reader, and a
 * deterministic byte pattern.
 */

#include <cb2/cb2.hpp>
#include <sodium.h>

#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace tu {

using Bytes = std::vector<uint8_t>;

inline Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

inline std::span<const uint8_t> sp(const Bytes& b) { return b; }

inline std::span<const uint8_t> sp(std::string_view s) { return cb2::bytes(s); }

inline std::string hex(std::span<const uint8_t> b) {
    std::string s(b.size() * 2 + 1, '\0');
    sodium_bin2hex(s.data(), s.size(), b.data(), b.size());
    s.resize(b.size() * 2);
    return s;
}

inline Bytes unhex(std::string_view h) {
    Bytes out(h.size() / 2 + 1);
    size_t n = 0;
    if (sodium_hex2bin(out.data(), out.size(), h.data(), h.size(), nullptr, &n, nullptr) != 0) return {};
    out.resize(n);
    return out;
}

inline Bytes pattern(size_t n, uint8_t start) {
    Bytes v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(start + 7 * i);
    return v;
}

inline std::optional<std::string> read_file(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) return std::nullopt;
    std::string s;
    char buf[65536];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

inline bool write_file(const char* path, std::string_view text) {
    std::FILE* f = std::fopen(path, "wb");
    if (f == nullptr) return false;
    const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
    std::fclose(f);
    return ok;
}

inline std::string str(const cb2::json::Value& v, std::string_view key) {
    const auto* m = v.get(key);
    return m != nullptr && m->is_string() ? m->text : std::string();
}

inline bool flag(const cb2::json::Value& v, std::string_view key) {
    const auto* m = v.get(key);
    return m != nullptr && m->kind == cb2::json::Value::Kind::boolean && m->b;
}

inline long long num(const cb2::json::Value& v, std::string_view key) {
    const auto* m = v.get(key);
    return m != nullptr && m->kind == cb2::json::Value::Kind::number ? std::stoll(m->text) : 0;
}

/// Rules at a fixed clock that accept any audience and issuer, for tests
/// whose subject is something else.
inline cb2::ValidationRules lenient(cb2::Seconds now) {
    return cb2::ValidationRules().at(now).allow_any_audience().allow_any_issuer();
}

inline std::string str_of(std::span<const uint8_t> b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

}
