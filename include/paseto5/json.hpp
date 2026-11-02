#pragma once

/**
 * A minimal, strict JSON reader and writer for claims and footers.
 *
 * The reader accepts exactly RFC 8259: one value, the four JSON whitespace
 * characters only, strings with valid escapes and valid UTF-8, numbers by
 * the grammar (kept as text, never converted, so there is no coercion),
 * no duplicate member names, no trailing commas, and nesting bounded by
 * max_depth. Anything else fails. Numbers are stored as their verbatim
 * text; the claims layer only ever needs strings.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace paseto5::json {

struct Value {
    enum class Kind : uint8_t { null, boolean, number, string, array, object };
    Kind kind = Kind::null;
    bool b = false;
    std::string text;
    std::vector<Value> items;
    std::vector<std::pair<std::string, Value>> members;

    [[nodiscard]] const Value* get(std::string_view key) const noexcept {
        for (const auto& [k, v] : members) if (k == key) return &v;
        return nullptr;
    }
    [[nodiscard]] bool is_string() const noexcept { return kind == Kind::string; }
    [[nodiscard]] bool is_object() const noexcept { return kind == Kind::object; }
};

inline constexpr std::size_t DEFAULT_MAX_DEPTH = 16;

class Reader {
public:
    [[nodiscard]] static bool parse(std::string_view in, Value& out,
                                    std::size_t max_depth = DEFAULT_MAX_DEPTH) {
        Reader r{in, 0, max_depth};
        r.ws();
        if (!r.value(out, 0)) return false;
        r.ws();
        return r.i == in.size();
    }

private:
    Reader(std::string_view text, std::size_t pos, std::size_t depth) noexcept
        : in(text), i(pos), max_depth(depth) {}

    std::string_view in;
    std::size_t i;
    std::size_t max_depth;

    [[nodiscard]] bool at_end() const noexcept { return i >= in.size(); }
    [[nodiscard]] char peek() const noexcept { return in[i]; }

    void ws() noexcept {
        while (!at_end() && (in[i] == ' ' || in[i] == '\t' || in[i] == '\n' || in[i] == '\r')) ++i;
    }

    [[nodiscard]] bool literal(std::string_view word) noexcept {
        if (in.substr(i, word.size()) != word) return false;
        i += word.size();
        return true;
    }

    [[nodiscard]] bool value(Value& v, std::size_t depth) {
        if (at_end()) return false;
        switch (peek()) {
            case '{': return object(v, depth);
            case '[': return array(v, depth);
            case '"': v.kind = Value::Kind::string; return string(v.text);
            case 't': v.kind = Value::Kind::boolean; v.b = true; return literal("true");
            case 'f': v.kind = Value::Kind::boolean; v.b = false; return literal("false");
            case 'n': v.kind = Value::Kind::null; return literal("null");
            default: v.kind = Value::Kind::number; return number(v.text);
        }
    }

    [[nodiscard]] bool object(Value& v, std::size_t depth) {
        if (depth >= max_depth) return false;
        v.kind = Value::Kind::object;
        ++i;
        ws();
        if (!at_end() && peek() == '}') { ++i; return true; }
        for (;;) {
            ws();
            std::string key;
            if (at_end() || peek() != '"' || !string(key)) return false;
            if (v.get(key) != nullptr) return false;
            ws();
            if (at_end() || peek() != ':') return false;
            ++i;
            ws();
            Value member;
            if (!value(member, depth + 1)) return false;
            v.members.emplace_back(std::move(key), std::move(member));
            ws();
            if (at_end()) return false;
            if (peek() == ',') { ++i; continue; }
            if (peek() == '}') { ++i; return true; }
            return false;
        }
    }

    [[nodiscard]] bool array(Value& v, std::size_t depth) {
        if (depth >= max_depth) return false;
        v.kind = Value::Kind::array;
        ++i;
        ws();
        if (!at_end() && peek() == ']') { ++i; return true; }
        for (;;) {
            ws();
            Value item;
            if (!value(item, depth + 1)) return false;
            v.items.push_back(std::move(item));
            ws();
            if (at_end()) return false;
            if (peek() == ',') { ++i; continue; }
            if (peek() == ']') { ++i; return true; }
            return false;
        }
    }

    [[nodiscard]] static int hexval(char c) noexcept {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    [[nodiscard]] bool hex4(unsigned& cp) noexcept {
        if (i + 4 > in.size()) return false;
        cp = 0;
        for (int k = 0; k < 4; ++k) {
            const int h = hexval(in[i + static_cast<std::size_t>(k)]);
            if (h < 0) return false;
            cp = cp << 4 | static_cast<unsigned>(h);
        }
        i += 4;
        return true;
    }

    static void put_utf8(std::string& o, unsigned cp) {
        if (cp < 0x80) { o += static_cast<char>(cp); return; }
        if (cp < 0x800) {
            o += static_cast<char>(0xC0 | (cp >> 6));
            o += static_cast<char>(0x80 | (cp & 0x3F));
            return;
        }
        if (cp < 0x10000) {
            o += static_cast<char>(0xE0 | (cp >> 12));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
            return;
        }
        o += static_cast<char>(0xF0 | (cp >> 18));
        o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        o += static_cast<char>(0x80 | (cp & 0x3F));
    }

    [[nodiscard]] bool escape(std::string& o) {
        if (at_end()) return false;
        const char e = in[i++];
        switch (e) {
            case '"': o += '"'; return true;
            case '\\': o += '\\'; return true;
            case '/': o += '/'; return true;
            case 'b': o += '\b'; return true;
            case 'f': o += '\f'; return true;
            case 'n': o += '\n'; return true;
            case 'r': o += '\r'; return true;
            case 't': o += '\t'; return true;
            case 'u': break;
            default: return false;
        }
        unsigned cp = 0;
        if (!hex4(cp)) return false;
        if (cp >= 0xDC00 && cp <= 0xDFFF) return false;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (in.substr(i, 2) != "\\u") return false;
            i += 2;
            unsigned lo = 0;
            if (!hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) return false;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        }
        put_utf8(o, cp);
        return true;
    }

    [[nodiscard]] bool utf8_sequence(std::string& o) {
        const auto c0 = static_cast<unsigned char>(in[i]);
        std::size_t len = 0;
        unsigned cp = 0;
        if (c0 >= 0xC2 && c0 <= 0xDF) { len = 2; cp = c0 & 0x1F; }
        if (c0 >= 0xE0 && c0 <= 0xEF) { len = 3; cp = c0 & 0x0F; }
        if (c0 >= 0xF0 && c0 <= 0xF4) { len = 4; cp = c0 & 0x07; }
        if (len == 0 || i + len > in.size()) return false;
        for (std::size_t k = 1; k < len; ++k) {
            const auto c = static_cast<unsigned char>(in[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = cp << 6 | (c & 0x3F);
        }
        if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        o.append(in.data() + i, len);
        i += len;
        return true;
    }

    [[nodiscard]] bool string(std::string& o) {
        ++i;
        for (;;) {
            if (at_end()) return false;
            const auto c = static_cast<unsigned char>(in[i]);
            if (c == '"') { ++i; return true; }
            if (c == '\\') { ++i; if (!escape(o)) return false; continue; }
            if (c < 0x20) return false;
            if (c < 0x80) { o += static_cast<char>(c); ++i; continue; }
            if (!utf8_sequence(o)) return false;
        }
    }

    [[nodiscard]] bool digits(std::size_t& n) noexcept {
        const std::size_t start = i;
        while (!at_end() && peek() >= '0' && peek() <= '9') ++i;
        n = i - start;
        return n != 0;
    }

    [[nodiscard]] bool number(std::string& o) {
        const std::size_t start = i;
        if (!at_end() && peek() == '-') ++i;
        if (at_end()) return false;
        if (peek() == '0') {
            ++i;
        } else {
            std::size_t n = 0;
            if (peek() < '1' || peek() > '9' || !digits(n)) return false;
        }
        if (!at_end() && peek() == '.') {
            ++i;
            std::size_t n = 0;
            if (!digits(n)) return false;
        }
        if (!at_end() && (peek() == 'e' || peek() == 'E')) {
            ++i;
            if (!at_end() && (peek() == '+' || peek() == '-')) ++i;
            std::size_t n = 0;
            if (!digits(n)) return false;
        }
        o.assign(in.data() + start, i - start);
        return true;
    }
};

class Writer {
public:
    static void string(std::string& out, std::string_view s) {
        static constexpr char HEX[] = "0123456789abcdef";
        out += '"';
        for (const char ch : s) {
            const auto c = static_cast<unsigned char>(ch);
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        out += "\\u00";
                        out += HEX[c >> 4];
                        out += HEX[c & 15];
                    } else {
                        out += ch;
                    }
            }
        }
        out += '"';
    }

    static void value(std::string& out, const Value& v) {
        switch (v.kind) {
            case Value::Kind::null: out += "null"; return;
            case Value::Kind::boolean: out += v.b ? "true" : "false"; return;
            case Value::Kind::number: out += v.text; return;
            case Value::Kind::string: string(out, v.text); return;
            case Value::Kind::array: {
                out += '[';
                bool first = true;
                for (const auto& item : v.items) {
                    if (!first) out += ',';
                    first = false;
                    value(out, item);
                }
                out += ']';
                return;
            }
            case Value::Kind::object: {
                out += '{';
                bool first = true;
                for (const auto& [k, m] : v.members) {
                    if (!first) out += ',';
                    first = false;
                    string(out, k);
                    out += ':';
                    value(out, m);
                }
                out += '}';
                return;
            }
        }
    }
};

}
