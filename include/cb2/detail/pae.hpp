#pragma once

/**
 * Pre-Authentication Encoding, as in PASETO: the number of pieces as a
 * 64-bit little-endian integer with the top bit clear, then each piece as
 * its length in the same encoding followed by its bytes. The encoding is
 * streamed into any sink with an update(const uint8_t*, size_t) member, so
 * a MAC never needs the encoding materialised; a span sink exists for the
 * signature path, where the backends need a contiguous message.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>

namespace cb2::detail {

/// Writes n as PAE's little-endian 64-bit length with the top bit clear.
inline void put_le64(uint8_t* p, std::size_t n) noexcept {
    const uint64_t v = static_cast<uint64_t>(n) & 0x7FFFFFFFFFFFFFFFULL;
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

/// Bytes PAE produces for pieces of these lengths.
[[nodiscard]] constexpr std::size_t pae_len(std::initializer_list<std::size_t> lens) noexcept {
    std::size_t total = 8;
    for (std::size_t n : lens) total += 8 + n;
    return total;
}

/// Streams PAE(pieces...) into sink.
template <class Sink>
void pae_stream(Sink& sink, std::initializer_list<std::span<const uint8_t>> pieces) {
    uint8_t le[8];
    put_le64(le, pieces.size());
    sink.update(le, 8);
    for (const auto& p : pieces) {
        put_le64(le, p.size());
        sink.update(le, 8);
        if (!p.empty()) sink.update(p.data(), p.size());
    }
}

/// A sink that writes into a region the caller sized with pae_len.
struct SpanSink {
    uint8_t* p;
    std::size_t pos = 0;
    void update(const uint8_t* src, std::size_t n) noexcept {
        if (n != 0) std::memcpy(p + pos, src, n);
        pos += n;
    }
};

}
