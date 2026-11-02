#pragma once

/**
 * The reference implementations from cryptolib (PASETO v4.local and
 * cb1.local) behind a plain function table, compiled in their own
 * translation unit because cryptolib's hash.hpp includes blake3.h inside
 * namespace crypto::hash and cannot share a translation unit with
 * paseto5's global include of the same header.
 */

#include <cstddef>
#include <cstdint>

namespace bench_ref {

struct Impl {
    const char* name;
    std::size_t (*token_len)(std::size_t msg, std::size_t footer);
    std::size_t (*open_capacity)(std::size_t token_len);
    bool (*seal)(uint8_t* out, std::size_t cap, std::size_t& out_len, const uint8_t* key,
                 const uint8_t* msg, std::size_t msg_len, const uint8_t* footer, std::size_t footer_len,
                 const uint8_t* implicit, std::size_t implicit_len);
    bool (*open)(uint8_t* out, std::size_t cap, std::size_t& out_len, const uint8_t* token,
                 std::size_t token_len, const uint8_t* key, const uint8_t* footer, std::size_t footer_len,
                 const uint8_t* implicit, std::size_t implicit_len);
};

Impl v4_local();
Impl cb1_local();

}
