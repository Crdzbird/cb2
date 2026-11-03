#pragma once

/**
 * Thin RAII wrappers over the official BLAKE3 C API. The keyed hasher is
 * the keyed mode of the BLAKE3 specification (a PRF with extendable
 * output); its state is wiped on destruction because it holds the key.
 */

#include <blake3.h>
#include <sodium.h>

#include <cstddef>
#include <cstdint>

namespace cb2::detail {

class Blake3Keyed {
public:
    static constexpr std::size_t KEY_BYTES = BLAKE3_KEY_LEN;

    explicit Blake3Keyed(const uint8_t key[BLAKE3_KEY_LEN]) noexcept {
        blake3_hasher_init_keyed(&h_, key);
    }
    Blake3Keyed(const Blake3Keyed&) = delete;
    Blake3Keyed& operator=(const Blake3Keyed&) = delete;
    ~Blake3Keyed() { sodium_memzero(&h_, sizeof h_); }

    void rekey(const uint8_t key[BLAKE3_KEY_LEN]) noexcept { blake3_hasher_init_keyed(&h_, key); }
    void update(const uint8_t* p, std::size_t n) noexcept {
        if (n != 0) blake3_hasher_update(&h_, p, n);
    }
    void finalize(uint8_t* out, std::size_t n) const noexcept { blake3_hasher_finalize(&h_, out, n); }

private:
    blake3_hasher h_;
};

class Blake3 {
public:
    Blake3() noexcept { blake3_hasher_init(&h_); }
    void update(const uint8_t* p, std::size_t n) noexcept {
        if (n != 0) blake3_hasher_update(&h_, p, n);
    }
    void finalize(uint8_t* out, std::size_t n) const noexcept { blake3_hasher_finalize(&h_, out, n); }

private:
    blake3_hasher h_;
};

}
