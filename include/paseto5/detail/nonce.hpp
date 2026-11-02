#pragma once

/**
 * The nonce source: libsodium's randombytes_buf and nothing else. It never
 * returns weak output; libsodium aborts the process if the operating
 * system's random device is unavailable, which is the fail-closed
 * behaviour this library wants. The deterministic hook used to produce
 * known-answer vectors exists only when PASETO5_TEST_NONCE is defined and
 * is reachable only through the *_with_nonce_for_testing functions.
 */

#include <sodium.h>

#include <cstddef>
#include <cstdint>

namespace paseto5::detail {

inline void fresh_nonce(uint8_t* n, std::size_t len) noexcept { randombytes_buf(n, len); }

}
