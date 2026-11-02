#pragma once

/**
 * paseto5: the single include.
 *
 * v5.local and v5.public tokens, the typed claims layer, the key types with
 * their PASERK forms and ids, and k5.local-wrap. v5.public and the
 * PublicKey and SecretKey types exist only when PASETO5_HAS_PQ is defined,
 * which the CMake target does when liboqs is available; without it the
 * public purpose is absent, never silently reduced to Ed25519 alone.
 *
 * paseto5 is CipherBird's proposal for a successor to PASETO version 4.
 * It is not a paseto-standard version; see docs/SPEC.md.
 */

#include "result.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "public.hpp"
#include "keywrap.hpp"
#include "json.hpp"
#include "claims.hpp"

namespace paseto5 {

inline constexpr std::string_view VERSION = "0.1.0";

/// Whether this build has the v5.public purpose.
[[nodiscard]] constexpr bool has_public() noexcept {
#ifdef PASETO5_HAS_PQ
    return true;
#else
    return false;
#endif
}

}
