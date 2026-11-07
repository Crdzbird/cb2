#pragma once

/**
 * cb2: the single include.
 *
 * cb2.local and cb2.public tokens, the typed claims layer, the key types with
 * their PASERK forms and ids, and kcb2.local-wrap. cb2.public and the
 * PublicKey and SecretKey types exist only when CB2_HAS_PQ is defined,
 * which the CMake target does when liboqs is available; without it the
 * public purpose is absent, never silently reduced to Ed25519 alone.
 *
 * cb2 is CipherBird's proposal for a successor to PASETO version 4.
 * It is not a paseto-standard version; see docs/SPEC.md.
 */

#include "result.hpp"
#include "keys.hpp"
#include "local.hpp"
#include "public.hpp"
#include "holder.hpp"
#include "keywrap.hpp"
#include "seal.hpp"
#include "text.hpp"
#include "json.hpp"
#include "claims.hpp"
#include "compact.hpp"

namespace cb2 {

inline constexpr std::string_view VERSION = "0.1.0";

/// Whether this build has the cb2.public purpose.
[[nodiscard]] constexpr bool has_public() noexcept {
#ifdef CB2_HAS_PQ
    return true;
#else
    return false;
#endif
}

}
