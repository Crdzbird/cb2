#pragma once

/**
 * Holder proofs: the raw purpose a sender-constrained token's proof is
 * made of, and the request it binds. A holder proof shows that the
 * presenter of an access token holds the key the token's cnf claim names.
 *
 *   cb2.holder-public.   the hybrid signature construction of public.hpp
 *                        with this header as the domain string, under the
 *                        client's key pair; present only under CB2_HAS_PQ
 *   cb2.holder-local.    the cb2.local construction with this header,
 *                        under the 32-byte proof key the issuer wrote into
 *                        cnf of a cb2.local access token and handed to the
 *                        client with it; present in every build
 *
 * The footer of a proof is the key id binding of the bound key (its
 * kcb2.pid or kcb2.lid) and its implicit assertion is the complete text
 * of the access token it accompanies, so a proof is worthless with any
 * other token. The header is the ML-DSA context string of a public proof
 * and enters the key derivation and the tag of a local one, so a proof is
 * never a cb2.public or cb2.local token and a token is never a proof,
 * under the same key.
 *
 * The claims of a proof and their validation are in claims.hpp
 * (HolderProof); this header holds what the claims layer needs first:
 * the request description and the target normalisation both ends apply.
 */

#include "result.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#ifdef CB2_HAS_PQ
#include "public.hpp"
#endif

namespace cb2 {

/// The request a holder proof is made for and checked against.
struct HolderRequest {
    /// The HTTP method, uppercase by convention; compared byte for byte.
    std::string method;
    /// The request URI; normalised by Holder::normalize_target on both ends.
    std::string target;
    /// A value the verifier handed out, when it uses server nonces.
    std::optional<std::string> nonce;
};

class Holder {
public:
    static constexpr std::string_view PUBLIC_HEADER = "cb2.holder-public.";
    static constexpr std::string_view LOCAL_HEADER = "cb2.holder-local.";
    /// A cnf value that names a client public key.
    static constexpr std::string_view CNF_PUBLIC_PREFIX = "kcb2.public.";
    /// A cnf value that carries a symmetric proof key (the local mode).
    static constexpr std::string_view CNF_LOCAL_PREFIX = "kcb2.local.";
    /// The longest life a proof may claim unless the verifier says otherwise.
    static constexpr int64_t DEFAULT_LIFETIME = 60;

    /// The target as both ends write and compare it: the query and the
    /// fragment removed, the scheme and the host lowercased, a port that
    /// is the scheme's default removed, an empty path written as "/",
    /// nothing else changed. Nothing for a URI without a scheme and a
    /// host, with userinfo, or with a port that is not digits.
    [[nodiscard]] static std::optional<std::string> normalize_target(std::string_view uri) {
        const std::size_t sep = uri.find("://");
        if (sep == 0 || sep == std::string_view::npos) return std::nullopt;
        std::string scheme = lower(uri.substr(0, sep));
        for (const char c : scheme) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'))
                return std::nullopt;
        }
        if (scheme[0] < 'a' || scheme[0] > 'z') return std::nullopt;
        std::string_view rest = uri.substr(sep + 3);
        const std::size_t cut = rest.find_first_of("?#");
        if (cut != std::string_view::npos) rest = rest.substr(0, cut);
        const std::size_t slash = rest.find('/');
        std::string_view authority = slash == std::string_view::npos ? rest : rest.substr(0, slash);
        const std::string_view path = slash == std::string_view::npos ? std::string_view("/") : rest.substr(slash);
        if (authority.empty() || authority.find('@') != std::string_view::npos) return std::nullopt;
        std::string_view host = authority;
        std::string_view port;
        const std::size_t bracket = authority.rfind(']');
        const std::size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket)) {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        }
        if (host.empty()) return std::nullopt;
        for (const char c : port) {
            if (c < '0' || c > '9') return std::nullopt;
        }
        if (port == (scheme == "https" ? "443" : scheme == "http" ? "80" : "")) port = {};
        std::string out = scheme + "://" + lower(host);
        if (!port.empty()) out += ":" + std::string(port);
        out += path;
        return out;
    }

private:
    [[nodiscard]] static std::string lower(std::string_view s) {
        std::string out(s);
        for (char& c : out) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        return out;
    }
};

}
