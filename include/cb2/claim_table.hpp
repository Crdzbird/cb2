#pragma once

/**
 * The claim table of cb3 tokens (PROTOCOL.md section 15.5): an ordered
 * list of issuer and audience strings that the issuer and the verifier
 * both configure. With a table, an iss or aud equal to an entry travels
 * as the entry's index instead of its text, and the table's digest is
 * bound into the authenticated implicit assertion, so a token opens only
 * under the same table. The digest is never sent and never truncated.
 */

#include "cbor.hpp"
#include "detail/blake3.hpp"
#include "result.hpp"
#include "text.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cb2 {

class ClaimTable {
public:
    static constexpr std::size_t MAX_ENTRIES = 256;
    static constexpr std::size_t DIGEST_BYTES = 32;
    static constexpr std::string_view TABLE_DOMAIN = "kcb3.table.";

    /// A table of 1 to MAX_ENTRIES distinct, non-empty entries, each an
    /// identifier under the text policy of claims; argument otherwise.
    [[nodiscard]] static Result<ClaimTable> make(std::vector<std::string> entries) {
        if (entries.empty() || entries.size() > MAX_ENTRIES) return Result<ClaimTable>::err(Error::argument);
        for (std::size_t i = 0; i < entries.size(); ++i) {
            if (entries[i].empty() || !text::identifier_ok(entries[i])) return Result<ClaimTable>::err(Error::argument);
            for (std::size_t j = 0; j < i; ++j)
                if (entries[j] == entries[i]) return Result<ClaimTable>::err(Error::argument);
        }
        return Result<ClaimTable>::ok(ClaimTable(std::move(entries)));
    }

    [[nodiscard]] const std::vector<std::string>& entries() const noexcept { return entries_; }

    /// BLAKE3(TABLE_DOMAIN || the entries as one CBOR array of text strings),
    /// all 32 bytes.
    [[nodiscard]] const std::array<uint8_t, DIGEST_BYTES>& digest() const noexcept { return digest_; }

    /// The index of an entry equal to s, if there is one.
    [[nodiscard]] std::optional<uint64_t> index_of(std::string_view s) const noexcept {
        for (std::size_t i = 0; i < entries_.size(); ++i)
            if (entries_[i] == s) return static_cast<uint64_t>(i);
        return std::nullopt;
    }

    /// The entry at index i, or nullptr past the end.
    [[nodiscard]] const std::string* at(uint64_t i) const noexcept {
        return i < entries_.size() ? &entries_[static_cast<std::size_t>(i)] : nullptr;
    }

    /// The implicit assertion a tabled token authenticates: TABLE_DOMAIN, the
    /// digest, then the caller's implicit assertion.
    [[nodiscard]] std::string bind(std::string_view implicit) const {
        std::string out;
        out.reserve(TABLE_DOMAIN.size() + DIGEST_BYTES + implicit.size());
        out.append(TABLE_DOMAIN);
        out.append(reinterpret_cast<const char*>(digest_.data()), DIGEST_BYTES);
        out.append(implicit);
        return out;
    }

    /// Whether a caller's implicit assertion could be confused with a
    /// bound one; such an assertion is refused when no table is used.
    [[nodiscard]] static bool reserved(std::string_view implicit) noexcept { return implicit.starts_with(TABLE_DOMAIN); }

private:
    explicit ClaimTable(std::vector<std::string> entries) : entries_(std::move(entries)) {
        std::string encoded;
        cbor::Writer::head(encoded, cbor::MAJOR_ARRAY, entries_.size());
        for (const auto& e : entries_) cbor::Writer::text(encoded, e);
        detail::Blake3 h;
        h.update(reinterpret_cast<const uint8_t*>(TABLE_DOMAIN.data()), TABLE_DOMAIN.size());
        h.update(reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size());
        h.finalize(digest_.data(), DIGEST_BYTES);
    }

    std::vector<std::string> entries_;
    std::array<uint8_t, DIGEST_BYTES> digest_{};
};

}
