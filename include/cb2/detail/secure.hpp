#pragma once

/**
 * Secret memory helpers: a zeroizing allocator, the SecureBytes and
 * SecureString containers built on it, fixed-size wiped arrays and the
 * constant-time comparison used for every secret or key-id comparison.
 * Every primitive is libsodium's; nothing here is hand-rolled.
 */

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cb2 {

/// Allocator that wipes every block with sodium_memzero before freeing it.
template <class T>
struct ZeroizingAllocator {
    using value_type = T;
    ZeroizingAllocator() noexcept = default;
    template <class U>
    ZeroizingAllocator(const ZeroizingAllocator<U>&) noexcept {}
    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > static_cast<std::size_t>(-1) / sizeof(T)) throw std::bad_alloc();
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }
    void deallocate(T* p, std::size_t n) noexcept {
        sodium_memzero(p, n * sizeof(T));
        ::operator delete(p);
    }
    template <class U>
    bool operator==(const ZeroizingAllocator<U>&) const noexcept { return true; }
    template <class U>
    bool operator!=(const ZeroizingAllocator<U>&) const noexcept { return false; }
};

/// Bytes that are wiped when freed. Used for plaintexts and secret keys.
using SecureBytes = std::vector<uint8_t, ZeroizingAllocator<uint8_t>>;

/// Text that is wiped when freed. Used for the PASERK form of secret keys.
using SecureString = std::basic_string<char, std::char_traits<char>, ZeroizingAllocator<char>>;

namespace detail {

/// Wipes n bytes at p.
inline void wipe(void* p, std::size_t n) noexcept { sodium_memzero(p, n); }

/// Keeps n bytes at p out of swap and, where the platform allows, out of
/// core dumps. Best effort: a platform or a limit that refuses is
/// ignored, and the memory is wiped on release either way.
inline void lock(void* p, std::size_t n) noexcept { (void)sodium_mlock(p, n); }

/// Wipes n bytes at p and releases the lock taken by lock().
inline void unlock(void* p, std::size_t n) noexcept {
    if (sodium_munlock(p, n) != 0) sodium_memzero(p, n);
}

/// Initialises libsodium once; returns false if the library cannot start.
[[nodiscard]] inline bool ensure_sodium() noexcept {
    static const bool ok = sodium_init() >= 0;
    return ok;
}

/// A fixed-size byte array wiped on destruction and never copied.
template <std::size_t N>
struct SecureArray {
    uint8_t v[N];
    SecureArray() noexcept : v{} {}
    SecureArray(const SecureArray&) = delete;
    SecureArray& operator=(const SecureArray&) = delete;
    ~SecureArray() { wipe(v, N); }
};

/// Constant-time equality of two byte strings. The lengths are compared in
/// the open, which is acceptable only when both lengths are public, as they
/// are for footers, key ids and claim strings whose length the token
/// already reveals.
[[nodiscard]] inline bool ct_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

[[nodiscard]] inline bool ct_equal(std::string_view a, std::string_view b) noexcept {
    return ct_equal({reinterpret_cast<const uint8_t*>(a.data()), a.size()},
                    {reinterpret_cast<const uint8_t*>(b.data()), b.size()});
}

[[nodiscard]] inline std::span<const uint8_t> as_bytes(std::string_view s) noexcept {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

[[nodiscard]] inline bool overlaps(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept {
    if (a.empty() || b.empty()) return false;
    const auto a0 = reinterpret_cast<std::uintptr_t>(a.data());
    const auto b0 = reinterpret_cast<std::uintptr_t>(b.data());
    return a0 < b0 + b.size() && b0 < a0 + a.size();
}

}

}
