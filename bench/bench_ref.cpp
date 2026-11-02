#include "bench_ref.hpp"

#include <cryptolib/paseto.hpp>
#include <cryptolib/cb1_token.hpp>

#include <span>

namespace bench_ref {

namespace {

template <class T>
Impl make(const char* name) {
    Impl i{};
    i.name = name;
    i.token_len = [](std::size_t m, std::size_t f) { return T::token_len(m, f); };
    i.open_capacity = [](std::size_t t) { return T::open_capacity(t); };
    i.seal = [](uint8_t* out, std::size_t cap, std::size_t& n, const uint8_t* key, const uint8_t* msg,
                std::size_t mlen, const uint8_t* f, std::size_t flen, const uint8_t* im, std::size_t ilen) {
        return T::seal({out, cap}, n, {key, 32}, {msg, mlen}, {f, flen}, {im, ilen}) == decltype(T::seal({out, cap}, n, {key, 32}, {msg, mlen}, {f, flen}, {im, ilen}))::ok;
    };
    i.open = [](uint8_t* out, std::size_t cap, std::size_t& n, const uint8_t* tok, std::size_t tlen,
                const uint8_t* key, const uint8_t* f, std::size_t flen, const uint8_t* im, std::size_t ilen) {
        return T::open({out, cap}, n, {tok, tlen}, {key, 32}, {f, flen}, {im, ilen}) == decltype(T::open({out, cap}, n, {tok, tlen}, {key, 32}, {f, flen}, {im, ilen}))::ok;
    };
    return i;
}

}

Impl v4_local() { return make<crypto::paseto::V4Local>("cryptolib v4.local"); }
Impl cb1_local() { return make<crypto::cb1::Local>("cryptolib cb1.local"); }

}
