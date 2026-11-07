#include <cb2/cb2.hpp>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <random>
#include <string>

static std::string hex(std::mt19937_64& r, int n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; ++i) s += d[r() % 16];
    return s;
}

static cb2::Claims make(std::mt19937_64& r, int64_t now) {
    static const char* auds[] = {"api", "billing", "admin-console", "mobile"};
    static const char* roles[] = {"user", "admin", "viewer", "editor"};
    cb2::Claims c;
    c.iss = "https://auth.example.com";
    c.aud = auds[r() % 4];
    c.sub = "user-" + std::to_string(100000 + r() % 900000);
    c.iat = now - static_cast<int64_t>(r() % 600);
    c.exp = *c.iat + 900;
    c.jti = hex(r, 8) + "-" + hex(r, 4) + "-" + hex(r, 4) + "-" + hex(r, 4) + "-" + hex(r, 12);
    (void)c.set("role", roles[r() % 4]);
    (void)c.set("tenant", "acme-" + std::to_string(r() % 50));
    return c;
}

int main(int argc, char** argv) {
    const int n = argc > 1 ? std::atoi(argv[1]) : 5000;
    std::mt19937_64 r(7);
    const int64_t now = std::time(nullptr);
    auto lk = cb2::LocalKey::generate().value();
    auto sk = cb2::SecretKey::generate().value();
    std::size_t sum_json = 0, sum_local = 0, sum_public = 0;
    for (int i = 0; i < n; ++i) {
        auto c = make(r, now);
        const std::string j = c.to_json();
        std::ofstream(std::string(i < n * 4 / 5 ? "train/" : "test/") + std::to_string(i) + ".json", std::ios::binary) << j;
        sum_json += j.size();
        auto t = cb2::Token::seal(lk, c).value();
        sum_local += t.size();
        if (i < 50) sum_public += cb2::Token::sign(sk, c).value().size();
        if (i == 0) {
            std::printf("claims json (%zu bytes): %s\n", j.size(), j.c_str());
            std::printf("local token (%zu chars): %s\n", t.size(), t.c_str());
            std::printf("local footer (%zu bytes): %s\n", lk.footer().size(), lk.footer().c_str());
            auto p = cb2::Token::sign(sk, c).value();
            std::printf("public token: %zu chars, footer %zu bytes\n", p.size(), sk.footer().size());
        }
    }
    std::printf("avg json %.1f, avg local %.1f, avg public %.1f\n", double(sum_json) / n, double(sum_local) / n, double(sum_public) / 50);
}
