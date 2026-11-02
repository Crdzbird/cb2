#pragma once

/**
 * A zero-dependency test runner: cases register themselves at static
 * initialisation, run in registration order, and report PASS or FAIL in
 * plain ASCII. The process exit code is the number of failed cases,
 * capped at 1.
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <vector>

namespace t {

struct Case {
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& cases() {
    static std::vector<Case> v;
    return v;
}

struct Reg {
    Reg(const char* name, void (*fn)()) { cases().push_back({name, fn}); }
};

inline bool current_ok = true;
inline int checks = 0;

inline void fail(const char* expr, const char* file, int line) {
    current_ok = false;
    std::printf("      FAIL %s:%d  %s\n", file, line, expr);
}

inline int run_all(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int total = 0, passed = 0;
    for (const Case& c : cases()) {
        if (filter != nullptr && std::strstr(c.name, filter) == nullptr) continue;
        ++total;
        current_ok = true;
        try {
            c.fn();
        } catch (const std::exception& e) {
            std::printf("      exception: %s\n", e.what());
            current_ok = false;
        }
        std::printf("  %s  %s\n", current_ok ? "PASS" : "FAIL", c.name);
        if (current_ok) ++passed;
    }
    std::printf("\n  %d cases, %d passed, %d failed, %d checks\n", total, passed, total - passed, checks);
    return total == passed ? 0 : 1;
}

}

#define T_CAT2(a, b) a##b
#define T_CAT(a, b) T_CAT2(a, b)
#define TEST_CASE(name)                                                    \
    static void T_CAT(t_case_, __LINE__)();                                 \
    static ::t::Reg T_CAT(t_reg_, __LINE__)(name, &T_CAT(t_case_, __LINE__)); \
    static void T_CAT(t_case_, __LINE__)()

#define CHECK(expr)                                                       \
    do {                                                                  \
        ++::t::checks;                                                    \
        if (!(expr)) ::t::fail(#expr, __FILE__, __LINE__);                \
    } while (0)

#define REQUIRE(expr)                                                     \
    do {                                                                  \
        ++::t::checks;                                                    \
        if (!(expr)) { ::t::fail(#expr, __FILE__, __LINE__); return; }    \
    } while (0)
