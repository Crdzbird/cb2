/**
 * cb2 playground: a line-oriented session with the library.
 *
 * Generate and import keys, seal and open cb2.local tokens, sign and
 * verify cb2.public tokens, build claims and check them under rules,
 * wrap keys, peek at a token's footer, tamper with a token and watch the
 * verdict change. Every command prints what it did as "name = value"
 * lines; verdicts print as "verdict = ok" or "verdict = <error name>".
 *
 * Interactive: ./build/cb2_playground
 * Scripted:    ./build/cb2_playground playground/demo.cb2
 *
 * --fast-random, given first, selects libsodium's own userspace random
 * generator for the nonces instead of the kernel's: the opt-in that
 * README.md describes, chosen here before anything else runs because
 * libsodium takes the choice only once, before its initialisation. The
 * time command reports which source is in use.
 *
 * A script is the same commands, one per line, with # comments; "assert
 * <verdict>" checks the last verdict and the process exits non-zero if any
 * assert fails or a command is malformed, so a script doubles as a test.
 * The interpreter itself is session.hpp, which the web playground shares.
 */

#include "session.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace {

bool is_terminal() {
#if defined(__unix__) || defined(__APPLE__)
    return isatty(0) != 0;
#else
    return false;
#endif
}

}

int main(int argc, char** argv) {
    int first = 1;
    if (argc > 1 && std::string(argv[1]) == "--fast-random") {
        if (randombytes_set_implementation(&randombytes_internal_implementation) != 0) {
            std::fputs("cannot select libsodium's internal random generator\n", stderr);
            return 2;
        }
        first = 2;
    }
    if (sodium_init() < 0) {
        std::fputs("libsodium failed to initialise\n", stderr);
        return 2;
    }
    std::ifstream file;
    std::istream* in = &std::cin;
    if (argc > first) {
        file.open(argv[first]);
        if (!file) {
            std::fprintf(stderr, "cannot open %s\n", argv[first]);
            return 2;
        }
        in = &file;
    }
    const bool prompt = argc <= first && is_terminal();
    cb2_playground::Session s;
    if (prompt) std::puts("cb2 playground; help lists the commands, quit leaves");
    std::string text;
    while (true) {
        if (prompt) {
            std::fputs("cb2> ", stdout);
            std::fflush(stdout);
        }
        if (!std::getline(*in, text)) break;
        if (text == "quit" || text == "exit") break;
        if (!prompt) std::printf("> %s\n", text.c_str());
        cb2_playground::run(s, text);
        std::fputs(s.out.c_str(), stdout);
        s.out.clear();
    }
    if (s.failures > 0) {
        std::printf("%d failure(s)\n", s.failures);
        return 1;
    }
    return 0;
}
