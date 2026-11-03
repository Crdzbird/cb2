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
    std::ifstream file;
    std::istream* in = &std::cin;
    if (argc > 1) {
        file.open(argv[1]);
        if (!file) {
            std::fprintf(stderr, "cannot open %s\n", argv[1]);
            return 2;
        }
        in = &file;
    }
    const bool prompt = argc <= 1 && is_terminal();
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
