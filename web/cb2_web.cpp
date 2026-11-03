/**
 * The browser entry of the cb2 playground. One session lives for the
 * page; cb2_web_run executes one command line through the same
 * interpreter as the command-line playground (playground/session.hpp)
 * and returns its output. Built by web/build.sh with Emscripten.
 */

#include "../playground/session.hpp"

#include <emscripten/emscripten.h>

#include <string>

namespace {

cb2_playground::Session& session() {
    static cb2_playground::Session s;
    return s;
}

std::string reply;

}

extern "C" {

EMSCRIPTEN_KEEPALIVE const char* cb2_web_run(const char* text) {
    cb2_playground::Session& s = session();
    s.out.clear();
    cb2_playground::run(s, std::string(text == nullptr ? "" : text));
    reply = s.out;
    return reply.c_str();
}

EMSCRIPTEN_KEEPALIVE void cb2_web_reset() {
    session() = cb2_playground::Session{};
}

EMSCRIPTEN_KEEPALIVE int cb2_web_failures() {
    return session().failures;
}

EMSCRIPTEN_KEEPALIVE int cb2_web_has_pq() {
#ifdef CB2_HAS_PQ
    return 1;
#else
    return 0;
#endif
}

}
