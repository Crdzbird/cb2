/**
 * The browser entry of the cb2 playground. One session lives for the
 * page; cb2_web_run executes one command line through the same
 * interpreter as the command-line playground (playground/session.hpp)
 * and returns its output. cb2_web_load_setup and cb2_web_load_batch run
 * the heavy load card (web/load.hpp), apart from the session. Built by
 * web/build.sh with Emscripten.
 */

#include "../playground/session.hpp"
#include "load.hpp"

#include <emscripten/emscripten.h>

#include <string>

namespace {

cb2_playground::Session& session() {
    static cb2_playground::Session s;
    return s;
}

std::string reply;
std::string load_reply;

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

EMSCRIPTEN_KEEPALIVE const char* cb2_web_load_setup(const char* kind) {
    load_reply = cb2_load::setup(kind == nullptr ? "" : kind, emscripten_get_now);
    return load_reply.c_str();
}

EMSCRIPTEN_KEEPALIVE const char* cb2_web_load_batch(int n, int attack_every) {
    load_reply = cb2_load::batch(n, attack_every, emscripten_get_now);
    return load_reply.c_str();
}

EMSCRIPTEN_KEEPALIVE int cb2_web_has_pq() {
#ifdef CB2_HAS_PQ
    return 1;
#else
    return 0;
#endif
}

}
