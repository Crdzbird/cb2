#include "test_runner.hpp"

#include <sodium.h>

int main(int argc, char** argv) {
    if (sodium_init() < 0) return 2;
    return t::run_all(argc, argv);
}
