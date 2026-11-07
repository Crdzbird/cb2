# cb2_c_bench: cb2 through libcb2_c against JWT (libjwt) and PASETO
# (libpaseto) on the same claims. Built only with -DCB2_C_BENCH=ON; libjwt,
# jansson and libpaseto are dependencies of this program alone, never of
# the library. libjwt and jansson come from pkg-config, libpaseto from a
# source checkout in CB2_C_BENCH_PASETO_SOURCE (bench/run.sh fetches it).
# A competitor that is missing is left out and reported as such.

add_executable(cb2_c_bench cb2_c_bench.c)
target_link_libraries(cb2_c_bench PRIVATE cb2_c)
target_compile_options(cb2_c_bench PRIVATE -O2 -Wall -Wextra)

pkg_check_modules(CB2_C_BENCH_LIBJWT IMPORTED_TARGET libjwt>=3.6)
if(CB2_C_BENCH_LIBJWT_FOUND)
    target_sources(cb2_c_bench PRIVATE bench_jwt.c)
    target_link_libraries(cb2_c_bench PRIVATE PkgConfig::CB2_C_BENCH_LIBJWT)
    target_compile_definitions(cb2_c_bench PRIVATE CB2_C_BENCH_JWT)
    message(STATUS "cb2_c_bench: libjwt ${CB2_C_BENCH_LIBJWT_VERSION}")
endif()

set(CB2_C_BENCH_PASETO_SOURCE "" CACHE PATH "A checkout of the libpaseto fork with v4, for cb2_c_bench")
pkg_check_modules(CB2_C_BENCH_JANSSON IMPORTED_TARGET jansson)
if(CB2_C_BENCH_PASETO_SOURCE AND CB2_C_BENCH_JANSSON_FOUND)
    set(_paseto_src "${CB2_C_BENCH_PASETO_SOURCE}/src")
    add_library(cb2_c_bench_paseto STATIC
        ${_paseto_src}/paseto.c ${_paseto_src}/helpers.c
        ${_paseto_src}/paseto_v2_local.c ${_paseto_src}/paseto_v2_public.c
        ${_paseto_src}/paseto_v4_local.c ${_paseto_src}/paseto_v4_public.c)
    target_include_directories(cb2_c_bench_paseto PUBLIC "${CB2_C_BENCH_PASETO_SOURCE}/include" ${SODIUM_INCLUDE_DIRS})
    target_link_directories(cb2_c_bench_paseto PUBLIC ${SODIUM_LIBRARY_DIRS})
    target_link_libraries(cb2_c_bench_paseto PUBLIC ${SODIUM_LIBRARIES})
    target_compile_options(cb2_c_bench_paseto PRIVATE -O2 -w)
    target_sources(cb2_c_bench PRIVATE bench_paseto.c)
    target_link_libraries(cb2_c_bench PRIVATE cb2_c_bench_paseto PkgConfig::CB2_C_BENCH_JANSSON)
    target_compile_definitions(cb2_c_bench PRIVATE CB2_C_BENCH_PASETO)
    message(STATUS "cb2_c_bench: libpaseto from ${CB2_C_BENCH_PASETO_SOURCE}")
endif()
