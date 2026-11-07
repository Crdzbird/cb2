# cb2 for C

`libcb2_c` is cb2 behind a plain C ABI: opaque key handles, malloc'd
results, integer verdicts with stable names, claims and rules as JSON
text, and replay checks as callbacks. It is the one surface every other
language bridge in this repository sits on, and it is a library of its
own: a shared and a static build, a header, a CMake package and a
pkg-config file.

    include/cb2_c.h        the whole surface, with the ownership rules
    src/cb2_c.cpp          the ABI over the header-only C++ library
    test/test_c.c          every call and every verdict, from C
    examples/              a small CLI, built in-tree and against an install, and install_check.sh
    cmake/                 the export list, the package and pkg-config templates

## Build

The C library is part of the root build (`-DCB2_BUILD_BINDINGS=ON`, the
default). It needs what cb2 needs: libsodium, BLAKE3, libcrypto, and
liboqs unless you configure with `-DCB2_PQ=OFF`, which leaves out
cb2.public, kcb2.seal and public holder proofs.

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target cb2_c cb2_c_static cb2_c_test cb2_c_example
    ./build/bindings/c/cb2_c_test
    ./build/bindings/c/cb2_c_example

The shared library lands in `build/bindings/c` as `libcb2_c.dylib` or
`libcb2_c.so`, where the other bridges look for it, and the static one
next to it as `libcb2_c.a`.

## Install

    cmake --install build --prefix /usr/local

installs, under the prefix:

    include/cb2_c.h
    lib/libcb2_c.0.1.0.dylib, libcb2_c.0.dylib, libcb2_c.dylib   (libcb2_c.so.0.1.0, .so.0, .so on Linux)
    lib/libcb2_c.a
    lib/cmake/cb2_c/                 cb2_cConfig.cmake and the exported targets
    lib/pkgconfig/cb2_c.pc

along with the C++ headers under `include/cb2`. Both the CMake package
and the pkg-config file locate the prefix from where they are installed,
so a tree installed with `--prefix` and moved elsewhere still works.

## Use it from CMake

    find_package(cb2_c 0.1 REQUIRED)
    target_link_libraries(app PRIVATE cb2_c::cb2_c)

`cb2_c::cb2_c` is the shared library and `cb2_c::cb2_c_static` the
static one. Point CMake at a non-standard prefix with
`-DCMAKE_PREFIX_PATH=<prefix>`. After `find_package`, `cb2_c_HAS_PUBLIC`
says whether the installed library was built with cb2.public; at run
time `cb2_has_public` and `cb2_has_seal` say the same.

## Use it with pkg-config

    cc app.c $(pkg-config --cflags --libs cb2_c) -Wl,-rpath,$(pkg-config --variable=libdir cb2_c)

Set `PKG_CONFIG_PATH=<prefix>/lib/pkgconfig` for a non-standard prefix.
The dependencies are listed in `Requires.private`, so their `.pc` files
must be findable too; `pkg-config --static --libs cb2_c` adds them and
the C++ runtime for a static link.

On macOS the install name of the library is `@rpath/libcb2_c.0.dylib`,
so a program needs an rpath to the library directory, as above. CMake
adds it by itself for a program linked through `find_package`.

## Static linking

The static library is C++ inside, so a C program linking it also needs
the C++ runtime and cb2's dependencies. `cb2_c::cb2_c_static` carries
both, and so does `pkg-config --static`. The CMake package records the
dependency libraries by the paths they had when cb2 was built, which
suits a library installed on the machine that built it; a package
manager that moves the dependencies should rebuild cb2_c. On Windows,
define `CB2_C_STATIC` when compiling against the static library (the
CMake target does it).

## The example

`examples/cb2_c_example.c` issues and opens a cb2.local token, signs and
verifies a cb2.public token, shows three refusals (a wrong audience, a
token that expired, a changed byte), and binds an access token to a
proof key, proves possession for one request, and replays the proof:

    $ cb2_c_example
    cb2_c 0.1.0 (ABI 0), cb2.public yes
    local   issued  cb2.local.wPiEjM-QLgYN6shGntScBTs3C3UcJD... (346 bytes)
    local   opened  {"iss":"https://issuer.example","sub":"user-1","aud":"api",...}
    public  signed  cb2.public.eyJpc3MiOiJodHRwczovL2lzc3Vlc... (4759 bytes)
    public  opened  {"iss":"https://issuer.example","sub":"user-1","aud":"api",...}
    refuse  wrong audience   audience_mismatch
    refuse  in the year 2100 expired
    refuse  one byte changed invalid
    holder  proof   cb2.holder-local.-dYiHz4knZJICKweaBYXGy-... (362 bytes)
    holder  token without a proof  missing_proof
    holder  token with the proof   ok
    holder  the same proof again   proof_replayed
    every step behaved as expected

`cb2_c_example local`, `public`, `refuse` or `holder` runs one step. The
same source builds three ways: in-tree as above, against an install with
CMake,

    cmake -S bindings/c/examples -B build-example -DCMAKE_PREFIX_PATH=<prefix>
    cmake --build build-example
    ./build-example/cb2_c_example

(`-DCB2_C_EXAMPLE_STATIC=ON` links the static library), and against an
install with pkg-config:

    PKG_CONFIG_PATH=<prefix>/lib/pkgconfig make -C bindings/c/examples
    ./bindings/c/examples/cb2_c_example

`examples/install_check.sh build` does all of that in one go: it
installs a configured build into a temporary prefix, builds and runs the
example against it with the shared library, the static library and
pkg-config, and checks that the installed shared library exports nothing
but `cb2_` functions. CI runs it on macOS and Linux.

## Ownership and lifetime

The header states these rules once at the top and per group of
functions; in short:

- Inputs are borrowed for the call only. The library keeps no pointer to
  an argument after it returns. Text inputs carry explicit lengths and
  need no NUL; an input pointer may be NULL when its length is 0.
- A handle belongs to the caller from the moment a constructor writes it
  until the caller passes it to the matching free function, once. Handles
  are independent of each other: a public key taken from a signing pair
  outlives the pair if the caller keeps it.
- Every returned `char*` or `uint8_t*` is a fresh malloc'd block for the
  caller, released with `cb2_free`. The three texts that carry key
  material (from the `to_paserk` functions of local keys, signing pairs
  and recipient pairs) are released with `cb2_free_secret`, which wipes
  them first.
- Outputs are written only on success. A failed call leaves the output
  pointer as it was.
- Text results are NUL-terminated; a reported length excludes the NUL.
  An opened raw message is followed by one 0 byte the length does not
  count.
- A NULL handle or NULL output pointer is refused with `CB2_ARGUMENT`
  (or NULL from the functions that return a pointer), and every free
  function accepts NULL.
- The static strings from `cb2_version` and `cb2_error_name` are never
  freed.

## Errors

Every fallible function returns `CB2_OK` (0) or a positive `cb2_code`.
`cb2_error_name` gives the stable name (`invalid`, `expired`,
`proof_replayed`, ...), the same names the protocol document and every
other bridge use. A token that fails authentication is `invalid`
whatever the cause, so the code never tells an attacker which check
failed. No C++ exception crosses the boundary: anything unexpected is
`CB2_INTERNAL`, or NULL from a function that returns a pointer.

## Threads

The library holds no mutable state of its own beyond a one-time
initialisation of libsodium, and every function is reentrant. A handle
may be shared between threads for every function that takes it as
`const`; `set_key_id`, `clear_key_id` and the free functions change the
handle and need exclusive access. Replay callbacks run on the calling
thread during the call that triggers them.

## ABI stability and versioning

The header carries `CB2_C_VERSION_MAJOR`, `CB2_C_VERSION_MINOR`,
`CB2_C_VERSION_PATCH` and `CB2_C_ABI_VERSION`; the build reads them from
the header and refuses to configure when they disagree with the project
version, and the library refuses to compile when they disagree with
`cb2::VERSION`. `CB2_C_ABI_VERSION` is the shared library's SOVERSION.
Within one ABI version the surface only grows: functions and error codes
are added, never removed or changed, and no ownership rule changes. A
program can compare `cb2_abi_version()` with the `CB2_C_ABI_VERSION` it
was compiled against to catch a mismatched library at run time, as the
example does.

The shared library exports the `cb2_` functions and nothing else: the
sources build with hidden visibility, and the link uses an export list on
macOS (`cmake/cb2_c.exports`) and a version script on Linux
(`cmake/cb2_c.map`), so the statically linked parts of liboqs stay
private. Each of these prints nothing, the first on macOS, the second
on Linux:

    nm -gU build/bindings/c/libcb2_c.dylib | grep -v ' _cb2_'
    nm -D --defined-only build/bindings/c/libcb2_c.so | grep -v ' cb2_'
