# Verification record

What was built, run and measured, and when, newest first. The README
summarises it; this file keeps the detail. Everything ran on one Apple
silicon Mac (M3 Max) unless an entry says otherwise.

## 2026-11-07, the Python bridge as a package

`bindings/python` is now a src-layout package built with
scikit-build-core: `bindings/python/CMakeLists.txt` includes the root
CMakeLists.txt, builds the `cb2_c` target of bindings/c and installs it
unversioned inside the `cb2` package, so the wheel
(`py3-none-<platform>`) carries the library. The loader takes
`CB2_C_LIBRARY` alone when it is set, else the bundled copy, else
`find_library`, and refuses a library whose `cb2_abi_version` is not 0.
The package is typed (`py.typed`), the unittest cases became 41 pytest
cases with every earlier assertion kept, and examples/token_service.py
is an http.server token service with a client that checks each answer.

`python -m build --wheel` built cb2-0.1.0-py3-none-macosx_26_0_arm64.whl
in 5 s; `delocate-wheel` copied libsodium, libblake3 and libcrypto into
it (liboqs is linked statically, and only the 61 `cb2_` functions are
exported). scripts/check_wheel.sh installed it under Python 3.12 into a
fresh virtual environment in a temporary directory outside the
repository: `cb2.library_path()` was the copy in site-packages, 41 tests
passed, `mypy --strict` found no issues in the tests and the example,
and the example's nine steps (cb2.local open, a tampered token refused
as `invalid`, cb2.public verify and a foreign signature refused, a bound
token refused as `missing_proof`, accepted with its holder proof,
refused as `proof_replayed` and `proof_mismatch`) all behaved as
expected. Against a libcb2_c built with `-DCB2_PQ=OFF` through
`CB2_C_LIBRARY`, 35 passed and 6 were skipped, and the example used a
kcb2.local proof key instead. `pip install -e` resolves the library from
site-packages while the sources stay in place. In the source tree `ruff
check`, `ruff format --check` and `mypy` (strict, over src, tests and
the example) are clean. CI now builds the wheel on macOS and Linux,
repairs it with delocate-wheel and auditwheel, and runs the same script.

## 2026-11-07, the Go binding as a module library

`bindings/go` is the module `github.com/Crdzbird/cb2/bindings/go`, with a
package `doc.go`, godoc on every exported identifier, runnable `Example`
functions, and two example programs: a net/http service that issues a
cb2.local access token bound to a proof key on login and accepts it only
with a holder proof for the exact request, and a CLI that makes those
proofs. Key handles are reference counted: `Close` is idempotent and lets
calls in flight finish, `SetKeyID` waits for them, and a call on a closed
key returns `ErrClosed`, which also matches `ErrArgument`. A test runs
seals, opens, wraps, key id changes and `Close` on one key from 17
goroutines under the race detector.

`go build ./...`, `go vet ./...`, staticcheck 2026.2.2 and golangci-lint
2.13.2 report nothing; `go test -race ./...` passes with Go 1.27.1,
including the 10 examples with checked output (an eleventh, for
cb2.public signing, is compiled but not run, since cb2.public is
optional in the library) and the service tests under `httptest`. The service binaries were run and driven with curl: a bound
request answered 200; the same request again, a proof for another
target, a proof for another method, a request without a proof, a token
with one character changed and, on an instance with a one-second token
lifetime, a request after the 5 second skew allowance were refused with
401 and `proof_replayed`, `proof_mismatch`, `proof_mismatch`,
`missing_proof`, `invalid` and `expired`. The first attempt at the expiry
case waited only 3 seconds and was accepted, which is the skew allowance
working as configured. Outside the repository, a copy of the module
linked and passed its tests under the race detector through the new
`cb2_pkgconfig` build tag and the `cb2_c.pc` that `cmake --install`
writes, and through `CGO_CFLAGS` and `CGO_LDFLAGS`; CI runs the tag
against a fresh install on macOS and Linux.

## 2026-11-07, the C ABI as an installable library

`bindings/c` installs as a C library: the header, `libcb2_c` shared
(SOVERSION 0) and static, a CMake package with the targets
`cb2_c::cb2_c` and `cb2_c::cb2_c_static`, and `cb2_c.pc`. Before the
change the shared library exported 1,364 symbols, 1,304 of them from the
statically linked liboqs; it now exports the 61 `cb2_` functions (the 60
of before and `cb2_abi_version`) and nothing else (an export list on
macOS, a version script on Linux). The header gained
`CB2_C_VERSION_MAJOR`, `_MINOR`, `_PATCH`, `CB2_C_ABI_VERSION` and
`cb2_abi_version`, and states the ownership,
lifetime, thread and ABI rules; every existing declaration is unchanged.
The ABI now refuses a NULL handle or output pointer with `CB2_ARGUMENT`
instead of dereferencing it, and the functions returning a pointer catch
exceptions like the rest. `cb2_c_test` gained a boundary case and passes
in the release, ASan and UBSan, and no-liboqs builds; the new example
`cb2_c_example` passes in all three, and `bindings/c/examples/install_check.sh`
built and ran it against an installed prefix through `find_package` with
the shared and the static library and through pkg-config, for the
release and the no-liboqs builds. Against this build the other bridges
pass: Swift 10 XCTest cases, Python 26 unittest cases, Node 9 tests, Go
`go test` and `go vet`, Java and Kotlin through `bindings/java/build.sh`,
Dart 14 tests. The export list parsed from the header by
`bindings/js/build.sh` equals the library's exports, and `cb2_c.cpp`
still compiles under em++ with the flags of that script.

## 2026-11-06, ASCII fast path in the claims layer

The identifier and UTF-8 checks skip a leading run of printable ASCII
in blocks of 16 bytes, and the JSON reader and writer copy runs of
plain ASCII in one step. Against the code before the change, on 10
million random strings mixing ASCII, multi-byte UTF-8, controls,
invisible and bidi characters, escapes, surrogate pairs and invalid
bytes, the text checks, the JSON reader and the JSON writer gave the
same verdict and the same output every time. Two new test cases put a
refused or escaped character at every offset of a 70-byte ASCII run;
with the fast path deliberately broken to let 0x7F through they fail,
and restored they pass. The release build passes 100 of 100 cases, the
ASan and UBSan build 100 of 100, the build without liboqs 75 of 75,
tools/check_vectors.py 638 checks, the C, Python, Go and JavaScript
bridges, the six playground demos and the web smoke test; `fuzz_claims`
ran 6,753,301 inputs in 121 s with no report.

Measured on the same machine against the previous commit: `Claims::from_json`
of a 2.7 KB payload carrying a kcb2.public key in cnf went from 19.8 to
2.9 us and its text check from 11.3 to 0.2 us; opening that bound token
before its proof from 29.1 to 11.9 us; the whole bound request from
171.5 to 154.5 us; `Token::open` of a typical 391-character token from
3.35 to 2.84 us. In `cb2_bench`, run alternately with the previous
commit's build, the bearer check went from 3.2 to 2.7 us and the local
holder request from 8.5 to 6.7 to 7.3 us.

## 2026-11-06, holder target normalisation fixed

`fuzz_holder` had found that holder target normalisation was not
idempotent: it split host and port at the last colon, so
`https://h:1:443/x` and `https://h:1/x` normalised to the same target.
docs/PROTOCOL.md 13.2 now refuses a host that holds a colon or a bracket
outside one bracketed IP literal, and the library, the vectors and
tools/check_vectors.py follow it. The release build passes 98 of 98
cases, the ASan and UBSan build 98 of 98, the build without liboqs 73 of
73, tools/check_vectors.py 638 checks with none failed or skipped, and
the C, Python, Go and JavaScript bridges their tests. `fuzz_holder`
checks idempotence on every input again: 121,381 runs in five minutes
from seeds of exactly that shape, no report.

## 2026-11-06, fuzz targets and the constant-time probe

On the tree with the local holder mode and the unrolled Keccak. The
three new fuzz targets ran 181 s each from an empty corpus with no
crash, leak or timeout: `fuzz_seal` 576,181 runs, `fuzz_sha3` 1,277,837
runs (every SHA3-256 and SHAKE256 output equal to OpenSSL's),
`fuzz_holder` 77,092 runs over both holder modes. The constant-time
probe ran in the `linux` CI job (Ubuntu 24.04, x86-64, Valgrind 3.22.0,
gcc, RelWithDebInfo): 0 errors. Its first run reported 43
secret-dependent addresses from 7 places and no secret-dependent branch;
all 7 are the base64url alphabet lookup on a secret key's PASERK text,
now the one suppression, and nothing else in Keccak, cb2.local, Ed25519
signing, verification, X-Wing or ML-KEM decapsulation was reported.

## 2026-11-06, the local holder mode

The release build passes 97 of 97 cases, the ASan and UBSan build 97 of
97, the build without liboqs 72 of 72 (the local mode included), the C
ABI test in all three, the six playground demos, the web module's smoke
test, the Python, Go, JavaScript, Java, Kotlin, Swift and Dart binding
tests, and tools/check_vectors.py with 629 checks and none skipped.

## 2026-11-06, cb2's own SHA3

After cb2 took over SHA3 from liboqs: the release build passes 87 of 87
cases (about 25,600 checks), the ASan and UBSan build 87 of 87 with no
reports, and the build without liboqs 63 of 63. The release build also
links and passes against a shared liboqs 0.16.0 built as Homebrew builds
it, which the tree before that change could not. With the round loops
unrolled, seal, unseal and recipient key import measure within noise of
the tree that used liboqs's SHA3 (about 79, 67 and 35 us), and one
SHA3-256 call costs 0.40 us against liboqs's 0.40 us.

## 2026-11-03, the first full run

The case counts below are those of that day.

All on an Apple silicon Mac on 2026-11-03, from the tree as committed.

- Release build (`cmake -S . -B build -G Ninja`, Apple
  clang 21, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow`): zero warnings. `cb2_tests`: 59 cases, 59 passed,
  about 24,600 checks (the exact count varies with the random lengths in
  the codec agreement test).
- The same with `-DCB2_SANITIZE=ON` (AddressSanitizer + UBSan, no
  recovery): 59 of 59, no reports. The sanitizer build caught one bug
  during development, an iterator pair taken from two temporaries in
  the vector generator, which is fixed; the library itself produced no
  report at any point.
- `-DCB2_PQ=OFF` (no liboqs): builds, 47 of 47 cases, cb2.public
  absent as specified.
- `cb2_example_text`: zero warnings, all eight scenarios hold their
  expectations in the release, the sanitizer and the no-liboqs builds.
- Known-answer vectors under `tests/vectors`: 11 cb2.local success
  vectors reproduced byte for byte and 15 failure vectors rejected, 99
  single-character tamper cases of a 99-character token all rejected;
  6 cb2.public success vectors verified and 14 failure vectors rejected,
  38 sampled tamper cases rejected and every byte of a 4512-character
  token swept live; 40 claims-layer vectors with the recorded verdicts
  (among them incomplete rules, replayed and missing token ids); 3 weak
  local keys and 5 corrupted secret keys refused on import;
  the PASERK vectors reproduced.
- Official PASETO v4 vectors (`tests/vectors/paseto/v4.json` in the
  repository): all 9 v4.local tokens reproduced byte for byte and all
  3 v4.public tokens reproduced and verified through cb2's own PAE,
  base64url, token splitting and footer comparison, and the 5 failure
  vectors rejected. This validates the two building blocks cb2
  shares with v4.
- libFuzzer (`/opt/homebrew/opt/llvm/bin/clang++`, `-fsanitize=fuzzer,
  address,undefined`): `fuzz_local` 146,067 runs in 131 s, `fuzz_public`
  143,169 runs in 131 s, `fuzz_claims` 10,489,676 runs in 121 s; no
  crash, leak or timeout. A one-minute confirmation campaign per target
  was run again from the saved corpora after the last header edit.
- Benchmark: the table above, two runs.


## Not verified on this Mac

Behaviour on Windows, the constant-time property under a dynamic probe
(Valgrind is not available here; the probe runs in the `linux` CI job),
and any review by a second person.
