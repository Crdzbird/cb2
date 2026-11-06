# Verification record

What was built, run and measured, and when, newest first. The README
summarises it; this file keeps the detail. Everything ran on one Apple
silicon Mac (M3 Max) unless an entry says otherwise.

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
