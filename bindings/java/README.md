# cb2 for Java and Kotlin

cb2 is a format for security tokens, the strings a server hands out
after a login and later accepts as proof of who is calling. It does the
job of JWT and PASETO with the claim checks built in, a post-quantum
signature next to Ed25519, and tokens that can be tied to the client
they were issued to. This directory holds the JVM libraries; the format,
its design and its security claims are described in the
[root README](../../README.md), [docs/SPEC.md](../../docs/SPEC.md) and
[docs/SECURITY.md](../../docs/SECURITY.md).

Two libraries, both version 0.1.0:

| artifact | JPMS module | what it is |
|---|---|---|
| `com.cipherbird:cb2` | `com.cipherbird.cb2` | the Java API, the JNI glue, and the native library for the platform it was built on |
| `com.cipherbird:cb2-kotlin` | `com.cipherbird.cb2.kotlin` | a rules DSL, a claims builder, extension functions and verdict helpers for Kotlin; depends on `cb2` |

The Java library needs nothing beyond the JDK, version 17 or later. The
Kotlin library adds kotlin-stdlib.

## Adding the dependency

The artifacts are not published to a public repository. Build them
(see [Building](#building), at the end) and install them into your local
Maven repository:

    ./gradlew publishToMavenLocal

Then, in Gradle:

    repositories {
        mavenLocal()
        mavenCentral()
    }

    dependencies {
        implementation("com.cipherbird:cb2:0.1.0")
        implementation("com.cipherbird:cb2-kotlin:0.1.0")
    }

or in Maven:

    <dependency>
        <groupId>com.cipherbird</groupId>
        <artifactId>cb2</artifactId>
        <version>0.1.0</version>
    </dependency>

Leave out `cb2-kotlin` in a Java project. In a modular application add
`requires com.cipherbird.cb2;` to your module-info.

## Quick start in Java

This is `examples/token-service/src/main/java/com/cipherbird/cb2/example/service/QuickStart.java`;
`./gradlew :examples:token-service:quickStart` runs it.

    import com.cipherbird.cb2.Cb2;
    import com.cipherbird.cb2.Cb2Exception;
    import com.cipherbird.cb2.LocalKey;
    import com.cipherbird.cb2.PublicKey;
    import com.cipherbird.cb2.Rules;
    import com.cipherbird.cb2.SecretKey;
    import com.cipherbird.cb2.Token;
    import java.util.Set;
    import java.util.concurrent.ConcurrentHashMap;

    public final class QuickStart {
        public static void main(String[] args) {
            String claims = "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"sub\":\"user-1\","
                    + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\"}";
            Set<String> seen = ConcurrentHashMap.newKeySet();
            Rules rules = new Rules()
                    .issuer("https://issuer.example")
                    .audience("api")
                    .replay(seen::add);

            try (LocalKey key = LocalKey.generate()) {
                String token = Token.seal(key, claims);
                System.out.println("cb2.local token: " + token.length() + " chars");
                System.out.println("opened:          " + Token.open(key, token, rules));
                try {
                    Token.open(key, token, rules);
                } catch (Cb2Exception e) {
                    System.out.println("opened again:    refused, " + e.name());
                }
            }

            if (Cb2.hasPublic()) {
                try (SecretKey signer = SecretKey.generate(); PublicKey verifier = signer.publicKey()) {
                    String token = Token.sign(signer, claims);
                    Rules check = new Rules().issuer("https://issuer.example").audience("api");
                    System.out.println("cb2.public token: " + token.length() + " chars");
                    System.out.println("verified:         " + Token.verify(verifier, token, check));
                }
            }
        }
    }

It prints:

    cb2.local token: 322 chars
    opened:          {"iss":"https://issuer.example","sub":"user-1","aud":"api","exp":"2099-01-01T00:00:00+00:00","jti":"id-1"}
    opened again:    refused, replayed
    cb2.public token: 4735 chars
    verified:         {"iss":"https://issuer.example","sub":"user-1","aud":"api","exp":"2099-01-01T00:00:00+00:00","jti":"id-1"}

## Quick start in Kotlin

This is `examples/token-tour/src/main/kotlin/com/cipherbird/cb2/example/tour/QuickStart.kt`;
`./gradlew :examples:token-tour:quickStart` runs it.

    import com.cipherbird.cb2.Cb2
    import com.cipherbird.cb2.LocalKey
    import com.cipherbird.cb2.SecretKey
    import com.cipherbird.cb2.kotlin.claims
    import com.cipherbird.cb2.kotlin.openClaims
    import com.cipherbird.cb2.kotlin.rememberingCheck
    import com.cipherbird.cb2.kotlin.sealClaims
    import com.cipherbird.cb2.kotlin.signClaims
    import com.cipherbird.cb2.kotlin.verdictOf
    import com.cipherbird.cb2.kotlin.verifyClaims
    import java.time.Instant

    fun main() {
        val claims = claims(
            "iss" to "https://issuer.example",
            "aud" to "api",
            "sub" to "user-1",
            "exp" to Instant.now().plusSeconds(3600),
            "jti" to "id-1",
        )
        val seen = rememberingCheck()

        LocalKey.generate().use { key ->
            val token = key.sealClaims(claims)
            println("cb2.local token: ${token.length} chars")
            println("opened:          " + key.openClaims(token) { issuer("https://issuer.example"); audience("api"); replay(seen) })
            val again = verdictOf { key.openClaims(token) { issuer("https://issuer.example"); audience("api"); replay(seen) } }
            println("opened again:    refused, $again")
        }

        if (Cb2.hasPublic()) {
            SecretKey.generate().use { signer ->
                signer.publicKey().use { verifier ->
                    val token = signer.signClaims(claims)
                    println("cb2.public token: ${token.length} chars")
                    println("verified:         " + verifier.verifyClaims(token) { issuer("https://issuer.example"); audience("api") })
                }
            }
        }
    }

It prints (exp is an hour from the run):

    cb2.local token: 322 chars
    opened:          {"iss":"https://issuer.example","sub":"user-1","aud":"api","exp":"2026-11-07T13:16:53+00:00","jti":"id-1"}
    opened again:    refused, replayed
    cb2.public token: 4735 chars
    verified:         {"iss":"https://issuer.example","sub":"user-1","aud":"api","exp":"2026-11-07T13:16:53+00:00","jti":"id-1"}

## Token kinds and when to use each

| kind | use it for | keys in this library |
|---|---|---|
| `cb2.local` | sessions and calls between your own services: one secret key shared by issuer and verifier, the claims encrypted so nobody else can read them | `LocalKey` |
| `cb2.public` | tokens many parties verify but only you issue: signed with Ed25519 and ML-DSA-65 together, the claims readable | `SecretKey` to sign, `PublicKey` to verify |
| `cb2.holder-local`, `cb2.holder-public` | a proof the client makes for each request, so a stolen access token is useless alone; the issuer names the client's key in the token's `cnf` claim | the `LocalKey` proof key from `cnf`, or the client's `SecretKey` |
| `cb3.local`, `cb3.public` | experimental compact forms of the two above, about half the size of a cb2.local token; see [Compact tokens](#compact-tokens-experimental) | the same keys, through `Compact` |
| `kcb2.local-wrap` | storing a local key encrypted under another local key | `LocalKey`, through `KeyWrap` |
| `kcb2.seal` | sending a local key to a recipient, safe against a future quantum computer (X-Wing) | `RecipientKey`, `RecipientPublicKey`, through `Seal` |

Pick `cb2.local` when the same party issues and checks the token; it is
small and fast. Pick `cb2.public` when other parties must check tokens
they cannot mint; it is large (about 4,800 characters) because of the
post-quantum signature. Add holder proofs when a leaked token must not
be enough to call your API.

## API overview

All classes are in `com.cipherbird.cb2`:

| class | what it does |
|---|---|
| `Token` | claims tokens: `seal` and `open` for cb2.local, `sign` and `verify` for cb2.public, `peekKeyId` to pick a key before checking |
| `Compact` | compact claims tokens, cb3.local and cb3.public: `seal`, `open`, `sign`, `verify` as in `Token`, each also with a `ClaimTable`; `peekKeyDigest` and `keyDigest` to pick a key |
| `ClaimTable` | a claim table for compact tokens: `of` a list of entries, `entries`, `digest`, `close` |
| `Rules` | what a token is checked against: issuer, audience, subject, clock and skew, lifetime and size limits, the replay checks, the holder proof and the request it must match |
| `ReplayCheck` | `boolean accept(String jti)`, called with each token id (or proof id); return false for one you have seen |
| `Local`, `Public` | raw tokens of any bytes, with an optional footer and implicit assertion |
| `Holder` | `prove` (client signing pair) and `proveLocal` (local proof key) for one request; `normalizeTarget` |
| `LocalKey`, `SecretKey`, `PublicKey`, `RecipientKey`, `RecipientPublicKey` | the keys: `generate`, `fromBytes`, `fromPaserk`, `toPaserk`, `paserkId`, `keyId` and `setKeyId` |
| `KeyWrap`, `Seal` | wrap a local key under another, or seal it to a recipient |
| `Cb2` | `version`, `hasPublic`, `hasSeal`, `errorName`, `load` |
| `Cb2Exception`, `Code` | a refusal and its code |
| `Json` | JSON string quoting, for claims built by hand |

Claims go in and come out as JSON text: an object with the registered
claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `cnf`, times as
RFC 3339 strings such as `2099-01-01T00:00:00+00:00`) and any claims of
your own. `open` and `verify` refuse a token whose rules are incomplete:
name the expected issuer and audience, or allow any explicitly.

The Kotlin library, in `com.cipherbird.cb2.kotlin`, adds:

| function | what it does |
|---|---|
| `rules { issuer("..."); audience("...") }` | builds a `Rules` |
| `claims("iss" to "...", "exp" to Instant.now())`, `Map.toClaimsJson()` | claims JSON from pairs or a map; `Instant` and `OffsetDateTime` become RFC 3339 |
| `LocalKey.sealClaims`, `openClaims`, `seal`, `open`, `prove`, `wrapWith`, `sealTo` | extensions on the local key |
| `SecretKey.signClaims`, `sign`, `prove`; `PublicKey.verifyClaims`, `verify` | extensions on the signing keys |
| `LocalKey.sealCompact`, `openCompact`; `SecretKey.signCompact`; `PublicKey.verifyCompact` | compact claims tokens, in the style of `sealClaims` and the rest |
| `claimTable("...", "...")`, `Iterable<String>.toClaimTable()`; `sealCompact(table, ...)`, `openCompact(table, ...)`, `signCompact(table, ...)`, `verifyCompact(table, ...)` | claim tables and the compact extensions under one |
| `String.peekCompactKeyDigest()`, `LocalKey.compactKeyDigest` (and on `SecretKey`, `PublicKey`) | the digest a compact token carries, and the one a key's id gives |
| `Rules.onReplay { }`, `onProofReplay { }`, `rememberingCheck()` | replay checks as lambdas, or backed by a concurrent set |
| `verdictOf { }`, `cb2OrNull { }`, `Cb2Exception.verdict` | a refusal as its verdict name, or as null |

Holder proofs, in short: the issuer puts the client's key in `cnf`, the
client calls `Holder.prove` (or `proveLocal`) for each request, and the
server opens the token with `Rules.proof(proof)`,
`Rules.request(method, url)` and a proof replay check. The
token-service example below does all of it over HTTP.

## Compact tokens (experimental)

`Compact` issues and checks the compact formats `cb3.local` and
`cb3.public` of [docs/PROTOCOL.md](../../docs/PROTOCOL.md) section 15.
The cryptography is the one of cb2.local and cb2.public, and so are the
claims JSON, the `Rules`, the replay checks, the holder proofs and the
verdicts; what changes is the encoding. The claims travel as strict
canonical CBOR and the footer carries a 16-byte digest of the key id
(`Compact.KEY_DIGEST_BYTES`) instead of the id itself. For the claims of
the benchmarks below a cb3.local token is 224 bytes against 430 for
cb2.local, and a cb3.public token 4637 against 4843.

    String token = Compact.seal(key, claims);
    String opened = Compact.open(key, token, rules);

A verifier that holds several keys compares `Compact.peekKeyDigest(token)`
with `Compact.keyDigest(key.keyId())` of each one; a token sealed by a
key without an id carries no digest and `peekKeyDigest` returns null.
In Kotlin the same calls are `key.sealCompact(claims)`,
`key.openCompact(token) { ... }`, `token.peekCompactKeyDigest()` and
`key.compactKeyDigest`.

The two families never cross: a cb2 token is `invalid` through `Compact`
and a compact token is `invalid` through `Token`. The compact profile
carries less than cb2, and the issuer refuses with `argument` what it
cannot carry: a custom number that is not an integer in the signed
64-bit range written in canonical form (`1.5`, `1e3` and `-0` are
refused; cb2 accepts them), a time outside the years 0000 to 9999, and a
`cnf` that is not a kcb2.local or kcb2.public key. A cb3.public token
cannot carry a kcb2.local proof key in `cnf`, since its claims are
readable. The format is experimental and its header name `cb3` may
change; nothing here should be stored for long.

### Claim tables

An issuer and its verifiers may also agree on a claim table
(docs/PROTOCOL.md section 15.5): an ordered list of 1 to 256 distinct,
non-empty strings, typically the issuer's name and its audiences. Under
a table an `iss` or `aud` equal to an entry travels as its index, which
brings the cb3.local token of the benchmark claims from 224 bytes to
191. The table is configuration, like a key: both sides build the same
list, and it is never sent.

    try (ClaimTable table = ClaimTable.of("https://issuer.example", "api", "billing")) {
        String token = Compact.seal(key, table, claims);
        String opened = Compact.open(key, table, token, rules);
    }

Every `Compact` call has an overload with the table after the key; a
null table means none, and the overloads without one are unchanged. The
table's digest (`ClaimTable.digest()`, 32 bytes, so two parties can
compare their tables) is bound into the token: a token opens only under
the same entries in the same order, and under another table, or none,
it is `invalid`, as is a token made without a table and opened under
one. The rules work as before, so `issuer_mismatch`,
`audience_mismatch` and the rules that accept any issuer or audience
keep their meaning. Without a table, an implicit assertion that starts
with `kcb3.table.` is refused with `argument`. `ClaimTable.of` refuses
with `argument` an empty list, more than 256 entries, a repeated or
empty entry and an entry with control characters. A table is immutable
and may be shared between threads; close it like a key. In Kotlin,
`claimTable(...)` or `list.toClaimTable()` builds one, and
`key.sealCompact(table, claims)`, `key.openCompact(table, token) { ... }`,
`signer.signCompact(table, claims)` and `verifier.verifyCompact(table,
token) { ... }` use it.

## Errors

Every refusal by the library is a `Cb2Exception` (unchecked) carrying an
integer `code()`, one of the constants in `Code`, and its stable
`name()`: `invalid`, `expired`, `audience_mismatch`, `replayed`,
`missing_proof`, `proof_replayed` and so on; the message reads
`cb2: replayed (17)`. The names are the verdicts of
[docs/PROTOCOL.md](../../docs/PROTOCOL.md), the same in every language.
A token that is not authentic is `invalid` without saying why. Misuse of
the Java API is an ordinary Java exception: `IllegalArgumentException`
for a null argument, `IllegalStateException` for a closed key.

## Native library loading

`Cb2.load()` loads the native code once; every class calls it before its
first native call, so call it yourself only to fail early. It tries, and
the first that works wins:

1. the file named by the system property `cb2.jni.library`;
2. the libraries the jar carries under
   `com/cipherbird/cb2/native/<os>-<arch>/` (os is macos, linux or
   windows; arch is aarch64 or x86_64), listed in load order in the file
   `libraries` there. They are copied into a new directory only the
   current user can read, under the system property `cb2.jni.tmpdir` or
   else java.io.tmpdir, loaded, and deleted at once. Set
   `cb2.jni.bundled=false` to skip this step;
3. `System.loadLibrary("cb2_jni")` from java.library.path, which needs
   libcb2_c beside libcb2_jni or on the system library path.

When the bundled copy is present but fails to load, step 3 still runs,
and if it fails as well its error carries the first one as a suppressed
exception.

A jar carries the libraries for the platform that built it. The shared
libraries libcb2_c itself links must be installed where it runs: with
the Homebrew build on macOS these are libsodium, libcrypto and libblake3
(`otool -L` or `ldd` on libcb2_c lists them). For a jar that serves
several platforms, add each platform's directory with its `libraries`
file under `cb2/src/main/resources/com/cipherbird/cb2/native/` before
building, or ship the libraries separately and use step 1 or 3.

From Java 24 the JVM warns when a library loads native code without
permission. Grant it to the module with
`--enable-native-access=com.cipherbird.cb2`, or on the class path with
`--enable-native-access=ALL-UNNAMED` (or the jar manifest attribute
`Enable-Native-Access: ALL-UNNAMED` for an executable jar).

## Closing keys, and threads

Keys hold native memory and implement `AutoCloseable`: use
try-with-resources in Java and `use { }` in Kotlin. Closing wipes and
frees the native key; a closed key refuses use with
`IllegalStateException`, and closing twice does nothing. A key that is
never closed is freed by a `Cleaner` once it is unreachable, but that is
a backstop, not the contract. Keys made by `publicKey()`, `unwrap` and
`unseal` are new keys you close too.

A key may be used from several threads at once. `setKeyId` and
`clearKeyId` wait for calls in progress, and `close` frees the native key
when the last call in progress returns. `Rules` is a mutable builder:
make one per check, or share one only once it no longer changes. A
`ReplayCheck` runs on the thread that opens the token, so one shared
between threads must be thread-safe, such as
`ConcurrentHashMap.newKeySet()::add`.

## Examples

    ./gradlew :examples:token-service:run
    ./gradlew :examples:token-tour:run

`examples/token-service` is a Java module: an HTTP service on
`com.sun.net.httpserver` that issues a cb2.local access token bound to
the client's signing key and a cb2.public id token, and a client on
`java.net.http` that verifies the id token with the published key and
calls GET /me with holder proofs, then tries a replayed proof, no proof,
a proof for another path, a tampered token and a stolen token with a
thief's proof:

    cb2 0.1.0 from Java
    token service listening on http://127.0.0.1:49581
    POST /token                              200  access cb2.local (3986 chars), id cb2.public (4784 chars)
    id token verified with the published key: {"iss":"http://127.0.0.1:49581","sub":"user-1","aud":"client",...}
    GET /me with a proof                     200  sub user-1, scope read
    GET /me, the same proof again            401  proof_replayed
    GET /me without a proof                  401  missing_proof
    GET /me, proof for another path          401  proof_mismatch
    GET /me, a tampered token                401  invalid
    GET /me, stolen token, thief's proof     401  proof_invalid
    GET /me with a new proof                 200  sub user-1, scope read

`examples/token-tour` walks the Kotlin library: a cb2.local token sealed,
opened and refused four ways, the same claims as a compact cb3.local
token with and without a claim table, a cb2.public token signed and verified, a
local-mode holder proof checked and refused, and a key sealed to a
recipient.

## Android

The same JNI source compiles with the NDK: build libcb2_c for the target
ABI (arm64-v8a, x86_64, ...) with the NDK toolchain, then point
`cb2/CMakeLists.txt` at it with `CB2_C_LIBRARY_DIR` and
`CB2_C_INCLUDE_DIR` from an `externalNativeBuild` block, or add
`cb2/src/main/cpp/cb2_jni.cpp` to your own CMake target. Ship libcb2_c
and libcb2_jni (and the libraries libcb2_c links, such as libsodium,
libcrypto and libblake3, when they are not static) in `jniLibs`; the
loader then finds them with `System.loadLibrary("cb2_jni")`. The Java and
Kotlin sources need nothing beyond the JDK and kotlin-stdlib. This path
is not built or tested here.

## Benchmarks

JMH benchmarks in [bench/](bench/README.md) compare the library with
the popular JWT and PASETO libraries on the JVM, on one claims payload
(iss, sub, aud, exp, iat, jti and a short custom claim, 187 bytes of
JSON). Issuing makes a token from the claims; checking verifies or
decrypts it and checks issuer, audience and expiry. JJWT and Nimbus do
that check themselves; paseto4j returns the payload, so the benchmark
parses it with Jackson and checks the three claims by hand, as an
application would. cb2 and paseto4j take the claims as JSON text; JJWT
and Nimbus serialise their claims object on every issue.

Average time per operation in microseconds (lower is better), with the
99.9% confidence interval JMH reports:

| format and library | issue (us) | check (us) | token (bytes) |
|---|---:|---:|---:|
| cb2.local (this library) | 6.57 +- 0.28 | 6.03 +- 0.20 | 430 |
| PASETO v4.local (paseto4j) | 6.81 +- 0.22 | 5.56 +- 0.19 | 344 |
| JWT HS256 (JJWT) | 4.70 +- 0.08 | 6.79 +- 0.28 | 272 |
| JWT HS256 (Nimbus) | 2.55 +- 0.07 | 4.90 +- 0.10 | 269 |
| cb2.public, Ed25519 and ML-DSA-65 (this library) | 174.31 +- 1.96 | 123.18 +- 7.20 | 4843 |
| PASETO v4.public, Ed25519 (paseto4j, Bouncy Castle) | 57.37 +- 2.24 | 76.37 +- 1.52 | 345 |
| JWT EdDSA, Ed25519 (Nimbus, Tink) | 63.04 +- 3.77 | 174.84 +- 3.65 | 312 |
| JWT EdDSA, Ed25519 (JJWT, the JDK's SunEC) | 574.20 +- 13.98 | 569.92 +- 20.57 | 315 |
| JWT ES256 (Nimbus) | 152.92 +- 2.90 | 533.91 +- 9.72 | 312 |
| JWT ES256 (JJWT) | 163.75 +- 3.74 | 536.44 +- 15.15 | 315 |

What the numbers say, plainly:

- With a shared key, the four are within a few microseconds of each
  other. cb2.local costs about the same as PASETO v4.local and JJWT
  HS256; Nimbus HS256 is the fastest. The cb2 figures include the JNI
  crossing, copying the strings to and from UTF-8, and serialising the
  rules to JSON on every check; the work in the native library is
  only part of it. A cb2.local token is 86 bytes larger than the PASETO one
  because its footer names the key (the kcb2.lid identifier, 84
  characters after encoding); unlike a JWT, its claims are encrypted.
- cb2.public carries a post-quantum ML-DSA-65 signature next to the
  Ed25519 one and checks both, so it is expected to be slower and much
  larger than the classical formats: against PASETO v4.public it takes
  3 times as long to issue, 1.6 times as long to check, and is 14 times
  the size. That is the price of a token that stays unforgeable against
  a quantum computer. It issues in about the time of an ES256 JWT, and
  checks faster than every EdDSA and ES256 JWT measured here.
- The Ed25519 figures depend more on the crypto provider than on the
  format: the same JWT EdDSA token costs 63 us to sign with Tink
  (Nimbus) and 574 us with the JDK's SunEC (JJWT).

Measured on 2026-11-07 on an Apple M3 Max (14 cores, 10 performance)
with macOS 26.6.2 and Oracle JDK 21.0.1, with JMH 1.37: average time,
2 forks, 3 warmup and 5 measured iterations of one second, one thread.
Other processes kept the load average at 7 to 10 during the run, on a
machine with 14 cores; an earlier run under a load of 44 gave similar
figures with much wider intervals and is not reported. Libraries: cb2 0.1.0
(native: libsodium 1.0.22, BLAKE3 1.8.7, liboqs 0.16.0, OpenSSL 4.0.3),
JJWT 0.13.0 with Jackson 2.22.4, Nimbus JOSE+JWT 10.10 with Tink 1.24.0
for Ed25519, paseto4j 2026.0 with Bouncy Castle 1.84. paseto4j is used
for PASETO because it is maintained (its last release is from September
2026) and implements v4.local and v4.public; jpaseto, the other known
Java implementation, has had no release since 2021 and stops at v2.
Token sizes come from `./gradlew :bench:tokenSizes`.

## Building

Build the C ABI first, from the repository root:

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target cb2_c

Then, from `bindings/java`:

    ./gradlew build

This configures and builds the JNI glue with CMake, packs libcb2_jni and
libcb2_c into the jar, compiles the libraries, the examples and the
benchmarks, writes the Javadoc, and runs the tests twice: `test` loads
the glue from the jar, `testLibraryPath` from java.library.path with the
bundled copy turned off. It needs a JDK 17 or later to run Gradle
(tested with 21 and 24), CMake and a C++20 compiler; Gradle downloads
Kotlin, JUnit and the benchmark libraries. When the C ABI was built
somewhere other than `build/bindings/c`, pass `-Pcb2.c.dir=/path/to/dir`
or set `CB2_C_LIBRARY_DIR`.

The JNI glue can also be built on its own:

    cmake -S bindings/java/cb2 -B build-jni -DCB2_C_LIBRARY_DIR=/path/to/libcb2_c
    cmake --build build-jni

Built this way it finds libcb2_c beside itself or in `CB2_C_LIBRARY_DIR`.

Layout:

    settings.gradle.kts, gradlew        the Gradle build (Kotlin DSL, wrapper committed)
    gradle/libs.versions.toml           versions of Kotlin, JUnit and the benchmark libraries
    cb2/                                the Java library: CMakeLists.txt, the JNI glue in
                                        src/main/cpp, the API in src/main/java, JUnit 5 tests
    cb2-kotlin/                         the Kotlin library and its JUnit 5 tests
    bench/                              JMH benchmarks against JJWT, Nimbus and paseto4j
    examples/token-service              Java: an HTTP token service, its client, the quick start
    examples/token-tour                 Kotlin: a command line tour, the quick start
