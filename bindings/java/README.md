# cb2 for Java and Kotlin

Two JVM libraries over the cb2 C ABI (bindings/c):

| artifact | module | what it is |
|---|---|---|
| `com.cipherbird:cb2` | `com.cipherbird.cb2` (module-info) | the Java API in the package `com.cipherbird.cb2`, the JNI glue, and the native libraries for the platform it was built on |
| `com.cipherbird:cb2-kotlin` | `com.cipherbird.cb2.kotlin` (Automatic-Module-Name) | a rules DSL, a claims builder, extension functions on the keys and verdict helpers, in the package `com.cipherbird.cb2.kotlin`; depends on `cb2` |

The Java library needs nothing beyond the JDK (17 or later); the Kotlin
library adds kotlin-stdlib. The glue calls `cb2_c.h` only; the Java side
sees handles, byte arrays and strings.

## Layout

    settings.gradle.kts, gradlew        the Gradle build (Kotlin DSL, wrapper committed)
    gradle/libs.versions.toml           versions of Kotlin and JUnit
    cb2/                                the Java library
      CMakeLists.txt                    builds libcb2_jni from src/main/cpp/cb2_jni.cpp
      src/main/cpp/cb2_jni.cpp          the JNI glue (C ABI only)
      src/main/java/module-info.java
      src/main/java/com/cipherbird/cb2  Cb2, Cb2Exception, Code, ReplayCheck, the five key
                                        classes, Local, Public, Token, Rules, Holder, KeyWrap,
                                        Seal, Json, and the package-private loader and handle
      src/test/java                     JUnit 5 tests
    cb2-kotlin/                         the Kotlin library: Rules.kt, Claims.kt, Keys.kt,
                                        Verdicts.kt, and JUnit 5 tests
    examples/token-service              Java: an HTTP token service and its client
    examples/token-tour                 Kotlin: a command line tour

## Building

Build the C ABI first, from the repository root (the usual CMake build
with CB2_BUILD_BINDINGS on, which produces build/bindings/c/libcb2_c):

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target cb2_c

Then, from bindings/java:

    ./gradlew build

This configures and builds the JNI glue with CMake, packs libcb2_jni and
libcb2_c into the jar, compiles the Java and Kotlin libraries and the
examples, writes the Javadoc, and runs the tests twice: `test` loads the
glue from the jar, `testLibraryPath` loads it from java.library.path with
the bundled copy turned off. It needs a JDK 17 or later to run Gradle
(tested with 21 and 24), CMake and a C++20 compiler; Gradle downloads
Kotlin and JUnit. When the C ABI was built somewhere other than
build/bindings/c, pass `-Pcb2.c.dir=/path/to/dir` or set
CB2_C_LIBRARY_DIR.

The JNI glue can also be built on its own:

    cmake -S bindings/java/cb2 -B build-jni -DCB2_C_LIBRARY_DIR=/path/to/libcb2_c
    cmake --build build-jni

Built this way it finds libcb2_c beside itself or in CB2_C_LIBRARY_DIR.

## Native library loading

`Cb2.load()` loads the glue once, and every class calls it before its
first native call, so an explicit call is only needed to fail early. It
tries, first match wins:

1. the file named by the system property `cb2.jni.library`;
2. the libraries the jar carries under
   `com/cipherbird/cb2/native/<os>-<arch>/` (os is macos, linux or
   windows; arch is aarch64 or x86_64), listed in load order in the file
   `libraries` there. They are copied into a new directory that only the
   current user can read, under the system property `cb2.jni.tmpdir` or
   else java.io.tmpdir, loaded, and deleted at once. Set
   `cb2.jni.bundled=false` to skip this step;
3. `System.loadLibrary("cb2_jni")` from java.library.path, which needs
   libcb2_c beside libcb2_jni or on the system library path.

When the bundled copy is present but fails to load, step 3 still runs,
and if it fails as well its error carries the first one as a suppressed
exception.

The jar built here carries the libraries for the platform that built it.
The shared libraries libcb2_c itself links must be installed where it
runs: with the Homebrew build on macOS these are libsodium, libcrypto
and libblake3 (`otool -L` or `ldd` on libcb2_c lists them). For a
jar that serves several platforms, add each platform's directory with its
`libraries` file under src/main/resources/com/cipherbird/cb2/native/
before building, or ship the libraries separately and use step 1 or 3.

From Java 24 the JVM warns when a library loads native code without
permission. Grant it to the module, `--enable-native-access=com.cipherbird.cb2`,
or on the class path `--enable-native-access=ALL-UNNAMED` (or the jar
manifest attribute `Enable-Native-Access: ALL-UNNAMED` for an executable
jar).

## Using from Java

Keys implement AutoCloseable: close them, with try-with-resources, to
release and wipe the native key; a closed key refuses use with
IllegalStateException. A key may be used from several threads at once;
setKeyId waits for calls in flight, and close frees the native key once
the last call in flight returns. A key that is never closed is freed by a
Cleaner once unreachable, but that is a backstop, not the contract.

Claims are JSON text in and out. Rules is a builder serialised to the
rules JSON of the C ABI; the replay checks are objects implementing
ReplayCheck (`boolean accept(String jti)`), which the glue calls on the
thread that opens the token. Every refusal is a Cb2Exception carrying the
code (the constants in Code) and the stable verdict name.

    import com.cipherbird.cb2.*;

    Set<String> seen = ConcurrentHashMap.newKeySet();
    try (LocalKey key = LocalKey.generate()) {
        String token = Token.seal(key,
            "{\"iss\":\"https://issuer.example\",\"aud\":\"api\","
            + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\"}");

        Rules rules = new Rules()
            .issuer("https://issuer.example")
            .audience("api")
            .replay(seen::add);
        try {
            String claims = Token.open(key, token, rules);
        } catch (Cb2Exception e) {
            if (e.code() == Code.REPLAYED) {
                ...
            }
        }
    }

Raw tokens take any bytes (Local.seal and Local.open, Public.sign and
Public.verify) with an optional footer and implicit assertion. A bound
token (one with cnf) needs a holder proof made by the client, with
Holder.prove under the client's signing pair or, for a cb2.local token
whose cnf is a kcb2.local proof key, Holder.proveLocal under that key. The
server presents it through Rules.proof and Rules.request, with a proof
replay check (Rules.proofReplay or Rules.proofSeenJti). KeyWrap wraps a
local key under another local key; Seal seals one to a
RecipientPublicKey.

## Using from Kotlin

    import com.cipherbird.cb2.LocalKey
    import com.cipherbird.cb2.kotlin.*
    import java.time.Instant

    LocalKey.generate().use { key ->
        val token = key.sealClaims(claims(
            "iss" to "https://issuer.example",
            "aud" to "api",
            "exp" to Instant.now().plusSeconds(3600),
            "jti" to "id-1",
        ))

        val seen = rememberingCheck()
        val claims = key.openClaims(token) {
            issuer("https://issuer.example")
            audience("api")
            replay(seen)
        }

        when (val verdict = verdictOf { key.openClaims(token) { issuer("x"); audience("api") } }) {
            "ok" -> Unit
            else -> println("refused: $verdict")
        }
    }

Instant and OffsetDateTime values in a claims map become RFC 3339
strings. `onReplay { }` and `onProofReplay { }` take lambdas;
`rememberingCheck()` is backed by a concurrent set unless given one.

## Examples

    ./gradlew :examples:token-service:run
    ./gradlew :examples:token-tour:run

token-service is a Java module: an HTTP service on com.sun.net.httpserver
that issues a cb2.local access token bound to the client's signing key
and a cb2.public id token, and a client on java.net.http that verifies
the id token with the published key and calls GET /me with holder proofs,
then tries a replayed proof, no proof, a proof for another path, a
tampered token and a stolen token with a thief's proof:

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

token-tour walks the Kotlin layer: a cb2.local token sealed, opened and
refused four ways, a cb2.public token signed and verified, a local-mode
holder proof checked and refused, and a key sealed to a recipient.

## Android

The same JNI source compiles with the NDK: build libcb2_c for the target
ABI (arm64-v8a, x86_64, ...) with the NDK toolchain, then point
cb2/CMakeLists.txt at it with CB2_C_LIBRARY_DIR and CB2_C_INCLUDE_DIR from
an externalNativeBuild block, or add cb2/src/main/cpp/cb2_jni.cpp to your
own CMake target. Ship libcb2_c and libcb2_jni (and the libraries
libcb2_c links, such as libsodium, libcrypto and libblake3, when they are
not static) in jniLibs; the loader then finds them with
System.loadLibrary("cb2_jni"). The Java and Kotlin sources need nothing
beyond the JDK and kotlin-stdlib.
