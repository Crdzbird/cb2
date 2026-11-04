# cb2 for Java and Kotlin

A JNI bridge over the cb2 C ABI (bindings/c), with Java classes in the
package com.cipherbird.cb2 and a Kotlin layer of extensions and a rules
DSL over them. The glue calls cb2_c.h only; the Java side sees handles,
byte arrays and strings.

## Layout

    CMakeLists.txt              builds libcb2_jni from src/main/cpp/cb2_jni.cpp
    build.sh                    builds the glue, compiles Java and Kotlin, runs both tests
    src/main/cpp/cb2_jni.cpp    the JNI glue (C ABI only)
    src/main/java/...           Cb2, Cb2Exception, Code, ReplayCheck, the five key
                                classes, Local, Public, Token, Rules, Holder,
                                KeyWrap, Seal, Json
    src/main/kotlin/.../Cb2.kt  the Kotlin layer
    src/test/java/.../Cb2Test.java   the Java test (a main; throws on the first failure)
    src/test/kotlin/Cb2KtTest.kt     the Kotlin test, likewise

## Building

Build the C ABI first from the repository root (the usual cmake build
with CB2_BUILD_BINDINGS on produces build/bindings/c/libcb2_c.dylib or
.so). Then, from the repository root:

    ./bindings/java/build.sh

The script configures and builds the JNI library with cmake into
bindings/java/build, compiles the Java classes with javac into
bindings/java/out/java, compiles the Kotlin layer with kotlinc into
bindings/java/out/cb2-kotlin.jar (the Kotlin runtime included), and runs
both tests. It needs javac and java (17 or later; tested with 24),
kotlinc, cmake and a C++20 compiler. Set CB2_C_LIBRARY_DIR when the C
ABI was built somewhere other than build/bindings/c, and JAVA_HOME when
cmake cannot find the JDK on its own.

To build only the glue:

    cmake -S bindings/java -B bindings/java/build -DCB2_C_LIBRARY_DIR=/path/to/libcb2_c
    cmake --build bindings/java/build

The glue is linked against libcb2_c with an rpath to that directory, so
loading libcb2_jni finds libcb2_c without any further setting.

## Loading

Cb2.load() loads the glue once: from the path in the system property
cb2.jni.library when it is set, otherwise with System.loadLibrary
("cb2_jni") from java.library.path. Every class calls it before its
first native call, so an explicit call is only needed to fail early.
On Java 24 and later pass --enable-native-access=ALL-UNNAMED (or name
your module) to silence the restricted-method warning.

## Using from Java

Keys implement AutoCloseable and must be closed to release the native
key; a closed key refuses use with IllegalStateException. Claims are
JSON text in and out. Rules is a builder serialised to the rules JSON of
the C ABI; the replay checks are objects implementing ReplayCheck
(boolean accept(String jti)), which the glue calls from the library's
callback. Every refusal is a Cb2Exception carrying the code (the
constants in Code) and the stable verdict name.

    import com.cipherbird.cb2.*;

    try (LocalKey key = LocalKey.generate()) {
        String token = Token.seal(key,
            "{\"iss\":\"https://issuer.example\",\"aud\":\"api\","
            + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\"}");

        Set<String> seen = ConcurrentHashMap.newKeySet();
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

Raw tokens take any bytes (Local.seal / Local.open, Public.sign /
Public.verify) with an optional footer and implicit assertion. A bound
token (one with cnf) needs a holder proof made by Holder.prove on the
client and presented through Rules.proof and Rules.request on the
server, together with a proof replay check (Rules.proofReplay or
Rules.proofSeenJti). KeyWrap wraps a local key under another local key;
Seal seals one to a RecipientPublicKey.

## Using from Kotlin

The Kotlin layer (Cb2.kt) adds a rules DSL, lambdas for the replay
checks, a claims map to JSON helper with escaping, and extension
functions on the keys. The keys are AutoCloseable, so use {} releases
them.

    import com.cipherbird.cb2.*
    import java.time.Instant

    LocalKey.generate().use { key ->
        val token = key.sealClaims(claims(
            "iss" to "https://issuer.example",
            "aud" to "api",
            "exp" to Instant.now().plusSeconds(3600),
            "jti" to "id-1",
        ))

        val seen = mutableSetOf<String>()
        val claims = key.openClaims(token) {
            issuer("https://issuer.example")
            audience("api")
            onReplay { jti -> seen.add(jti) }
        }

        when (val verdict = verdictOf { key.openClaims(token, rules { issuer("x"); audience("api") }) }) {
            "ok" -> Unit
            else -> println("refused: $verdict")
        }
    }

Instant and OffsetDateTime values in a claims map become RFC 3339
strings. Compile against out/java and run with out/cb2-kotlin.jar (or
your own kotlin-stdlib) on the classpath.

## Android

The same JNI source compiles with the NDK: build libcb2_c for the target
ABI (arm64-v8a, x86_64, ...) with the NDK toolchain, then point this
CMakeLists.txt at it with CB2_C_LIBRARY_DIR and CB2_C_INCLUDE_DIR from
an externalNativeBuild block, or add src/main/cpp/cb2_jni.cpp to your
own CMake target. Ship libcb2_c and libcb2_jni (and the libraries
libcb2_c links, such as libsodium, libcrypto and libblake3, when they
are not static) in jniLibs, and call Cb2.load() or let the first use
load it with System.loadLibrary("cb2_jni"). The Java and Kotlin sources
are plain and need nothing beyond the JDK and kotlin-stdlib.
