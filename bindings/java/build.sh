#!/bin/sh
# Builds the JNI glue, compiles the Java and Kotlin sources, and runs both
# tests. Run from the repository root or from bindings/java; the C ABI
# must already be built in build/bindings/c (or point CB2_C_LIBRARY_DIR
# at it).

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
C_DIR=${CB2_C_LIBRARY_DIR:-$ROOT/build/bindings/c}
BUILD=$HERE/build
OUT=$HERE/out

if [ -z "${JAVA_HOME:-}" ] && [ -x /usr/libexec/java_home ]; then
    JAVA_HOME=$(/usr/libexec/java_home)
    export JAVA_HOME
fi

case "$(uname -s)" in
    Darwin) JNI_LIB=$BUILD/libcb2_jni.dylib ;;
    *) JNI_LIB=$BUILD/libcb2_jni.so ;;
esac

echo "== JNI glue"
cmake -S "$HERE" -B "$BUILD" -DCB2_C_LIBRARY_DIR="$C_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD"

echo "== Java"
rm -rf "$OUT"
mkdir -p "$OUT/java" "$OUT/test"
javac -Xlint:all -Werror -d "$OUT/java" "$HERE"/src/main/java/com/cipherbird/cb2/*.java
javac -Xlint:all -Werror -cp "$OUT/java" -d "$OUT/test" "$HERE"/src/test/java/com/cipherbird/cb2/*.java

echo "== Kotlin"
kotlinc -Werror -cp "$OUT/java" -include-runtime -d "$OUT/cb2-kotlin.jar" "$HERE/src/main/kotlin"
kotlinc -Werror -cp "$OUT/java:$OUT/cb2-kotlin.jar" -d "$OUT/test" "$HERE/src/test/kotlin"

JAVA_FLAGS="--enable-native-access=ALL-UNNAMED -Djava.library.path=$BUILD -Dcb2.jni.library=$JNI_LIB"

echo "== Java test"
java $JAVA_FLAGS -cp "$OUT/java:$OUT/test" com.cipherbird.cb2.Cb2Test

echo "== Kotlin test"
java $JAVA_FLAGS -cp "$OUT/java:$OUT/cb2-kotlin.jar:$OUT/test" Cb2KtTest

echo "bindings/java: all tests passed"
