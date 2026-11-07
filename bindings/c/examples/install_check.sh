#!/bin/sh
# Installs the C library from a configured build directory into a
# temporary prefix, then builds and runs cb2_c_example against that
# install three ways: find_package with the shared library, find_package
# with the static library, and pkg-config with the Makefile. Fails as well
# when the installed shared library exports anything but cb2_ functions.
#
#   bindings/c/examples/install_check.sh build

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "${1:?usage: install_check.sh <build-dir>}" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PREFIX=$WORK/prefix

cmake --install "$BUILD" --prefix "$PREFIX" > /dev/null
PC_DIR=$(dirname "$(find "$PREFIX" -name cb2_c.pc)")
LIB_DIR=$(dirname "$PC_DIR")

for kind in shared static; do
    static=OFF
    if [ "$kind" = static ]; then static=ON; fi
    cmake -S "$HERE" -B "$WORK/$kind" -DCMAKE_PREFIX_PATH="$PREFIX" -DCB2_C_EXAMPLE_STATIC=$static > /dev/null
    cmake --build "$WORK/$kind" > /dev/null
    echo "== find_package(cb2_c), $kind library"
    "$WORK/$kind/cb2_c_example"
done

mkdir "$WORK/pc"
cp "$HERE/cb2_c_example.c" "$HERE/Makefile" "$WORK/pc/"
PKG_CONFIG_PATH="$PC_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" make -s -C "$WORK/pc"
echo "== pkg-config cb2_c"
"$WORK/pc/cb2_c_example"

case "$(uname -s)" in
    Darwin) extra=$(nm -gU "$LIB_DIR/libcb2_c.dylib" | grep -v ' _cb2_' || true) ;;
    *) extra=$(nm -D --defined-only "$LIB_DIR/libcb2_c.so" | grep -v ' cb2_' || true) ;;
esac
if [ -n "$extra" ]; then
    echo "the shared library exports more than the cb2_ functions:"
    echo "$extra"
    exit 1
fi
echo "== the shared library exports only cb2_ functions"
