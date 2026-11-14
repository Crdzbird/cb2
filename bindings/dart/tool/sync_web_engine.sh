#!/usr/bin/env bash
# Copy the JavaScript binding into package cb2, where a browser build of
# the package loads it: bindings/js/src/*.js to js/src and the
# WebAssembly core (dist/cb2_core.js, dist/cb2_core.wasm) to js/dist,
# keeping the layout src/cb2.js imports it by. Flutter serves the copy
# from assets/packages/cb2/js/. With --check nothing is copied, and the
# script fails when the copy differs from bindings/js in any file.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$(cd "$HERE/../js" && pwd)"
TARGET="$HERE/js"
FILES=()
for f in "$SOURCE"/src/*.js; do
    FILES+=("src/$(basename "$f")")
done
FILES+=(dist/cb2_core.js dist/cb2_core.wasm)
if [[ "${1:-}" == "--check" ]]; then
    status=0
    for f in "${FILES[@]}"; do
        cmp -s "$SOURCE/$f" "$TARGET/$f" || { echo "differs from bindings/js: js/$f" >&2; status=1; }
    done
    expected="$(printf '%s\n' "${FILES[@]}" | sort)"
    present="$(cd "$TARGET" && find . -type f | sed 's|^\./||' | sort)"
    if [[ "$expected" != "$present" ]]; then
        echo "js/ holds other files than bindings/js ships:" >&2
        diff <(echo "$expected") <(echo "$present") >&2 || true
        status=1
    fi
    exit "$status"
fi
rm -rf "$TARGET"
mkdir -p "$TARGET/src" "$TARGET/dist"
for f in "${FILES[@]}"; do
    cp "$SOURCE/$f" "$TARGET/$f"
done
echo "copied ${#FILES[@]} files from bindings/js to bindings/dart/js"
