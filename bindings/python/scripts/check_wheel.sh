#!/usr/bin/env bash
# Installs a cb2 wheel into a fresh virtual environment in a temporary
# directory outside the repository and runs the tests, mypy --strict and
# the example against the installed package. With CB2_NOPQ_LIBRARY set to
# a libcb2_c built with -DCB2_PQ=OFF, runs the tests and the example once
# more against it through CB2_C_LIBRARY.
#
#   bash bindings/python/scripts/check_wheel.sh dist/cb2-*.whl
set -euo pipefail

wheel="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "$0")/.." && pwd)"
nopq="${CB2_NOPQ_LIBRARY:-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
unset CB2_C_LIBRARY PYTHONPATH CB2_NOPQ_LIBRARY

cp -R "$here/tests" "$here/examples" "$work/"
cd "$work"
"${PYTHON:-python3}" -m venv venv
venv/bin/python -m pip install -q --upgrade pip
venv/bin/python -m pip install -q "$wheel" pytest mypy

venv/bin/python - <<'EOF'
import os
import cb2

print("cb2", cb2.__version__, "library", cb2.version(), "public", cb2.has_public(), "seal", cb2.has_seal())
print("opened", cb2.library_path())
assert os.path.dirname(cb2.library_path()) == os.path.dirname(cb2.__file__), "not the bundled library"
EOF
venv/bin/python -m pytest -q -p no:cacheprovider tests
venv/bin/python -m mypy --strict --no-incremental tests examples
venv/bin/python examples/token_service.py

if [ -n "$nopq" ]; then
    CB2_C_LIBRARY="$nopq" venv/bin/python -m pytest -q -p no:cacheprovider tests
    CB2_C_LIBRARY="$nopq" venv/bin/python examples/token_service.py
fi
