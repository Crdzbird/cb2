# cb2 for Python

cb2 tokens for Python: cb2.local (XChaCha20 and keyed BLAKE3),
cb2.public (Ed25519 and ML-DSA-65, both required), kcb2.seal (X-Wing),
key wrapping and holder proofs. The package calls the cb2 C ABI
(`bindings/c`) through `ctypes`, has no Python dependencies, is fully
typed (`py.typed`, checked with `mypy --strict`) and supports Python
3.10 and later.

## Install

The package is a platform wheel that carries `libcb2_c` inside it. It is
not on PyPI; build the wheel from a checkout of this repository. The
build needs CMake 3.20 or later, a C++20 compiler, pkg-config and the
libraries the root `CMakeLists.txt` needs: libsodium, BLAKE3, OpenSSL's
libcrypto and, for cb2.public and kcb2.seal, liboqs.

    python -m pip install build
    python -m build --wheel --outdir dist bindings/python
    python -m pip install dist/cb2-*.whl

The build backend is [scikit-build-core](https://scikit-build-core.readthedocs.io).
`bindings/python/CMakeLists.txt` includes the repository's root
`CMakeLists.txt`, builds its `cb2_c` target (the same shared library,
with the same export list, as `bindings/c`) and installs it into the
`cb2` package under its unversioned name, since a wheel cannot hold the
symlinks of a versioned library. The wheel is tagged `py3-none-<platform>`: it works
with any Python 3.10 or later on that platform, since `ctypes` has no
ABI of its own.

That wheel still links to libsodium, BLAKE3 and libcrypto where the
build machine has them. To ship it to machines without them, copy them
into the wheel with the standard repair tools, which is what CI does:

    delocate-wheel -w wheelhouse dist/cb2-*.whl            # macOS
    auditwheel repair -w wheelhouse dist/cb2-*.whl         # Linux

A source distribution is not supported, because the C++ sources live
outside `bindings/python`.

For development, `pip install -e bindings/python` builds the library
once and links the Python sources in place.

## Where the shared library comes from

The library is opened on first use, from the first of these that loads:

1. the path in the `CB2_C_LIBRARY` environment variable. When it is set
   it is the only candidate, so a wrong path fails instead of quietly
   loading another copy;
2. the copy inside the installed `cb2` package, which every wheel has;
3. whatever `ctypes.util.find_library("cb2_c")` finds: the system
   library path, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`.

A candidate whose `cb2_abi_version()` is not the ABI version this
package was written for (0), or that lacks a function, does not load.
When none loads, the call raises `cb2.LibraryNotFound` (an `OSError`)
listing what it tried. `cb2.library_path()` says which file was opened.
The environment variable is how to use a library from a CMake build
without a wheel, for example a build without liboqs:

    export CB2_C_LIBRARY=$PWD/build/bindings/c/libcb2_c.dylib

## Use

```python
import cb2
from cb2 import LocalKey, Rules, Token

key = LocalKey.generate()
claims = {
    "iss": "https://issuer.example",
    "aud": "api",
    "sub": "user-1",
    "exp": "2099-01-01T00:00:00+00:00",
    "jti": "id-1",
}
token = Token.seal(key, claims)

seen: set[str] = set()


def first_time(jti: str) -> bool:
    if jti in seen:
        return False
    seen.add(jti)
    return True


rules = Rules(issuer="https://issuer.example", audience="api", replay=first_time)
opened = Token.open(token, key, rules)
try:
    Token.open(token, key, rules)
except cb2.Cb2Error as e:
    print(e.name, e.code)
```

Every verdict of the library is a `cb2.Cb2Error` with `.code` (a
`cb2.Code`) and `.name` (`"expired"`, `"audience_mismatch"`,
`"replayed"`, ...). A replay callback that raises refuses the token.
`cb2.has_public()` and `cb2.has_seal()` tell whether the library carries
cb2.public (`SecretKey`, `PublicKey`, `Token.sign`, `Token.verify`,
`Public`, `Holder.prove`) and kcb2.seal (`RecipientKey`, `Seal`).
`Holder.prove_local`, the holder proof under the kcb2.local proof key
the issuer put in `cnf` of a cb2.local token, is in every build.

## Example

`examples/token_service.py` is a token service on the standard
library's `http.server`. It issues cb2.local and cb2.public access
tokens and serves `GET /me`, which opens or verifies the token and, for
a token bound to a client key, checks the holder proof in the
`CB2-Proof` header. Run without arguments it starts the service on a
free port, drives it with a `urllib` client and prints each step:

    $ python examples/token_service.py
    cb2 0.1.0 from .../site-packages/cb2/libcb2_c.dylib
    ok   cb2.local token opens: 200 sub=alice
    ok   tampered cb2.local token is refused: 401 invalid
    ok   request without a token is refused: 401 missing_token
    ok   cb2.public token verifies: 200 sub=bob
    ok   cb2.public token from another key is refused: 401 invalid
    ok   bound token without a proof is refused (public): 401 missing_proof
    ok   bound token with its proof opens (public): 200 sub=carol
    ok   the same proof again is refused (public): 401 proof_replayed
    ok   a proof for another target is refused (public): 401 proof_mismatch
    all steps behaved as expected

Against a library without liboqs it skips cb2.public and binds the
token to a kcb2.local proof key instead. `python
examples/token_service.py serve --port 8080` keeps the service running.

## Tests and checks

The tests are pytest; `tests/test_example.py` runs the example too.
They run against the installed package, so install it first (a wheel or
`pip install -e .`), then from `bindings/python`, with pip 25.1 or later
for dependency groups:

    python -m pip install --group dev
    python -m pytest
    python -m mypy
    ruff check . && ruff format --check .

`scripts/check_wheel.sh <wheel>` installs a wheel into a fresh virtual
environment in a temporary directory, then runs the tests,
`mypy --strict` and the example against it; with `CB2_NOPQ_LIBRARY`
set to a library built with `-DCB2_PQ=OFF` it runs them once more
against that library. CI runs it on macOS (after `delocate-wheel`) and
Linux (after `auditwheel repair`).
