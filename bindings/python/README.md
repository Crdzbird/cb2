# cb2 for Python

A bridge to cb2 over its C ABI (`bindings/c`), written with `ctypes` only.
There is no compile step and no third-party dependency; the only thing it
needs is the `cb2_c` shared library built from this repository.

## Install

Either copy the `cb2` directory into your project, or install it in place:

    cd bindings/python
    pip install -e .

## Pointing at the library

The package looks for the shared library in this order:

1. the path in the `CB2_C_LIBRARY` environment variable;
2. wherever `ctypes.util.find_library("cb2_c")` finds it (the system
   library path, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `PATH` on
   Windows);
3. `libcb2_c.dylib`, `libcb2_c.so` or `cb2_c.dll` next to the `cb2`
   package itself.

When none of those opens, importing raises `cb2.LibraryNotFound` with the
paths it tried. From a fresh build of this repository:

    export CB2_C_LIBRARY=$PWD/build/bindings/c/libcb2_c.dylib

## Example

    import cb2
    from cb2 import LocalKey, Rules, Token

    key = LocalKey.generate()
    token = Token.seal(key, {
        "iss": "https://issuer.example",
        "aud": "api",
        "sub": "user-1",
        "exp": "2099-01-01T00:00:00+00:00",
        "jti": "id-1",
    })

    seen = set()

    def first_time(jti: str) -> bool:
        if jti in seen:
            return False
        seen.add(jti)
        return True

    rules = Rules(issuer="https://issuer.example", audience="api", replay=first_time)
    claims = Token.open(token, key, rules)
    try:
        Token.open(token, key, rules)
    except cb2.Cb2Error as e:
        print(e.name, e.code)

Every verdict of the library is a `cb2.Cb2Error` with `.code` and `.name`
(`"expired"`, `"audience_mismatch"`, `"replayed"`, ...). `cb2.has_public()`
and `cb2.has_seal()` tell whether this build carries cb2.public (`SecretKey`,
`PublicKey`, `Token.sign`, `Token.verify`, `Holder.prove`) and kcb2.seal
(`RecipientKey`, `Seal`). `Holder.prove_local`, the holder proof of the local
mode under the `kcb2.local` proof key the issuer put in `cnf` of a cb2.local
token, is in every build.

## Tests

From the repository root, with the library built:

    CB2_C_LIBRARY=$PWD/build/bindings/c/libcb2_c.dylib python3 -m unittest discover -s bindings/python/tests -v
