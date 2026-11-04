# cb2 for Dart

Dart bindings for cb2, the post-quantum successor to PASETO, over the C ABI
in `bindings/c` (`cb2_c.h`). Keys are native handles freed by a
`NativeFinalizer` or by `dispose()`; every verdict of the library is a
`Cb2Exception` with the C code and its stable name (`invalid`, `expired`,
`proof_mismatch`, ...). Replay checks are Dart callbacks bridged to the
library for the duration of one call.

## Pointing at the library

The loader in `Cb2Library` tries, in order:

1. the path in the environment variable `CB2_C_LIBRARY`;
2. the platform spelling of `Cb2Library.name` (`cb2_c` by default):
   `libcb2_c.dylib`, `libcb2_c.so`, `cb2_c.dll`, or
   `cb2_c.framework/cb2_c` on iOS, resolved by the dynamic linker;
3. the symbols of the running process, for a statically linked build.

Build the shared library from the repository root with CMake (the
`cb2_c` target under `bindings/c`) and run the tests against it:

    cd bindings/dart
    dart pub get
    CB2_C_LIBRARY=/path/to/build/bindings/c/libcb2_c.dylib dart test

`hasPublic()` and `hasSeal()` say whether the loaded build carries
cb2.public (liboqs) and kcb2.seal.

## Example

```dart
import 'package:cb2/cb2.dart';

void main() {
  final key = LocalKey.generate();
  final token = Token.seal(key, {
    'iss': 'https://issuer.example',
    'aud': 'api',
    'sub': 'user-1',
    'exp': '2099-01-01T00:00:00+00:00',
    'jti': 'id-1',
  });

  final seen = <String>{};
  final claims = Token.open(
    key,
    token,
    Rules(
      issuer: 'https://issuer.example',
      audience: 'api',
      replay: (jti) => seen.add(jti),
    ),
  );
  print(claims['sub']);

  try {
    Token.open(key, token, const Rules(issuer: 'https://issuer.example'));
  } on Cb2Exception catch (e) {
    print(e.name);
  }
  key.dispose();
}
```

`Local` and `Public` carry raw bytes with an optional footer and implicit
assertion; `Token` carries claims as a `Map<String, Object?>` checked
against `Rules`, whose fields mirror the rules JSON documented in
`cb2_c.h`. `Holder.prove` makes a holder proof for a bound token;
`KeyWrap` and `Seal` wrap a local key under another key or seal it to a
`RecipientPublicKey`.

## Layout

One class per file under `lib/src`; `lib/src/bindings.dart` holds every
typed entry point of the ABI and is the one file longer than a hundred
lines, since the signatures belong together.
