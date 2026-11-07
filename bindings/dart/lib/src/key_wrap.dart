import 'dart:ffi';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// Symmetric key wrapping (kcb2.local-wrap).
final class KeyWrap {
  const KeyWrap._();

  /// Wraps [key] under [wrapping] and returns the kcb2.local-wrap text.
  static String wrap(LocalKey wrapping, LocalKey key) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(bindings.proofs.wrap(wrapping.handle, key.handle, out));
    return takeText(out.value);
  });

  /// Recovers the key wrapped in [text] under [wrapping].
  static LocalKey unwrap(String text, LocalKey wrapping) => using((arena) {
    final out = arena<Pointer<Void>>();
    Cb2Exception.check(
      bindings.proofs.unwrap(
        arenaText(arena, text),
        textLength(text),
        wrapping.handle,
        out,
      ),
    );
    return LocalKey.adopt(out.value);
  });
}
