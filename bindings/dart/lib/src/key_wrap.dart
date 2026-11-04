import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'local_key.dart';
import 'memory.dart';

/// Symmetric key wrapping (kcb2.local-wrap).
final class KeyWrap {
  const KeyWrap._();

  /// Wraps [key] under [wrapping] and returns the kcb2.local-wrap text.
  static String wrap(LocalKey wrapping, LocalKey key) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(
      Cb2Library.bindings.wrap(wrapping.handle, key.handle, out),
    );
    return takeText(out.value);
  });

  /// Recovers the key wrapped in [text] under [wrapping].
  static LocalKey unwrap(String text, LocalKey wrapping) => using((arena) {
    final out = arena<Pointer<Void>>();
    Cb2Exception.check(
      Cb2Library.bindings.unwrap(
        arenaText(arena, text),
        textLength(text),
        wrapping.handle,
        out,
      ),
    );
    return LocalKey.adopt(out.value);
  });
}
