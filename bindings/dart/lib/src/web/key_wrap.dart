import 'dart:js_interop';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/values.dart';

/// Symmetric key wrapping (kcb2.local-wrap).
final class KeyWrap {
  const KeyWrap._();

  /// Wraps [key] under [wrapping] and returns the kcb2.local-wrap text.
  static String wrap(LocalKey wrapping, LocalKey key) => textOf(
    Engine.current.call('KeyWrap', 'wrap', [wrapping.handle, key.handle]),
  );

  /// Recovers the key wrapped in [text] under [wrapping].
  static LocalKey unwrap(String text, LocalKey wrapping) => LocalKey.adopt(
    Engine.current.create('KeyWrap', 'unwrap', [text.toJS, wrapping.handle]),
  );
}
