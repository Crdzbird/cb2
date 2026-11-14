import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/values.dart';

/// cb2.local tokens over arbitrary bytes.
final class Local {
  const Local._();

  /// Seals [message] under [key], with an optional footer and implicit
  /// assertion, and returns the token text.
  static String seal(
    LocalKey key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => textOf(
    Engine.current.call('Local', 'seal', [
      key.handle,
      message.toJS,
      jsBytes(footer),
      jsBytes(implicit),
    ]),
  );

  /// Opens [token] under [key]; the footer and implicit assertion must
  /// match those given at sealing. [maxTokenBytes] of zero is the default
  /// limit of the library.
  static Uint8List open(
    LocalKey key,
    String token, {
    Uint8List? footer,
    Uint8List? implicit,
    int maxTokenBytes = 0,
  }) => bytesOf(
    Engine.current.call('Local', 'open', [
      key.handle,
      token.toJS,
      jsBytes(footer),
      jsBytes(implicit),
      maxTokenBytes.toJS,
    ]),
  );
}
