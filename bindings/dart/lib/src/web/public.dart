import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/public_key.dart';
import 'package:cb2/src/web/secret_key.dart';
import 'package:cb2/src/web/values.dart';

/// cb2.public tokens over arbitrary bytes.
final class Public {
  const Public._();

  /// Signs [message] with [key], with an optional footer and implicit
  /// assertion, and returns the token text.
  static String sign(
    SecretKey key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => textOf(
    Engine.current.call('Public', 'sign', [
      key.handle,
      message.toJS,
      jsBytes(footer),
      jsBytes(implicit),
    ]),
  );

  /// Verifies [token] with [key] and returns its message; the footer and
  /// implicit assertion must match those given at signing.
  static Uint8List verify(
    PublicKey key,
    String token, {
    Uint8List? footer,
    Uint8List? implicit,
    int maxTokenBytes = 0,
  }) => bytesOf(
    Engine.current.call('Public', 'verify', [
      key.handle,
      token.toJS,
      jsBytes(footer),
      jsBytes(implicit),
      maxTokenBytes.toJS,
    ]),
  );
}
