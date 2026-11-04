import 'dart:typed_data';

import 'library.dart';
import 'public_key.dart';
import 'raw_calls.dart';
import 'secret_key.dart';

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
  }) => rawSeal(
    Cb2Library.bindings.publicSign,
    key.handle,
    message,
    footer,
    implicit,
  );

  /// Verifies [token] with [key] and returns its message; the footer and
  /// implicit assertion must match those given at signing.
  static Uint8List verify(
    PublicKey key,
    String token, {
    Uint8List? footer,
    Uint8List? implicit,
    int maxTokenBytes = 0,
  }) => rawOpen(
    Cb2Library.bindings.publicVerify,
    key.handle,
    token,
    footer,
    implicit,
    maxTokenBytes,
  );
}
