import 'dart:typed_data';

import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/public_key.dart';
import 'package:cb2/src/raw_calls.dart';
import 'package:cb2/src/secret_key.dart';

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
    bindings.tokens.publicSign,
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
    bindings.tokens.publicVerify,
    key.handle,
    token,
    footer,
    implicit,
    maxTokenBytes,
  );
}
