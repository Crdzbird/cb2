import 'dart:typed_data';

import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/raw_calls.dart';

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
  }) =>
      rawSeal(bindings.tokens.localSeal, key.handle, message, footer, implicit);

  /// Opens [token] under [key]; the footer and implicit assertion must
  /// match those given at sealing. [maxTokenBytes] of zero is the default
  /// limit of the library.
  static Uint8List open(
    LocalKey key,
    String token, {
    Uint8List? footer,
    Uint8List? implicit,
    int maxTokenBytes = 0,
  }) => rawOpen(
    bindings.tokens.localOpen,
    key.handle,
    token,
    footer,
    implicit,
    maxTokenBytes,
  );
}
