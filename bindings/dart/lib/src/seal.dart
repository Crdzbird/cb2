import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'local_key.dart';
import 'memory.dart';
import 'recipient_key.dart';
import 'recipient_public_key.dart';

/// Sealing a local key to a recipient (kcb2.seal, X-Wing).
final class Seal {
  const Seal._();

  /// Seals [key] to the recipient [to] and returns the kcb2.seal text.
  static String seal(RecipientPublicKey to, LocalKey key) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(Cb2Library.bindings.seal(to.handle, key.handle, out));
    return takeText(out.value);
  });

  /// Recovers the key sealed in [text] with the recipient pair [by].
  static LocalKey unseal(String text, RecipientKey by) => using((arena) {
    final out = arena<Pointer<Void>>();
    Cb2Exception.check(
      Cb2Library.bindings.unseal(
        arenaText(arena, text),
        textLength(text),
        by.handle,
        out,
      ),
    );
    return LocalKey.adopt(out.value);
  });
}
