import 'dart:ffi';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/memory.dart';
import 'package:cb2/src/recipient_key.dart';
import 'package:cb2/src/recipient_public_key.dart';
import 'package:ffi/ffi.dart';

/// Sealing a local key to a recipient (kcb2.seal, X-Wing).
final class Seal {
  const Seal._();

  /// Seals [key] to the recipient [to] and returns the kcb2.seal text.
  static String seal(RecipientPublicKey to, LocalKey key) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(bindings.proofs.seal(to.handle, key.handle, out));
    return takeText(out.value);
  });

  /// Recovers the key sealed in [text] with the recipient pair [by].
  static LocalKey unseal(String text, RecipientKey by) => using((arena) {
    final out = arena<Pointer<Void>>();
    Cb2Exception.check(
      bindings.proofs.unseal(
        arenaText(arena, text),
        textLength(text),
        by.handle,
        out,
      ),
    );
    return LocalKey.adopt(out.value);
  });
}
