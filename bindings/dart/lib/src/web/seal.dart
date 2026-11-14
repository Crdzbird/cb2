import 'dart:js_interop';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/recipient_key.dart';
import 'package:cb2/src/web/recipient_public_key.dart';
import 'package:cb2/src/web/values.dart';

/// Sealing a local key to a recipient (kcb2.seal, X-Wing).
final class Seal {
  const Seal._();

  /// Seals [key] to the recipient [to] and returns the kcb2.seal text.
  static String seal(RecipientPublicKey to, LocalKey key) =>
      textOf(Engine.current.call('Seal', 'seal', [to.handle, key.handle]));

  /// Recovers the key sealed in [text] with the recipient pair [by].
  static LocalKey unseal(String text, RecipientKey by) => LocalKey.adopt(
    Engine.current.create('Seal', 'unseal', [text.toJS, by.handle]),
  );
}
