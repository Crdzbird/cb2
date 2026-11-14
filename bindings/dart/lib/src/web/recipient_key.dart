import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';
import 'package:cb2/src/web/recipient_public_key.dart';

/// A recipient pair for kcb2.seal (kcb2.recipient-secret in PASERK), held
/// in the heap of the WebAssembly engine.
final class RecipientKey {
  RecipientKey._(JSObject object) : _handle = JsHandle('RecipientKey', object);

  final JsHandle _handle;

  /// The key object of the JavaScript binding; throws once [dispose] has
  /// run.
  JSObject get handle => _handle.object;

  /// A fresh random recipient pair.
  static RecipientKey generate() =>
      RecipientKey._(Engine.current.create('RecipientKey', 'generate'));

  /// A key from its raw bytes.
  static RecipientKey fromBytes(Uint8List bytes) => RecipientKey._(
    Engine.current.create('RecipientKey', 'fromBytes', [bytes.toJS]),
  );

  /// A key from its kcb2.recipient-secret text.
  static RecipientKey fromPaserk(String text) => RecipientKey._(
    Engine.current.create('RecipientKey', 'fromPaserk', [text.toJS]),
  );

  /// The kcb2.recipient-secret text of this key; treat it as a secret.
  String toPaserk() => _handle.text('toPaserk');

  /// The public half, as a new key the caller owns.
  RecipientPublicKey publicKey() =>
      RecipientPublicKey.adopt(_handle.call('publicKey')! as JSObject);

  /// The kcb2.rid identifier of this key.
  String get paserkId => _handle.text('paserkId');

  /// Frees the key now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
