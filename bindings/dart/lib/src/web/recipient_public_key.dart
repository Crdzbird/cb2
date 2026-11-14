import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';

/// The public half of a recipient pair (kcb2.recipient in PASERK), held
/// in the heap of the WebAssembly engine.
final class RecipientPublicKey {
  RecipientPublicKey._(JSObject object)
    : _handle = JsHandle('RecipientPublicKey', object);

  final JsHandle _handle;

  /// The key object of the JavaScript binding; throws once [dispose] has
  /// run.
  JSObject get handle => _handle.object;

  /// A key from its raw bytes.
  static RecipientPublicKey fromBytes(Uint8List bytes) => RecipientPublicKey._(
    Engine.current.create('RecipientPublicKey', 'fromBytes', [bytes.toJS]),
  );

  /// A key from its kcb2.recipient text.
  static RecipientPublicKey fromPaserk(String text) => RecipientPublicKey._(
    Engine.current.create('RecipientPublicKey', 'fromPaserk', [text.toJS]),
  );

  /// Wraps a key object the binding produced elsewhere, taking ownership.
  static RecipientPublicKey adopt(JSObject handle) =>
      RecipientPublicKey._(handle);

  /// The kcb2.recipient text of this key.
  String toPaserk() => _handle.text('toPaserk');

  /// The kcb2.rid identifier of this key.
  String get paserkId => _handle.text('paserkId');

  /// Frees the key now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
