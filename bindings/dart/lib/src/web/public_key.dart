import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';

/// An ML-DSA-65 verifying key for cb2.public tokens (kcb2.public in
/// PASERK), held in the heap of the WebAssembly engine.
final class PublicKey {
  PublicKey._(JSObject object) : _handle = JsHandle('PublicKey', object);

  final JsHandle _handle;

  /// The key object of the JavaScript binding; throws once [dispose] has
  /// run.
  JSObject get handle => _handle.object;

  /// A key from its raw bytes; malformed material is refused.
  static PublicKey fromBytes(Uint8List bytes) => PublicKey._(
    Engine.current.create('PublicKey', 'fromBytes', [bytes.toJS]),
  );

  /// A key from its kcb2.public text.
  static PublicKey fromPaserk(String text) => PublicKey._(
    Engine.current.create('PublicKey', 'fromPaserk', [text.toJS]),
  );

  /// Wraps a key object the binding produced elsewhere, taking ownership.
  static PublicKey adopt(JSObject handle) => PublicKey._(handle);

  /// The kcb2.public text of this key.
  String toPaserk() => _handle.text('toPaserk');

  /// The kcb2.pid identifier of this key.
  String get paserkId => _handle.text('paserkId');

  /// The key id the verifier expects in token footers, null once cleared.
  String? get keyId => _handle.keyId;

  set keyId(String? id) => _handle.setKeyId(id);

  /// Removes the key id.
  void clearKeyId() => _handle.setKeyId(null);

  /// Frees the key now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
