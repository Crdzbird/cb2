import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';
import 'package:cb2/src/web/public_key.dart';

/// An ML-DSA-65 signing key for cb2.public tokens (kcb2.secret in
/// PASERK), held in the heap of the WebAssembly engine.
final class SecretKey {
  SecretKey._(JSObject object) : _handle = JsHandle('SecretKey', object);

  final JsHandle _handle;

  /// The key object of the JavaScript binding; throws once [dispose] has
  /// run.
  JSObject get handle => _handle.object;

  /// A fresh random key pair.
  static SecretKey generate() =>
      SecretKey._(Engine.current.create('SecretKey', 'generate'));

  /// A key from its raw bytes; malformed material is refused.
  static SecretKey fromBytes(Uint8List bytes) => SecretKey._(
    Engine.current.create('SecretKey', 'fromBytes', [bytes.toJS]),
  );

  /// A key from its kcb2.secret text.
  static SecretKey fromPaserk(String text) => SecretKey._(
    Engine.current.create('SecretKey', 'fromPaserk', [text.toJS]),
  );

  /// The kcb2.secret text of this key; treat it as a secret.
  String toPaserk() => _handle.text('toPaserk');

  /// The public half of this key, a new key to dispose separately.
  PublicKey publicKey() =>
      PublicKey.adopt(_handle.call('publicKey')! as JSObject);

  /// The key id bound into token footers, null once cleared.
  String? get keyId => _handle.keyId;

  set keyId(String? id) => _handle.setKeyId(id);

  /// Removes the key id so tokens carry none.
  void clearKeyId() => _handle.setKeyId(null);

  /// Frees the key now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
