import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';

/// A 32-byte symmetric key for cb2.local tokens (kcb2.local in PASERK),
/// held in the heap of the WebAssembly engine.
final class LocalKey {
  LocalKey._(JSObject object) : _handle = JsHandle('LocalKey', object);

  final JsHandle _handle;

  /// The key object of the JavaScript binding; throws once [dispose] has
  /// run.
  JSObject get handle => _handle.object;

  /// A fresh random key.
  static LocalKey generate() =>
      LocalKey._(Engine.current.create('LocalKey', 'generate'));

  /// A key from its raw bytes; weak material is refused with argument.
  static LocalKey fromBytes(Uint8List bytes) =>
      LocalKey._(Engine.current.create('LocalKey', 'fromBytes', [bytes.toJS]));

  /// A key from its kcb2.local text.
  static LocalKey fromPaserk(String text) =>
      LocalKey._(Engine.current.create('LocalKey', 'fromPaserk', [text.toJS]));

  /// Wraps a key object the binding produced elsewhere, taking ownership.
  static LocalKey adopt(JSObject handle) => LocalKey._(handle);

  /// The kcb2.local text of this key; treat it as a secret.
  String toPaserk() => _handle.text('toPaserk');

  /// The kcb2.lid identifier of this key.
  String get paserkId => _handle.text('paserkId');

  /// The key id bound into token footers, null once cleared.
  String? get keyId => _handle.keyId;

  set keyId(String? id) => _handle.setKeyId(id);

  /// Removes the key id so tokens carry none.
  void clearKeyId() => _handle.setKeyId(null);

  /// Frees the key now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
