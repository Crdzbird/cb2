import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// A 32-byte symmetric key for cb2.local tokens (kcb2.local in PASERK).
final class LocalKey implements Finalizable {
  LocalKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.localKey.freePointer,
  );

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('LocalKey used after dispose');
    }
    return _handle;
  }

  /// A fresh random key.
  static LocalKey generate() =>
      LocalKey._(takeHandle((_, out) => bindings.localKey.generate(out)));

  /// A key from its raw bytes; weak material is refused with argument.
  static LocalKey fromBytes(Uint8List bytes) => LocalKey._(
    takeHandle(
      (arena, out) => bindings.localKey.fromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.local text.
  static LocalKey fromPaserk(String text) => LocalKey._(
    takeHandle(
      (arena, out) => bindings.localKey.fromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// Wraps a handle the library produced elsewhere, taking ownership.
  static LocalKey adopt(Pointer<Void> handle) => LocalKey._(handle);

  /// The kcb2.local text of this key; treat it as a secret.
  String toPaserk() => takeSecretText(bindings.localKey.toPaserk(handle));

  /// The kcb2.lid identifier of this key.
  String get paserkId => takeText(bindings.localKey.paserkId(handle));

  /// The key id bound into token footers, null once cleared.
  String? get keyId => takeOptionalText(bindings.localKey.keyId(handle));

  set keyId(String? id) {
    if (id == null) {
      clearKeyId();
      return;
    }
    using((arena) {
      Cb2Exception.check(
        bindings.localKey.setKeyId(
          handle,
          arenaText(arena, id),
          textLength(id),
        ),
      );
    });
  }

  /// Removes the key id so tokens carry none.
  void clearKeyId() => bindings.localKey.clearKeyId(handle);

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.localKey.free(_handle);
    _handle = nullptr;
  }
}
