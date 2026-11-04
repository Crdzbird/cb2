import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'memory.dart';

/// The verifying half of a signing pair (kcb2.public in PASERK).
final class PublicKey implements Finalizable {
  PublicKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    Cb2Library.bindings.publicKeyFreePointer,
  );

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('PublicKey used after dispose');
    }
    return _handle;
  }

  /// A key from its raw bytes.
  static PublicKey fromBytes(Uint8List bytes) => PublicKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.publicKeyFromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.public text.
  static PublicKey fromPaserk(String text) => PublicKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.publicKeyFromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// Wraps a handle the library produced elsewhere, taking ownership.
  static PublicKey adopt(Pointer<Void> handle) => PublicKey._(handle);

  /// The kcb2.public text of this key.
  String toPaserk() => takeText(Cb2Library.bindings.publicKeyToPaserk(handle));

  /// The kcb2.pid identifier of this key.
  String get paserkId =>
      takeText(Cb2Library.bindings.publicKeyPaserkId(handle));

  /// The key id bound into token footers, null once cleared.
  String? get keyId =>
      takeOptionalText(Cb2Library.bindings.publicKeyKeyId(handle));

  set keyId(String? id) {
    if (id == null) {
      clearKeyId();
      return;
    }
    using((arena) {
      Cb2Exception.check(
        Cb2Library.bindings.publicKeySetKeyId(
          handle,
          arenaText(arena, id),
          textLength(id),
        ),
      );
    });
  }

  /// Removes the key id so tokens carry none.
  void clearKeyId() => Cb2Library.bindings.publicKeyClearKeyId(handle);

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    Cb2Library.bindings.publicKeyFree(_handle);
    _handle = nullptr;
  }
}
