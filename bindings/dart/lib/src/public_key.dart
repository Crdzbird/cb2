import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// The verifying half of a signing pair (kcb2.public in PASERK).
final class PublicKey implements Finalizable {
  PublicKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.publicKey.freePointer,
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
      (arena, out) => bindings.publicKey.fromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.public text.
  static PublicKey fromPaserk(String text) => PublicKey._(
    takeHandle(
      (arena, out) => bindings.publicKey.fromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// Wraps a handle the library produced elsewhere, taking ownership.
  static PublicKey adopt(Pointer<Void> handle) => PublicKey._(handle);

  /// The kcb2.public text of this key.
  String toPaserk() => takeText(bindings.publicKey.toPaserk(handle));

  /// The kcb2.pid identifier of this key.
  String get paserkId => takeText(bindings.publicKey.paserkId(handle));

  /// The key id bound into token footers, null once cleared.
  String? get keyId => takeOptionalText(bindings.publicKey.keyId(handle));

  set keyId(String? id) {
    if (id == null) {
      clearKeyId();
      return;
    }
    using((arena) {
      Cb2Exception.check(
        bindings.publicKey.setKeyId(
          handle,
          arenaText(arena, id),
          textLength(id),
        ),
      );
    });
  }

  /// Removes the key id so tokens carry none.
  void clearKeyId() => bindings.publicKey.clearKeyId(handle);

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.publicKey.free(_handle);
    _handle = nullptr;
  }
}
