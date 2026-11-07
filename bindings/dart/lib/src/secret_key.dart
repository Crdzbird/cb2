import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';
import 'package:cb2/src/public_key.dart';
import 'package:ffi/ffi.dart';

/// A signing pair for cb2.public tokens (kcb2.secret in PASERK); the
/// pair exists only when `hasPublic()` is true for the loaded library.
final class SecretKey implements Finalizable {
  SecretKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.secretKey.freePointer,
  );

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('SecretKey used after dispose');
    }
    return _handle;
  }

  /// A fresh random signing pair.
  static SecretKey generate() =>
      SecretKey._(takeHandle((_, out) => bindings.secretKey.generate(out)));

  /// A key from its raw bytes.
  static SecretKey fromBytes(Uint8List bytes) => SecretKey._(
    takeHandle(
      (arena, out) => bindings.secretKey.fromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.secret text.
  static SecretKey fromPaserk(String text) => SecretKey._(
    takeHandle(
      (arena, out) => bindings.secretKey.fromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// The kcb2.secret text of this key; treat it as a secret.
  String toPaserk() => takeSecretText(bindings.secretKey.toPaserk(handle));

  /// The public half, as a new key the caller owns.
  PublicKey publicKey() => PublicKey.adopt(
    takeHandle((_, out) => bindings.secretKey.publicKey(handle, out)),
  );

  /// The key id bound into token footers, null once cleared.
  String? get keyId => takeOptionalText(bindings.secretKey.keyId(handle));

  set keyId(String? id) {
    if (id == null) {
      clearKeyId();
      return;
    }
    using((arena) {
      Cb2Exception.check(
        bindings.secretKey.setKeyId(
          handle,
          arenaText(arena, id),
          textLength(id),
        ),
      );
    });
  }

  /// Removes the key id so tokens carry none.
  void clearKeyId() => bindings.secretKey.clearKeyId(handle);

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.secretKey.free(_handle);
    _handle = nullptr;
  }
}
