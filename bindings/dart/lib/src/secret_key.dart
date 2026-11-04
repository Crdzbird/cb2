import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'memory.dart';
import 'public_key.dart';

/// A signing pair for cb2.public tokens (kcb2.secret in PASERK); the
/// pair exists only when [hasPublic] is true for the loaded library.
final class SecretKey implements Finalizable {
  SecretKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    Cb2Library.bindings.secretKeyFreePointer,
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
  static SecretKey generate() => SecretKey._(
    takeHandle((_, out) => Cb2Library.bindings.secretKeyGenerate(out)),
  );

  /// A key from its raw bytes.
  static SecretKey fromBytes(Uint8List bytes) => SecretKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.secretKeyFromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.secret text.
  static SecretKey fromPaserk(String text) => SecretKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.secretKeyFromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// The kcb2.secret text of this key; treat it as a secret.
  String toPaserk() =>
      takeSecretText(Cb2Library.bindings.secretKeyToPaserk(handle));

  /// The public half, as a new key the caller owns.
  PublicKey publicKey() => PublicKey.adopt(
    takeHandle((_, out) => Cb2Library.bindings.secretKeyPublicKey(handle, out)),
  );

  /// The key id bound into token footers, null once cleared.
  String? get keyId =>
      takeOptionalText(Cb2Library.bindings.secretKeyKeyId(handle));

  set keyId(String? id) {
    if (id == null) {
      clearKeyId();
      return;
    }
    using((arena) {
      Cb2Exception.check(
        Cb2Library.bindings.secretKeySetKeyId(
          handle,
          arenaText(arena, id),
          textLength(id),
        ),
      );
    });
  }

  /// Removes the key id so tokens carry none.
  void clearKeyId() => Cb2Library.bindings.secretKeyClearKeyId(handle);

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    Cb2Library.bindings.secretKeyFree(_handle);
    _handle = nullptr;
  }
}
