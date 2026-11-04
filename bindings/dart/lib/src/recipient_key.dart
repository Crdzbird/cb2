import 'dart:ffi';
import 'dart:typed_data';

import 'library.dart';
import 'memory.dart';
import 'recipient_public_key.dart';

/// A recipient pair for kcb2.seal (kcb2.recipient-secret in PASERK).
///
/// Only available when [hasSeal] is true for the loaded library.
final class RecipientKey implements Finalizable {
  RecipientKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    Cb2Library.bindings.recipientKeyFreePointer,
  );

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('RecipientKey used after dispose');
    }
    return _handle;
  }

  /// A fresh random recipient pair.
  static RecipientKey generate() => RecipientKey._(
    takeHandle((_, out) => Cb2Library.bindings.recipientKeyGenerate(out)),
  );

  /// A key from its raw bytes.
  static RecipientKey fromBytes(Uint8List bytes) => RecipientKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.recipientKeyFromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.recipient-secret text.
  static RecipientKey fromPaserk(String text) => RecipientKey._(
    takeHandle(
      (arena, out) => Cb2Library.bindings.recipientKeyFromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// The kcb2.recipient-secret text of this key; treat it as a secret.
  String toPaserk() =>
      takeSecretText(Cb2Library.bindings.recipientKeyToPaserk(handle));

  /// The public half, as a new key the caller owns.
  RecipientPublicKey publicKey() => RecipientPublicKey.adopt(
    takeHandle(
      (_, out) => Cb2Library.bindings.recipientKeyPublicKey(handle, out),
    ),
  );

  /// The kcb2.rid identifier of this key.
  String get paserkId =>
      takeText(Cb2Library.bindings.recipientKeyPaserkId(handle));

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    Cb2Library.bindings.recipientKeyFree(_handle);
    _handle = nullptr;
  }
}
