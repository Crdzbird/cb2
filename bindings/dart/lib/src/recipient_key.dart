import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';
import 'package:cb2/src/recipient_public_key.dart';

/// A recipient pair for kcb2.seal (kcb2.recipient-secret in PASERK).
///
/// Only available when `hasSeal()` is true for the loaded library.
final class RecipientKey implements Finalizable {
  RecipientKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.recipientKey.freePointer,
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
    takeHandle((_, out) => bindings.recipientKey.generate(out)),
  );

  /// A key from its raw bytes.
  static RecipientKey fromBytes(Uint8List bytes) => RecipientKey._(
    takeHandle(
      (arena, out) => bindings.recipientKey.fromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.recipient-secret text.
  static RecipientKey fromPaserk(String text) => RecipientKey._(
    takeHandle(
      (arena, out) => bindings.recipientKey.fromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// The kcb2.recipient-secret text of this key; treat it as a secret.
  String toPaserk() => takeSecretText(bindings.recipientKey.toPaserk(handle));

  /// The public half, as a new key the caller owns.
  RecipientPublicKey publicKey() => RecipientPublicKey.adopt(
    takeHandle((_, out) => bindings.recipientKey.publicKey(handle, out)),
  );

  /// The kcb2.rid identifier of this key.
  String get paserkId => takeText(bindings.recipientKey.paserkId(handle));

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.recipientKey.free(_handle);
    _handle = nullptr;
  }
}
