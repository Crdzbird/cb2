import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';

/// The public half of a recipient pair (kcb2.recipient in PASERK).
final class RecipientPublicKey implements Finalizable {
  RecipientPublicKey._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.recipientPublicKey.freePointer,
  );

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('RecipientPublicKey used after dispose');
    }
    return _handle;
  }

  /// A key from its raw bytes.
  static RecipientPublicKey fromBytes(Uint8List bytes) => RecipientPublicKey._(
    takeHandle(
      (arena, out) => bindings.recipientPublicKey.fromBytes(
        arenaBytes(arena, bytes),
        bytes.length,
        out,
      ),
    ),
  );

  /// A key from its kcb2.recipient text.
  static RecipientPublicKey fromPaserk(String text) => RecipientPublicKey._(
    takeHandle(
      (arena, out) => bindings.recipientPublicKey.fromPaserk(
        arenaText(arena, text),
        textLength(text),
        out,
      ),
    ),
  );

  /// Wraps a handle the library produced elsewhere, taking ownership.
  static RecipientPublicKey adopt(Pointer<Void> handle) =>
      RecipientPublicKey._(handle);

  /// The kcb2.recipient text of this key.
  String toPaserk() => takeText(bindings.recipientPublicKey.toPaserk(handle));

  /// The kcb2.rid identifier of this key.
  String get paserkId => takeText(bindings.recipientPublicKey.paserkId(handle));

  /// Frees the native key now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.recipientPublicKey.free(_handle);
    _handle = nullptr;
  }
}
