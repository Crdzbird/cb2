import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// A claim table for compact tokens: an ordered list of 1 to 256 distinct,
/// non-empty strings, typically the issuer's name and its audiences, that
/// an issuer and its verifiers configure alike. Under a table an iss or
/// aud equal to an entry travels as its index, and a token opens only
/// under the table it was made under. A table is immutable.
final class ClaimTable implements Finalizable {
  ClaimTable._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  static final NativeFinalizer _finalizer = NativeFinalizer(
    bindings.tables.freePointer,
  );

  /// The size of a table digest in bytes.
  static const int digestBytes = 32;

  Pointer<Void> _handle;

  /// The native handle; throws once [dispose] has run.
  Pointer<Void> get handle {
    if (_handle == nullptr) {
      throw StateError('ClaimTable used after dispose');
    }
    return _handle;
  }

  /// The table of [entries], in order. An empty list, more than 256
  /// entries, a repeated or empty entry, or an entry with control
  /// characters is refused with argument.
  static ClaimTable fromEntries(List<String> entries) => ClaimTable._(
    takeHandle((arena, out) {
      final json = jsonEncode(entries);
      return bindings.tables.fromJson(
        arenaText(arena, json),
        textLength(json),
        out,
      );
    }),
  );

  /// The [digestBytes]-byte digest of this table, so two parties can
  /// check they hold the same one.
  Uint8List get digest => using((arena) {
    final out = arena<Pointer<Uint8>>();
    Cb2Exception.check(bindings.tables.digest(handle, out));
    return takeBytes(out.value, digestBytes);
  });

  /// Frees the native table now instead of at garbage collection.
  void dispose() {
    if (_handle == nullptr) {
      return;
    }
    _finalizer.detach(this);
    bindings.tables.free(_handle);
    _handle = nullptr;
  }
}
