import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/js_handle.dart';
import 'package:cb2/src/web/values.dart';

/// A claim table for compact tokens: an ordered list of 1 to 256 distinct,
/// non-empty strings, typically the issuer's name and its audiences, that
/// an issuer and its verifiers configure alike. Under a table an iss or
/// aud equal to an entry travels as its index, and a token opens only
/// under the table it was made under. A table is immutable.
final class ClaimTable {
  ClaimTable._(JSObject object) : _handle = JsHandle('ClaimTable', object);

  final JsHandle _handle;

  /// The size of a table digest in bytes.
  static const int digestBytes = 32;

  /// The table object of the JavaScript binding; throws once [dispose]
  /// has run.
  JSObject get handle => _handle.object;

  /// A table of [entries], in order; anything the rules refuse is
  /// refused with argument.
  static ClaimTable fromEntries(List<String> entries) => ClaimTable._(
    Engine.current.create('ClaimTable', 'fromEntries', [jsJson(entries)]),
  );

  /// The [digestBytes]-byte digest of the table, to compare two parties'
  /// tables.
  Uint8List get digest => bytesOf(_handle.call('digest'));

  /// Frees the table now instead of at garbage collection.
  void dispose() => _handle.dispose();
}
