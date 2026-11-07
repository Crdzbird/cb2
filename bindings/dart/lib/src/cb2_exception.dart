import 'package:cb2/src/ffi/loaded.dart';
import 'package:ffi/ffi.dart';

/// A verdict or failure reported by the cb2 library.
///
/// [code] is the C error code and [name] the stable name the library
/// gives it, such as "invalid", "expired" or "proof_mismatch".
final class Cb2Exception implements Exception {
  /// The verdict [code] with its stable [name].
  const factory Cb2Exception(int code, String name) = Cb2Exception._;

  const Cb2Exception._(this.code, this.name);

  /// The numeric error code, never zero.
  final int code;

  /// The stable name of the verdict.
  final String name;

  /// The name the library gives [code].
  static String nameOf(int code) {
    final text = bindings.core.errorName(code);
    return text.cast<Utf8>().toDartString();
  }

  /// Throws a [Cb2Exception] when [code] is not success.
  static void check(int code) {
    if (code == 0) {
      return;
    }
    throw Cb2Exception(code, nameOf(code));
  }

  @override
  String toString() => 'Cb2Exception($code, $name)';
}
