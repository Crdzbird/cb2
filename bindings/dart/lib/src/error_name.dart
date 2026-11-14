import 'package:cb2/src/ffi/loaded.dart';
import 'package:ffi/ffi.dart';

/// The stable name cb2_error_name gives [code].
String errorNameOf(int code) =>
    bindings.core.errorName(code).cast<Utf8>().toDartString();
