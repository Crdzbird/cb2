import 'package:cb2/src/ffi/loaded.dart';
import 'package:ffi/ffi.dart';

/// The version string of the loaded cb2 library.
String version() => bindings.core.version().cast<Utf8>().toDartString();

/// Whether the loaded library was built with cb2.public (liboqs).
bool hasPublic() => bindings.core.hasPublic() != 0;

/// Whether the loaded library was built with kcb2.seal.
bool hasSeal() => bindings.core.hasSeal() != 0;
