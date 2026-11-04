import 'package:ffi/ffi.dart';

import 'library.dart';

/// The version string of the loaded cb2 library.
String version() => Cb2Library.bindings.version().cast<Utf8>().toDartString();

/// Whether the loaded library was built with cb2.public (liboqs).
bool hasPublic() => Cb2Library.bindings.hasPublic() != 0;

/// Whether the loaded library was built with kcb2.seal.
bool hasSeal() => Cb2Library.bindings.hasSeal() != 0;
