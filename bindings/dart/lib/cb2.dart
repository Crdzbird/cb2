/// Dart bindings for cb2, the post-quantum token library.
///
/// Outside a browser the API runs over the C ABI through dart:ffi. Point
/// the loader at the shared library with the environment variable
/// CB2_C_LIBRARY, or let it find libcb2_c on the library path, or set
/// `Cb2Library.name` before the first call.
///
/// In a browser the same API runs over the WebAssembly build of the C ABI
/// that the JavaScript binding ships. Await `Cb2Library.load()` once
/// before the first call; until it completes every call throws a
/// `Cb2Exception` named unavailable.
library;

export 'package:cb2/src/cb2_native.dart'
    if (dart.library.js_interop) 'package:cb2/src/cb2_web.dart';
