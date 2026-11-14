import 'dart:ffi';
import 'dart:io';

import 'package:cb2/src/ffi/loaded.dart';

/// Locates and opens the cb2 C library once for the whole isolate.
///
/// The environment variable CB2_C_LIBRARY wins when set. Otherwise each
/// of [candidates] is opened in turn, and when none opens the symbols are
/// looked up in the running process, which is where a statically linked
/// build puts them. With [preferBundled] the candidates come first and
/// CB2_C_LIBRARY is only the fallback.
final class Cb2Library {
  const Cb2Library._();

  /// The base name of the shared library, without prefix or extension.
  ///
  /// Set it before the first call into cb2; the library is opened once.
  static String name = 'cb2_c';

  /// Whether the [candidates] are tried before CB2_C_LIBRARY.
  ///
  /// An app that bundles the library, as cb2_flutter does, sets this so
  /// that its environment cannot swap the library it ships, and a host
  /// test without a bundled library still finds the one CB2_C_LIBRARY
  /// names.
  static bool preferBundled = false;

  /// Where Flutter serves the browser engine; see [engineUrl].
  static const String bundledEngine = 'assets/packages/cb2/js/src/cb2.js';

  /// Not used outside a browser, where the API runs over the C library;
  /// kept so that code which points the browser engine elsewhere
  /// compiles on every platform.
  static String engineUrl = const String.fromEnvironment(
    'CB2_WEB_ENGINE',
    defaultValue: bundledEngine,
  );

  /// Whether a call has opened the library in this isolate.
  static bool get isLoaded => _loaded;

  static bool _loaded = false;

  /// Opens the library now, so that a missing library fails here rather
  /// than at the first call. Calls work without it outside a browser; in
  /// a browser, where the same method fetches the WebAssembly engine,
  /// it must be awaited first.
  static Future<void> load() async {
    bindings.core.version();
  }

  /// Opens the library following the rules of this class.
  static DynamicLibrary open() {
    final library = _open();
    _loaded = true;
    return library;
  }

  static DynamicLibrary _open() {
    final fromEnvironment = Platform.environment['CB2_C_LIBRARY'] ?? '';
    if (fromEnvironment.isNotEmpty && !preferBundled) {
      return DynamicLibrary.open(fromEnvironment);
    }
    for (final candidate in candidates()) {
      try {
        return DynamicLibrary.open(candidate);
      } on ArgumentError {
        continue;
      }
    }
    if (fromEnvironment.isNotEmpty) {
      return DynamicLibrary.open(fromEnvironment);
    }
    return DynamicLibrary.process();
  }

  /// The file names tried for [name] on the current platform, in order:
  /// cb2_c.framework/cb2_c then libcb2_c.dylib on iOS and macOS,
  /// cb2_c.dll on Windows, libcb2_c.so elsewhere.
  static List<String> candidates() {
    if (Platform.isIOS || Platform.isMacOS) {
      return ['$name.framework/$name', 'lib$name.dylib'];
    }
    if (Platform.isWindows) {
      return ['$name.dll', 'lib$name.dll'];
    }
    return ['lib$name.so'];
  }
}
