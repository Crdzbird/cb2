import 'dart:ffi';
import 'dart:io';

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

  /// Opens the library following the rules of this class.
  static DynamicLibrary open() {
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
