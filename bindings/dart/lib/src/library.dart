import 'dart:ffi';
import 'dart:io';

/// Locates and opens the cb2 C library once for the whole isolate.
///
/// The environment variable CB2_C_LIBRARY wins when set. Otherwise each
/// of [candidates] is opened in turn, and when none opens the symbols are
/// looked up in the running process, which is where a statically linked
/// build puts them.
final class Cb2Library {
  const Cb2Library._();

  /// The base name of the shared library, without prefix or extension.
  ///
  /// Set it before the first call into cb2; the library is opened once.
  static String name = 'cb2_c';

  /// Opens the library following the rules of this class.
  static DynamicLibrary open() {
    final fromEnvironment = Platform.environment['CB2_C_LIBRARY'];
    if (fromEnvironment != null && fromEnvironment.isNotEmpty) {
      return DynamicLibrary.open(fromEnvironment);
    }
    for (final candidate in candidates()) {
      try {
        return DynamicLibrary.open(candidate);
      } on ArgumentError {
        continue;
      }
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
