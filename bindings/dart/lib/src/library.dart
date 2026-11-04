import 'dart:ffi';
import 'dart:io';

import 'bindings.dart';

/// Locates and opens the cb2 C library once for the whole isolate.
///
/// The environment variable CB2_C_LIBRARY wins when set. Otherwise the
/// platform's spelling of [name] is opened (libcb2_c.dylib, libcb2_c.so,
/// cb2_c.dll, or cb2_c.framework/cb2_c on iOS), and when that fails the
/// symbols are looked up in the running process, which is where a
/// statically linked build puts them.
final class Cb2Library {
  const Cb2Library._();

  /// The base name of the shared library, without prefix or extension.
  static String name = 'cb2_c';

  static Cb2Bindings? _bindings;

  /// The typed entry points of the library, opened on first use.
  static Cb2Bindings get bindings => _bindings ??= Cb2Bindings(open());

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

  /// The file names tried for [name] on the current platform, in order.
  static List<String> candidates() {
    if (Platform.isIOS) {
      return ['$name.framework/$name', 'lib$name.dylib'];
    }
    if (Platform.isMacOS) {
      return ['lib$name.dylib', '$name.framework/$name'];
    }
    if (Platform.isWindows) {
      return ['$name.dll', 'lib$name.dll'];
    }
    return ['lib$name.so'];
  }
}
