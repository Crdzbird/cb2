/// Flutter packaging of cb2: the Dart API of package cb2, re-exported, and
/// the name of the native library this plugin builds or bundles.
library;

import 'package:cb2/cb2.dart';

export 'package:cb2/cb2.dart';

/// Points the cb2 loader at the library this plugin provides.
///
/// The plugin builds libcb2_c.so on Android and Linux and cb2_c.dll on
/// Windows, and vendors libcb2_c.xcframework on iOS and macOS, so the
/// loader of package cb2 resolves [libraryName] on every platform. Call
/// [ensureInitialized] once before the first cb2 call; it is idempotent.
final class Cb2Flutter {
  const Cb2Flutter._();

  /// The base name of the native library, without prefix or extension.
  static const String libraryName = 'cb2_c';

  /// Makes the cb2 loader look for [libraryName].
  static void ensureInitialized() {
    Cb2Library.name = libraryName;
  }
}
