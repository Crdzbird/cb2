import 'package:cb2/cb2.dart';

/// Points the cb2 loader at the library this plugin provides.
///
/// The plugin builds libcb2_c.so on Android and Linux and cb2_c.dll on
/// Windows, and bundles cb2_c.framework on iOS and macOS, so the loader
/// of package cb2 finds [libraryName] on every platform. The bundled
/// library is preferred to one named by CB2_C_LIBRARY, which only serves
/// host tests where nothing is bundled. Call [ensureInitialized] once per
/// isolate before the first cb2 call; it is idempotent.
final class Cb2Flutter {
  const Cb2Flutter._();

  /// The base name of the native library, without prefix or extension.
  static const String libraryName = 'cb2_c';

  /// Makes the cb2 loader of the calling isolate look for [libraryName],
  /// preferring it to CB2_C_LIBRARY.
  static void ensureInitialized() {
    Cb2Library.name = libraryName;
    Cb2Library.preferBundled = true;
  }
}
