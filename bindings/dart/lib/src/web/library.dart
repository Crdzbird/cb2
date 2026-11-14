import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/web/engine.dart';

/// Locates and loads the cb2 engine once for the whole page: the
/// JavaScript binding of bindings/js, whose src/cb2.js imports the
/// WebAssembly core from ../dist/cb2_core.js and cb2_core.wasm.
///
/// A browser cannot load WebAssembly synchronously, so await [load] once
/// before the first call. Until it completes every call throws a
/// `Cb2Exception` named unavailable.
final class Cb2Library {
  const Cb2Library._();

  /// Where Flutter serves the copy of the binding that package cb2 ships
  /// as assets, relative to the page.
  static const String bundledEngine = 'assets/packages/cb2/js/src/cb2.js';

  /// The URL of src/cb2.js; a relative URL resolves against the
  /// document's base URI. Defaults to the CB2_WEB_ENGINE define, else
  /// [bundledEngine]. Set it before [load].
  static String engineUrl = const String.fromEnvironment(
    'CB2_WEB_ENGINE',
    defaultValue: bundledEngine,
  );

  /// Not used in a browser; kept so that code which names the native
  /// library, as cb2_flutter does, compiles on every platform.
  static String name = 'cb2_c';

  /// Not used in a browser, for the same reason as [name].
  static bool preferBundled = false;

  /// Whether [load] completed and calls are served.
  static bool get isLoaded => Engine.loaded != null;

  /// Fetches and instantiates the engine at [engineUrl], once. Concurrent
  /// calls share one load. A failed load rejects with the browser's
  /// error, leaves nothing loaded, and the next call tries again.
  static Future<void> load() => Engine.load(candidates().single);

  /// The absolute URL [load] imports: [engineUrl] resolved against the
  /// document's base URI.
  static List<String> candidates() => [
    Uri.parse(_baseUri()).resolve(engineUrl).toString(),
  ];

  static String _baseUri() {
    final document = globalContext['document'];
    if (document.isA<JSObject>()) {
      final base = (document! as JSObject)['baseURI'];
      if (base.isA<JSString>()) {
        return (base! as JSString).toDart;
      }
    }
    return Uri.base.toString();
  }
}
