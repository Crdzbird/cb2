import 'package:flutter_web_plugins/flutter_web_plugins.dart';

/// The web platform of cb2_flutter, which Flutter registers in a browser
/// build. In a browser package cb2 runs over the WebAssembly build of
/// the cb2 C library that it ships as assets, and Flutter serves those
/// assets with the app, so there is nothing to register: an app awaits
/// `Cb2Flutter.load` once before the first cb2 call.
final class Cb2FlutterWeb {
  const Cb2FlutterWeb._();

  /// Called by the plugin registrant of a Flutter web app; registers
  /// nothing.
  static void registerWith(Registrar registrar) {}
}
