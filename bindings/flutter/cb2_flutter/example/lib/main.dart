import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/app/cb2_example_app.dart';
import 'package:flutter/material.dart';

/// Loads cb2, then starts the cb2 example app. In a browser the load
/// fetches the WebAssembly engine; elsewhere it opens the native library.
/// A load that fails is not fatal here: the demo reports it as its
/// first step.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await Cb2Flutter.load();
  } on Object catch (e) {
    debugPrint('cb2 did not load: $e');
  }
  runApp(const Cb2ExampleApp());
}
