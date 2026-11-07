import 'package:cb2_flutter_example/src/view/demo_page.dart';
import 'package:flutter/material.dart';

/// The example app: one page that runs the token demo.
final class Cb2ExampleApp extends StatelessWidget {
  /// The app with its default theme.
  const factory Cb2ExampleApp({Key? key}) = Cb2ExampleApp._;

  const Cb2ExampleApp._({super.key});

  static const Color _seed = Color(0xFF2F5D50);

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'cb2 tokens',
    theme: ThemeData(colorSchemeSeed: _seed),
    darkTheme: ThemeData(colorSchemeSeed: _seed, brightness: Brightness.dark),
    home: const DemoPage(),
  );
}
