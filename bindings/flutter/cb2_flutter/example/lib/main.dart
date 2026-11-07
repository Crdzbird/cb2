import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/app/cb2_example_app.dart';
import 'package:flutter/material.dart';

/// Starts the cb2 example app.
void main() {
  Cb2Flutter.ensureInitialized();
  runApp(const Cb2ExampleApp());
}
