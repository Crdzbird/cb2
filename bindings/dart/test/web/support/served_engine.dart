import 'package:cb2/cb2.dart';

/// The engine copy of this package as the test runner serves it: the
/// package root sits two levels above the page of a suite in test/web.
String get servedEngineUrl =>
    Uri.base.resolve('../../js/src/cb2.js').toString();

/// Points the loader at the served copy and loads it.
Future<void> loadServedEngine() {
  Cb2Library.engineUrl = servedEngineUrl;
  return Cb2Library.load();
}
