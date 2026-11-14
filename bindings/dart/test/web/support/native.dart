import 'package:test/test.dart';

/// Asks the native side, a VM isolate over the C library CB2_C_LIBRARY
/// names, to answer [request], and returns its answer.
Future<Object?> askNative(Map<String, Object?> request) => spawnHybridUri(
  '/test/web/hybrid/native_side.dart',
  message: request,
).stream.first;
