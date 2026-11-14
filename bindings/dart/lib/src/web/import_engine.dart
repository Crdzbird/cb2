import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/cb2_exception.dart';

/// Imports the ES module at [url], src/cb2.js of the JavaScript binding,
/// and resolves to the API object its load() builds over a fresh
/// WebAssembly instance. A module without load() is refused as
/// unavailable; a module or core that cannot be fetched or instantiated
/// rejects with the browser's error.
Future<JSObject> importEngine(String url) async {
  final module = await importModule(url.toJS).toDart;
  final load = module['load'];
  if (!load.isA<JSFunction>()) {
    throw const Cb2Exception(Cb2Exception.unavailable, 'unavailable');
  }
  final pending = (load! as JSFunction).callAsFunction();
  final api = await (pending! as JSPromise<JSObject>).toDart;
  if (!api['Holder'].isA<JSObject>()) {
    throw const Cb2Exception(Cb2Exception.unavailable, 'unavailable');
  }
  return api;
}
