import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/web/guard.dart';
import 'package:cb2/src/web/import_engine.dart';

/// The JavaScript binding of cb2, loaded once per page: the API object
/// its load() resolves to, with its own WebAssembly heap. Every key and
/// table made through it belongs to that heap.
final class Engine {
  Engine._(this._api);

  final JSObject _api;

  static Engine? _loaded;
  static Future<JSObject>? _loading;

  /// The loaded engine, null before [load] completed.
  static Engine? get loaded => _loaded;

  /// The loaded engine. Throws unavailable before [load] completed, so
  /// every call fails closed until the engine is in place.
  static Engine get current =>
      _loaded ??
      (throw const Cb2Exception(Cb2Exception.unavailable, 'unavailable'));

  /// Imports the module at [url] and loads its engine, once. Concurrent
  /// calls share one load; a failed load leaves nothing loaded and the
  /// next call tries again.
  static Future<void> load(String url) async {
    if (_loaded != null) {
      return;
    }
    final loading = _loading ??= importEngine(url);
    try {
      _loaded ??= Engine._(await loading);
    } on Object {
      _loading = null;
      rethrow;
    }
  }

  /// Calls [method] of the binding's [area], such as Holder or LocalKey.
  JSAny? call(String area, String method, [List<JSAny?> args = const []]) =>
      invoke(_api[area]! as JSObject, method, args);

  /// Like [call], for a method that returns an object, such as a key.
  JSObject create(String area, String method, [List<JSAny?> args = const []]) =>
      call(area, method, args)! as JSObject;

  /// Calls the top-level function [name] of the binding.
  JSAny? top(String name, [List<JSAny?> args = const []]) =>
      invoke(_api, name, args);
}
