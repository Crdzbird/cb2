import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/web/guard.dart';
import 'package:cb2/src/web/values.dart';

/// A key or table object of the JavaScript binding, owned by one Dart
/// object: freed by [dispose], or by a finalizer once its owner is
/// unreachable, as the native handles are.
final class JsHandle {
  /// Takes ownership of [object], a [kind] such as LocalKey.
  JsHandle(this.kind, JSObject object) : _object = object {
    _finalizer.attach(this, object, detach: this);
  }

  static final Finalizer<JSObject> _finalizer = Finalizer(
    (object) => object.callMethod<JSAny?>('free'.toJS),
  );

  /// The name of the class this handle belongs to, for messages.
  final String kind;

  JSObject? _object;

  /// The JavaScript object; throws once [dispose] has run.
  JSObject get object =>
      _object ?? (throw StateError('$kind used after dispose'));

  /// Calls [method] of the object with [args].
  JSAny? call(String method, [List<JSAny?> args = const []]) =>
      invoke(object, method, args);

  /// The text [method] returns.
  String text(String method) => textOf(call(method));

  /// The key id of a key that carries one, null once cleared.
  String? get keyId => optionalTextOf(guarded(() => object['keyId']));

  /// Sets the key id to [id], or clears it when [id] is null.
  void setKeyId(String? id) {
    if (id == null) {
      call('clearKeyId');
      return;
    }
    call('setKeyId', [id.toJS]);
  }

  /// Frees the object now instead of at garbage collection.
  void dispose() {
    final object = _object;
    if (object == null) {
      return;
    }
    _finalizer.detach(this);
    object.callMethod<JSAny?>('free'.toJS);
    _object = null;
  }
}
