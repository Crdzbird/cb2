import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/cb2_exception.dart';

/// Calls [method] of [target] with [args] through [guarded].
JSAny? invoke(JSObject target, String method, [List<JSAny?> args = const []]) =>
    guarded(() => target.callMethodVarArgs<JSAny?>(method.toJS, args));

/// Runs [body] and turns a Cb2Error thrown by the JavaScript binding into
/// the [Cb2Exception] the native side throws for the same verdict.
T guarded<T>(T Function() body) {
  try {
    return body();
  } on Object catch (error, stack) {
    final verdict = verdictOf(error);
    if (verdict == null) {
      rethrow;
    }
    Error.throwWithStackTrace(verdict, stack);
  }
}

/// The [Cb2Exception] for [error] when it is a Cb2Error of the binding:
/// an object with a numeric code and a string name. Null otherwise.
Cb2Exception? verdictOf(Object error) {
  if (!error.isA<JSObject>()) {
    return null;
  }
  final object = error as JSObject;
  final code = object['code'];
  final name = object['name'];
  if (!code.isA<JSNumber>() || !name.isA<JSString>()) {
    return null;
  }
  return Cb2Exception(
    (code! as JSNumber).toDartInt,
    (name! as JSString).toDart,
  );
}
