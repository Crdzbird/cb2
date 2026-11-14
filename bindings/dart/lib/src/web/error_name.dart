import 'dart:js_interop';

import 'package:cb2/src/web/engine.dart';

/// The stable name cb2_error_name gives [code], through the loaded
/// engine; unknown before it is loaded.
String errorNameOf(int code) {
  final engine = Engine.loaded;
  if (engine == null) {
    return 'unknown';
  }
  return (engine.top('errorName', [code.toJS])! as JSString).toDart;
}
