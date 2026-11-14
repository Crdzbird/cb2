import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:cb2/src/replay_check.dart';
import 'package:cb2/src/rules.dart';
import 'package:cb2/src/rules_json.dart';
import 'package:cb2/src/web/values.dart';

/// [rules] as the JavaScript binding takes them: the rules JSON of
/// cb2_c.h that the native side sends, with the replay check of the token
/// as replay and that of the proof as proofReplay, both run by the
/// library for the length of the call. A check that throws refuses.
JSObject rulesObject(Rules rules) {
  final object = jsJson(rules.toJson()) as JSObject;
  if (rules.replay case final ReplayCheck check) {
    object['replay'] = _replay(check);
  }
  if (rules.holder?.replay case final ReplayCheck check) {
    object['proofReplay'] = _replay(check);
  }
  return object;
}

JSFunction _replay(ReplayCheck check) =>
    ((JSString jti) => check(jti.toDart).toJS).toJS;
