import 'dart:js_interop';

import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/values.dart';

/// The version string of the loaded cb2 engine.
String version() => textOf(Engine.current.top('version'));

/// Whether the loaded engine was built with cb2.public (liboqs).
bool hasPublic() => (Engine.current.top('hasPublic')! as JSBoolean).toDart;

/// Whether the loaded engine was built with kcb2.seal.
bool hasSeal() => (Engine.current.top('hasSeal')! as JSBoolean).toDart;
