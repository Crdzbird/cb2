import 'dart:convert';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

/// The text a call returned.
String textOf(JSAny? value) => (value! as JSString).toDart;

/// The text a call returned, or null when it returned none.
String? optionalTextOf(JSAny? value) {
  if (value == null || value.isUndefinedOrNull) {
    return null;
  }
  return textOf(value);
}

/// The bytes a call returned, copied out of the JavaScript array.
Uint8List bytesOf(JSAny? value) =>
    Uint8List.fromList((value! as JSUint8Array).toDart);

/// The bytes a call returned, or null when it returned none.
Uint8List? optionalBytesOf(JSAny? value) {
  if (value == null || value.isUndefinedOrNull) {
    return null;
  }
  return bytesOf(value);
}

/// [bytes] for an argument; null stands for none, as on the native side.
JSUint8Array? jsBytes(Uint8List? bytes) => bytes?.toJS;

JSObject get _json => globalContext['JSON']! as JSObject;

/// [value] as a JavaScript value, through JSON, so numbers, strings,
/// lists and maps arrive as the binding's JSON.stringify expects them.
JSAny jsJson(Object? value) =>
    _json.callMethod<JSAny>('parse'.toJS, jsonEncode(value).toJS);

/// The claims object a call returned, through JSON, so integers come back
/// as int and the map has the shape the native side returns.
Map<String, Object?> claimsOf(JSAny? value) {
  final text = _json.callMethod<JSString>('stringify'.toJS, value);
  return jsonDecode(text.toDart) as Map<String, Object?>;
}
