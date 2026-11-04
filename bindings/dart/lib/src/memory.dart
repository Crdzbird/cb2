import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';

/// Copies [bytes] into [arena]; the null pointer stands for no bytes.
Pointer<Uint8> arenaBytes(Arena arena, Uint8List? bytes) {
  if (bytes == null || bytes.isEmpty) {
    return nullptr;
  }
  final Pointer<Uint8> out = arena<Uint8>(bytes.length);
  out.asTypedList(bytes.length).setAll(0, bytes);
  return out;
}

/// Encodes [text] as UTF-8 into [arena]; the null pointer stands for none.
Pointer<Char> arenaText(Arena arena, String? text) {
  if (text == null) {
    return nullptr;
  }
  return arenaBytes(arena, utf8.encode(text)).cast<Char>();
}

/// The UTF-8 length of [text], zero for none.
int textLength(String? text) => text == null ? 0 : utf8.encode(text).length;

/// Takes a text result of the library: decodes it and frees it.
String takeText(Pointer<Char> text, [int? length]) {
  final decoded = readText(text, length);
  Cb2Library.bindings.free(text.cast<Void>());
  return decoded;
}

/// Takes a text result that carries key material: decodes, wipes, frees.
String takeSecretText(Pointer<Char> text) {
  final decoded = readText(text, null);
  Cb2Library.bindings.freeSecret(text);
  return decoded;
}

/// Takes an optional text result; null stays null.
String? takeOptionalText(Pointer<Char> text) {
  if (text == nullptr) {
    return null;
  }
  return takeText(text);
}

/// Takes a byte result of the library: copies it out and frees it.
Uint8List takeBytes(Pointer<Uint8> bytes, int length) {
  final copy = Uint8List.fromList(bytes.asTypedList(length));
  Cb2Library.bindings.free(bytes.cast<Void>());
  return copy;
}

/// Decodes a NUL-terminated UTF-8 string, or [length] bytes when given.
String readText(Pointer<Char> text, int? length) {
  if (length == null) {
    return text.cast<Utf8>().toDartString();
  }
  return utf8.decode(text.cast<Uint8>().asTypedList(length));
}

/// Runs [call] with a fresh out-parameter for a key handle, checks its
/// code, and returns the handle it produced.
Pointer<Void> takeHandle(
  int Function(Arena arena, Pointer<Pointer<Void>> out) call,
) => using((arena) {
  final out = arena<Pointer<Void>>();
  Cb2Exception.check(call(arena, out));
  return out.value;
});
