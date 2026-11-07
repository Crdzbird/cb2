import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/digest_signatures.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// The size of a key digest in bytes, CB2_KEY_DIGEST_BYTES of cb2_c.h.
const int keyDigestBytes = 16;

/// Runs [call] on [text] and takes the key digest it hands back; null when
/// it hands back none.
Uint8List? digestCall(TextToBytesDart call, String text) => using((arena) {
  final out = arena<Pointer<Uint8>>();
  Cb2Exception.check(call(arenaText(arena, text), textLength(text), out));
  if (out.value == nullptr) {
    return null;
  }
  return takeBytes(out.value, keyDigestBytes);
});
