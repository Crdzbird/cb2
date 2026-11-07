import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/token_signatures.dart';
import 'package:cb2/src/memory.dart';
import 'package:ffi/ffi.dart';

/// Produces a raw token from [message] through [seal].
String rawSeal(
  RawSealDart seal,
  Pointer<Void> key,
  Uint8List message,
  Uint8List? footer,
  Uint8List? implicit,
) => using((arena) {
  final outToken = arena<Pointer<Char>>();
  final outLen = arena<Size>();
  Cb2Exception.check(
    seal(
      key,
      arenaBytes(arena, message),
      message.length,
      arenaBytes(arena, footer),
      footer?.length ?? 0,
      arenaBytes(arena, implicit),
      implicit?.length ?? 0,
      outToken,
      outLen,
    ),
  );
  return takeText(outToken.value, outLen.value);
});

/// Recovers the message of a raw [token] through [open].
Uint8List rawOpen(
  RawOpenDart open,
  Pointer<Void> key,
  String token,
  Uint8List? footer,
  Uint8List? implicit,
  int maxTokenBytes,
) => using((arena) {
  final outMsg = arena<Pointer<Uint8>>();
  final outLen = arena<Size>();
  Cb2Exception.check(
    open(
      key,
      arenaText(arena, token),
      textLength(token),
      arenaBytes(arena, footer),
      footer?.length ?? 0,
      arenaBytes(arena, implicit),
      implicit?.length ?? 0,
      maxTokenBytes,
      outMsg,
      outLen,
    ),
  );
  return takeBytes(outMsg.value, outLen.value);
});
