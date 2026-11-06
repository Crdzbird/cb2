import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'bindings.dart';
import 'cb2_exception.dart';
import 'memory.dart';

/// Makes a holder proof through [prove] under the key behind [key], for
/// the request [htm] [htu] and [accessToken], identified by [jti], valid
/// from [now] for [lifetime] seconds.
String proveCall(
  ProveDart prove,
  Pointer<Void> key, {
  required String htm,
  required String htu,
  required String accessToken,
  required String jti,
  required int now,
  required String? nonce,
  required int lifetime,
}) => using((arena) {
  final outProof = arena<Pointer<Char>>();
  final outLen = arena<Size>();
  Cb2Exception.check(
    prove(
      key,
      arenaText(arena, htm),
      textLength(htm),
      arenaText(arena, htu),
      textLength(htu),
      arenaText(arena, nonce),
      textLength(nonce),
      arenaText(arena, accessToken),
      textLength(accessToken),
      arenaText(arena, jti),
      textLength(jti),
      now,
      lifetime,
      outProof,
      outLen,
    ),
  );
  return takeText(outProof.value, outLen.value);
});
