import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart';
import 'cb2_exception.dart';
import 'memory.dart';
import 'replay_bridge.dart';
import 'rules.dart';

/// Issues a claims token from [claims] through [issue].
String issueClaims(
  TokenSealDart issue,
  Pointer<Void> key,
  Map<String, Object?> claims,
  Uint8List? implicit,
) => using((arena) {
  final json = jsonEncode(claims);
  final outToken = arena<Pointer<Char>>();
  final outLen = arena<Size>();
  Cb2Exception.check(
    issue(
      key,
      arenaText(arena, json),
      textLength(json),
      arenaBytes(arena, implicit),
      implicit?.length ?? 0,
      outToken,
      outLen,
    ),
  );
  return takeText(outToken.value, outLen.value);
});

/// Checks [token] against [rules] through [check] and returns its claims.
/// Both callbacks are bridged for the call and closed afterwards.
Map<String, Object?> checkClaims(
  TokenOpenDart check,
  Pointer<Void> key,
  String token,
  Rules rules,
  Uint8List? implicit,
) {
  final replay = ReplayBridge.of(rules.replay);
  final proofReplay = ReplayBridge.of(rules.proofReplay);
  try {
    return using((arena) {
      final json = jsonEncode(rules.toJson());
      final outClaims = arena<Pointer<Char>>();
      final outLen = arena<Size>();
      Cb2Exception.check(
        check(
          key,
          arenaText(arena, token),
          textLength(token),
          arenaText(arena, json),
          textLength(json),
          arenaBytes(arena, implicit),
          implicit?.length ?? 0,
          replay.pointer,
          proofReplay.pointer,
          nullptr,
          outClaims,
          outLen,
        ),
      );
      final text = takeText(outClaims.value, outLen.value);
      return (jsonDecode(text) as Map).cast<String, Object?>();
    });
  } finally {
    replay.close();
    proofReplay.close();
  }
}
