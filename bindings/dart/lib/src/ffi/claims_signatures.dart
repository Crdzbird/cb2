import 'dart:ffi';

import 'package:cb2/src/ffi/token_signatures.dart';

/// Seals or signs a claims JSON object.
typedef TokenSealNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> claims,
  Size claimsLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Dart side of [TokenSealNative].
typedef TokenSealDart = int Function(
  Pointer<Void> key,
  Pointer<Char> claims,
  int claimsLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Opens or verifies a claims token against a rules JSON object.
typedef TokenOpenNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> token,
  Size tokenLen,
  Pointer<Char> rules,
  Size rulesLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Pointer<NativeFunction<ReplayNative>> replay,
  Pointer<NativeFunction<ReplayNative>> proofReplay,
  Pointer<Void> user,
  Pointer<Pointer<Char>> outClaims,
  Pointer<Size> outLen,
);

/// Dart side of [TokenOpenNative].
typedef TokenOpenDart = int Function(
  Pointer<Void> key,
  Pointer<Char> token,
  int tokenLen,
  Pointer<Char> rules,
  int rulesLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  Pointer<NativeFunction<ReplayNative>> replay,
  Pointer<NativeFunction<ReplayNative>> proofReplay,
  Pointer<Void> user,
  Pointer<Pointer<Char>> outClaims,
  Pointer<Size> outLen,
);
