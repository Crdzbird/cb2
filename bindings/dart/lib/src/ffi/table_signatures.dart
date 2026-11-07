import 'dart:ffi';

import 'package:cb2/src/ffi/token_signatures.dart';

/// Hands back the digest of a claim table as bytes the caller frees.
typedef TableDigestNative = Int Function(
  Pointer<Void> table,
  Pointer<Pointer<Uint8>> out,
);

/// Dart side of [TableDigestNative].
typedef TableDigestDart = int Function(
  Pointer<Void> table,
  Pointer<Pointer<Uint8>> out,
);

/// Seals or signs a claims JSON object under a claim table.
typedef TableSealNative = Int Function(
  Pointer<Void> key,
  Pointer<Void> table,
  Pointer<Char> claims,
  Size claimsLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Dart side of [TableSealNative].
typedef TableSealDart = int Function(
  Pointer<Void> key,
  Pointer<Void> table,
  Pointer<Char> claims,
  int claimsLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Opens or verifies a claims token under a claim table.
typedef TableOpenNative = Int Function(
  Pointer<Void> key,
  Pointer<Void> table,
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

/// Dart side of [TableOpenNative].
typedef TableOpenDart = int Function(
  Pointer<Void> key,
  Pointer<Void> table,
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
