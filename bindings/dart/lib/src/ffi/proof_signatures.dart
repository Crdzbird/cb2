import 'dart:ffi';

/// Makes a holder proof for one request and one access token.
typedef ProveNative = Int Function(
  Pointer<Void> client,
  Pointer<Char> htm,
  Size htmLen,
  Pointer<Char> htu,
  Size htuLen,
  Pointer<Char> nonce,
  Size nonceLen,
  Pointer<Char> access,
  Size accessLen,
  Pointer<Char> jti,
  Size jtiLen,
  Int64 now,
  Int64 lifetime,
  Pointer<Pointer<Char>> outProof,
  Pointer<Size> outLen,
);

/// Dart side of [ProveNative].
typedef ProveDart = int Function(
  Pointer<Void> client,
  Pointer<Char> htm,
  int htmLen,
  Pointer<Char> htu,
  int htuLen,
  Pointer<Char> nonce,
  int nonceLen,
  Pointer<Char> access,
  int accessLen,
  Pointer<Char> jti,
  int jtiLen,
  int now,
  int lifetime,
  Pointer<Pointer<Char>> outProof,
  Pointer<Size> outLen,
);

/// Wraps or seals a key under another key.
typedef WrapNative = Int Function(
  Pointer<Void> by,
  Pointer<Void> key,
  Pointer<Pointer<Char>> out,
);

/// Dart side of [WrapNative].
typedef WrapDart = int Function(
  Pointer<Void> by,
  Pointer<Void> key,
  Pointer<Pointer<Char>> out,
);

/// Unwraps or unseals a key from its text with another key.
typedef UnwrapNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Void> by,
  Pointer<Pointer<Void>> out,
);

/// Dart side of [UnwrapNative].
typedef UnwrapDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Void> by,
  Pointer<Pointer<Void>> out,
);
