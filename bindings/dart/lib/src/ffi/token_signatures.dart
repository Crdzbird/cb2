import 'dart:ffi';

/// The replay callback of the C ABI: 1 accepts the id, 0 refuses it.
typedef ReplayNative = Int Function(
  Pointer<Void> user,
  Pointer<Char> jti,
  Size len,
);

/// Seals or signs raw bytes with a footer and an implicit assertion.
typedef RawSealNative = Int Function(
  Pointer<Void> key,
  Pointer<Uint8> msg,
  Size msgLen,
  Pointer<Uint8> footer,
  Size footerLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Dart side of [RawSealNative].
typedef RawSealDart = int Function(
  Pointer<Void> key,
  Pointer<Uint8> msg,
  int msgLen,
  Pointer<Uint8> footer,
  int footerLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);

/// Opens or verifies a raw token and hands back its message.
typedef RawOpenNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> token,
  Size tokenLen,
  Pointer<Uint8> footer,
  Size footerLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Size maxTokenBytes,
  Pointer<Pointer<Uint8>> outMsg,
  Pointer<Size> outLen,
);

/// Dart side of [RawOpenNative].
typedef RawOpenDart = int Function(
  Pointer<Void> key,
  Pointer<Char> token,
  int tokenLen,
  Pointer<Uint8> footer,
  int footerLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  int maxTokenBytes,
  Pointer<Pointer<Uint8>> outMsg,
  Pointer<Size> outLen,
);

/// Maps a text to a new text the caller frees.
typedef TextToTextNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Pointer<Char>> out,
);

/// Dart side of [TextToTextNative].
typedef TextToTextDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Pointer<Char>> out,
);
