import 'dart:ffi';

/// Maps a text to bytes the caller frees, or to null for none.
typedef TextToBytesNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Pointer<Uint8>> out,
);

/// Dart side of [TextToBytesNative].
typedef TextToBytesDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Pointer<Uint8>> out,
);
