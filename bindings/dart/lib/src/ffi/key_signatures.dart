import 'dart:ffi';

/// Makes a fresh key into the out-parameter.
typedef GenerateNative = Int Function(Pointer<Pointer<Void>> out);

/// Dart side of [GenerateNative].
typedef GenerateDart = int Function(Pointer<Pointer<Void>> out);

/// Makes a key from raw bytes.
typedef FromBytesNative = Int Function(
  Pointer<Uint8> bytes,
  Size len,
  Pointer<Pointer<Void>> out,
);

/// Dart side of [FromBytesNative].
typedef FromBytesDart = int Function(
  Pointer<Uint8> bytes,
  int len,
  Pointer<Pointer<Void>> out,
);

/// Makes a key from text, such as PASERK.
typedef FromTextNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Pointer<Void>> out,
);

/// Dart side of [FromTextNative].
typedef FromTextDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Pointer<Void>> out,
);

/// Returns a text the caller frees, or null.
typedef TextOfNative = Pointer<Char> Function(Pointer<Void> key);

/// Sets the key id of a key.
typedef SetKeyIdNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> id,
  Size len,
);

/// Dart side of [SetKeyIdNative].
typedef SetKeyIdDart = int Function(
  Pointer<Void> key,
  Pointer<Char> id,
  int len,
);

/// Acts on a key or a buffer and returns nothing.
typedef VoidOfNative = Void Function(Pointer<Void> key);

/// Dart side of [VoidOfNative].
typedef VoidOfDart = void Function(Pointer<Void> key);

/// Derives a new key, such as the public half, from a key.
typedef DeriveNative = Int Function(
  Pointer<Void> key,
  Pointer<Pointer<Void>> out,
);

/// Dart side of [DeriveNative].
typedef DeriveDart = int Function(
  Pointer<Void> key,
  Pointer<Pointer<Void>> out,
);
