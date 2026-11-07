import 'dart:ffi';

import 'package:cb2/src/ffi/key_signatures.dart';

/// The entry points of one key kind of cb2_c.h, named
/// `cb2_<kind>_generate`, `cb2_<kind>_from_bytes` and so on.
///
/// Every lookup is lazy, so a kind without some entry point, such as a
/// public key without generate, never looks it up.
final class KeyCalls {
  /// The calls of [kind], such as local_key, in [library].
  KeyCalls(this.library, this.kind);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// The key kind as spelled in the C symbols.
  final String kind;

  /// `cb2_<kind>_generate`.
  late final GenerateDart generate = library
      .lookupFunction<GenerateNative, GenerateDart>('cb2_${kind}_generate');

  /// `cb2_<kind>_from_bytes`.
  late final FromBytesDart fromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>('cb2_${kind}_from_bytes');

  /// `cb2_<kind>_from_paserk`.
  late final FromTextDart fromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>('cb2_${kind}_from_paserk');

  /// `cb2_<kind>_to_paserk`.
  late final TextOfNative toPaserk = library
      .lookupFunction<TextOfNative, TextOfNative>('cb2_${kind}_to_paserk');

  /// `cb2_<kind>_paserk_id`.
  late final TextOfNative paserkId = library
      .lookupFunction<TextOfNative, TextOfNative>('cb2_${kind}_paserk_id');

  /// `cb2_<kind>_key_id`.
  late final TextOfNative keyId = library
      .lookupFunction<TextOfNative, TextOfNative>('cb2_${kind}_key_id');

  /// `cb2_<kind>_set_key_id`.
  late final SetKeyIdDart setKeyId = library
      .lookupFunction<SetKeyIdNative, SetKeyIdDart>('cb2_${kind}_set_key_id');

  /// `cb2_<kind>_clear_key_id`.
  late final VoidOfDart clearKeyId = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_${kind}_clear_key_id');

  /// `cb2_<kind>_public_key`.
  late final DeriveDart publicKey = library
      .lookupFunction<DeriveNative, DeriveDart>('cb2_${kind}_public_key');

  /// `cb2_<kind>_free`.
  late final VoidOfDart free = library.lookupFunction<VoidOfNative, VoidOfDart>(
    'cb2_${kind}_free',
  );

  /// `cb2_<kind>_free` as a pointer, for a [NativeFinalizer].
  late final Pointer<NativeFunction<VoidOfNative>> freePointer = library.lookup(
    'cb2_${kind}_free',
  );
}
