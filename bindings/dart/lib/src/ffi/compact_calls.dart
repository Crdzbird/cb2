import 'dart:ffi';

import 'package:cb2/src/ffi/claims_signatures.dart';
import 'package:cb2/src/ffi/digest_signatures.dart';

/// The compact claims token entry points of cb2_c.h: cb3.local and
/// cb3.public, and the key digest of a footer.
final class CompactCalls {
  /// The calls of [library].
  CompactCalls(this.library);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// cb2_compact_seal.
  late final TokenSealDart seal = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_compact_seal');

  /// cb2_compact_sign.
  late final TokenSealDart sign = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_compact_sign');

  /// cb2_compact_open.
  late final TokenOpenDart open = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_compact_open');

  /// cb2_compact_verify.
  late final TokenOpenDart verify = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_compact_verify');

  /// cb2_compact_peek_key_digest.
  late final TextToBytesDart peekKeyDigest = library
      .lookupFunction<TextToBytesNative, TextToBytesDart>(
        'cb2_compact_peek_key_digest',
      );

  /// cb2_compact_key_digest.
  late final TextToBytesDart keyDigest = library
      .lookupFunction<TextToBytesNative, TextToBytesDart>(
        'cb2_compact_key_digest',
      );
}
