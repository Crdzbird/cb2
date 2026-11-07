import 'dart:ffi';

import 'package:cb2/src/ffi/claims_signatures.dart';
import 'package:cb2/src/ffi/token_signatures.dart';

/// The token entry points of cb2_c.h: raw and claims tokens, local and
/// public, and the unverified key id of a footer.
final class TokenCalls {
  /// The calls of [library].
  TokenCalls(this.library);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// cb2_local_seal.
  late final RawSealDart localSeal = library
      .lookupFunction<RawSealNative, RawSealDart>('cb2_local_seal');

  /// cb2_local_open.
  late final RawOpenDart localOpen = library
      .lookupFunction<RawOpenNative, RawOpenDart>('cb2_local_open');

  /// cb2_public_sign.
  late final RawSealDart publicSign = library
      .lookupFunction<RawSealNative, RawSealDart>('cb2_public_sign');

  /// cb2_public_verify.
  late final RawOpenDart publicVerify = library
      .lookupFunction<RawOpenNative, RawOpenDart>('cb2_public_verify');

  /// cb2_token_seal.
  late final TokenSealDart tokenSeal = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_token_seal');

  /// cb2_token_sign.
  late final TokenSealDart tokenSign = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_token_sign');

  /// cb2_token_open.
  late final TokenOpenDart tokenOpen = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_token_open');

  /// cb2_token_verify.
  late final TokenOpenDart tokenVerify = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_token_verify');

  /// cb2_peek_key_id.
  late final TextToTextDart peekKeyId = library
      .lookupFunction<TextToTextNative, TextToTextDart>('cb2_peek_key_id');
}
