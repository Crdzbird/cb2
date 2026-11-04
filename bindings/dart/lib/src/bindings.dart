import 'dart:ffi';

/// The replay callback of the C ABI: 1 accepts the id, 0 refuses it.
typedef ReplayNative = Int Function(
  Pointer<Void> user,
  Pointer<Char> jti,
  Size len,
);

typedef GenerateNative = Int Function(Pointer<Pointer<Void>> out);
typedef GenerateDart = int Function(Pointer<Pointer<Void>> out);
typedef FromBytesNative = Int Function(
  Pointer<Uint8> bytes,
  Size len,
  Pointer<Pointer<Void>> out,
);
typedef FromBytesDart = int Function(
  Pointer<Uint8> bytes,
  int len,
  Pointer<Pointer<Void>> out,
);
typedef FromTextNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Pointer<Void>> out,
);
typedef FromTextDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Pointer<Void>> out,
);
typedef TextOfNative = Pointer<Char> Function(Pointer<Void> key);
typedef TextOfDart = Pointer<Char> Function(Pointer<Void> key);
typedef SetKeyIdNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> id,
  Size len,
);
typedef SetKeyIdDart = int Function(
  Pointer<Void> key,
  Pointer<Char> id,
  int len,
);
typedef VoidOfNative = Void Function(Pointer<Void> key);
typedef VoidOfDart = void Function(Pointer<Void> key);
typedef DeriveNative = Int Function(
  Pointer<Void> key,
  Pointer<Pointer<Void>> out,
);
typedef DeriveDart = int Function(
  Pointer<Void> key,
  Pointer<Pointer<Void>> out,
);
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
typedef TokenSealNative = Int Function(
  Pointer<Void> key,
  Pointer<Char> claims,
  Size claimsLen,
  Pointer<Uint8> implicit,
  Size implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);
typedef TokenSealDart = int Function(
  Pointer<Void> key,
  Pointer<Char> claims,
  int claimsLen,
  Pointer<Uint8> implicit,
  int implicitLen,
  Pointer<Pointer<Char>> outToken,
  Pointer<Size> outLen,
);
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
typedef TextToTextNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Pointer<Char>> out,
);
typedef TextToTextDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Pointer<Char>> out,
);
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
typedef WrapNative = Int Function(
  Pointer<Void> by,
  Pointer<Void> key,
  Pointer<Pointer<Char>> out,
);
typedef WrapDart = int Function(
  Pointer<Void> by,
  Pointer<Void> key,
  Pointer<Pointer<Char>> out,
);
typedef UnwrapNative = Int Function(
  Pointer<Char> text,
  Size len,
  Pointer<Void> by,
  Pointer<Pointer<Void>> out,
);
typedef UnwrapDart = int Function(
  Pointer<Char> text,
  int len,
  Pointer<Void> by,
  Pointer<Pointer<Void>> out,
);

/// Every entry point of cb2_c.h, looked up once from a [DynamicLibrary].
///
/// Opaque key handles are plain [Pointer]s of [Void]; the public API gives
/// them their types. This file is the one file of the package allowed to
/// exceed the hundred-line rule, since the signatures cannot be split
/// without scattering the ABI over several lookups.
final class Cb2Bindings {
  Cb2Bindings(this.library);

  final DynamicLibrary library;

  late final Pointer<Char> Function() version = library
      .lookupFunction<Pointer<Char> Function(), Pointer<Char> Function()>(
        'cb2_version',
      );
  late final int Function() hasPublic = library
      .lookupFunction<Int Function(), int Function()>('cb2_has_public');
  late final int Function() hasSeal = library
      .lookupFunction<Int Function(), int Function()>('cb2_has_seal');
  late final Pointer<Char> Function(int) errorName = library
      .lookupFunction<Pointer<Char> Function(Int), Pointer<Char> Function(int)>(
        'cb2_error_name',
      );
  late final void Function(Pointer<Void>) free = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_free');
  late final void Function(Pointer<Char>) freeSecret = library
      .lookupFunction<
        Void Function(Pointer<Char>),
        void Function(Pointer<Char>)
      >('cb2_free_secret');

  late final GenerateDart localKeyGenerate = library
      .lookupFunction<GenerateNative, GenerateDart>('cb2_local_key_generate');
  late final FromBytesDart localKeyFromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>(
        'cb2_local_key_from_bytes',
      );
  late final FromTextDart localKeyFromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_local_key_from_paserk',
      );
  late final TextOfDart localKeyToPaserk = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_local_key_to_paserk');
  late final TextOfDart localKeyPaserkId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_local_key_paserk_id');
  late final TextOfDart localKeyKeyId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_local_key_key_id');
  late final SetKeyIdDart localKeySetKeyId = library
      .lookupFunction<SetKeyIdNative, SetKeyIdDart>('cb2_local_key_set_key_id');
  late final VoidOfDart localKeyClearKeyId = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_local_key_clear_key_id');
  late final VoidOfDart localKeyFree = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_local_key_free');
  late final Pointer<NativeFunction<VoidOfNative>> localKeyFreePointer = library
      .lookup('cb2_local_key_free');

  late final GenerateDart secretKeyGenerate = library
      .lookupFunction<GenerateNative, GenerateDart>('cb2_secret_key_generate');
  late final FromBytesDart secretKeyFromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>(
        'cb2_secret_key_from_bytes',
      );
  late final FromTextDart secretKeyFromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_secret_key_from_paserk',
      );
  late final TextOfDart secretKeyToPaserk = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_secret_key_to_paserk');
  late final DeriveDart secretKeyPublicKey = library
      .lookupFunction<DeriveNative, DeriveDart>('cb2_secret_key_public_key');
  late final TextOfDart secretKeyKeyId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_secret_key_key_id');
  late final SetKeyIdDart secretKeySetKeyId = library
      .lookupFunction<SetKeyIdNative, SetKeyIdDart>(
        'cb2_secret_key_set_key_id',
      );
  late final VoidOfDart secretKeyClearKeyId = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_secret_key_clear_key_id');
  late final VoidOfDart secretKeyFree = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_secret_key_free');
  late final Pointer<NativeFunction<VoidOfNative>> secretKeyFreePointer =
      library.lookup('cb2_secret_key_free');

  late final FromBytesDart publicKeyFromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>(
        'cb2_public_key_from_bytes',
      );
  late final FromTextDart publicKeyFromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_public_key_from_paserk',
      );
  late final TextOfDart publicKeyToPaserk = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_public_key_to_paserk');
  late final TextOfDart publicKeyPaserkId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_public_key_paserk_id');
  late final TextOfDart publicKeyKeyId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_public_key_key_id');
  late final SetKeyIdDart publicKeySetKeyId = library
      .lookupFunction<SetKeyIdNative, SetKeyIdDart>(
        'cb2_public_key_set_key_id',
      );
  late final VoidOfDart publicKeyClearKeyId = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_public_key_clear_key_id');
  late final VoidOfDart publicKeyFree = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_public_key_free');
  late final Pointer<NativeFunction<VoidOfNative>> publicKeyFreePointer =
      library.lookup('cb2_public_key_free');

  late final GenerateDart recipientKeyGenerate = library
      .lookupFunction<GenerateNative, GenerateDart>(
        'cb2_recipient_key_generate',
      );
  late final FromBytesDart recipientKeyFromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>(
        'cb2_recipient_key_from_bytes',
      );
  late final FromTextDart recipientKeyFromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_recipient_key_from_paserk',
      );
  late final TextOfDart recipientKeyToPaserk = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_recipient_key_to_paserk');
  late final DeriveDart recipientKeyPublicKey = library
      .lookupFunction<DeriveNative, DeriveDart>('cb2_recipient_key_public_key');
  late final TextOfDart recipientKeyPaserkId = library
      .lookupFunction<TextOfNative, TextOfDart>('cb2_recipient_key_paserk_id');
  late final VoidOfDart recipientKeyFree = library
      .lookupFunction<VoidOfNative, VoidOfDart>('cb2_recipient_key_free');
  late final Pointer<NativeFunction<VoidOfNative>> recipientKeyFreePointer =
      library.lookup('cb2_recipient_key_free');

  late final FromBytesDart recipientPublicKeyFromBytes = library
      .lookupFunction<FromBytesNative, FromBytesDart>(
        'cb2_recipient_public_key_from_bytes',
      );
  late final FromTextDart recipientPublicKeyFromPaserk = library
      .lookupFunction<FromTextNative, FromTextDart>(
        'cb2_recipient_public_key_from_paserk',
      );
  late final TextOfDart recipientPublicKeyToPaserk = library
      .lookupFunction<TextOfNative, TextOfDart>(
        'cb2_recipient_public_key_to_paserk',
      );
  late final TextOfDart recipientPublicKeyPaserkId = library
      .lookupFunction<TextOfNative, TextOfDart>(
        'cb2_recipient_public_key_paserk_id',
      );
  late final VoidOfDart recipientPublicKeyFree = library
      .lookupFunction<VoidOfNative, VoidOfDart>(
        'cb2_recipient_public_key_free',
      );
  late final Pointer<NativeFunction<VoidOfNative>>
  recipientPublicKeyFreePointer = library.lookup(
    'cb2_recipient_public_key_free',
  );

  late final RawSealDart localSeal = library
      .lookupFunction<RawSealNative, RawSealDart>('cb2_local_seal');
  late final RawOpenDart localOpen = library
      .lookupFunction<RawOpenNative, RawOpenDart>('cb2_local_open');
  late final RawSealDart publicSign = library
      .lookupFunction<RawSealNative, RawSealDart>('cb2_public_sign');
  late final RawOpenDart publicVerify = library
      .lookupFunction<RawOpenNative, RawOpenDart>('cb2_public_verify');

  late final TokenSealDart tokenSeal = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_token_seal');
  late final TokenSealDart tokenSign = library
      .lookupFunction<TokenSealNative, TokenSealDart>('cb2_token_sign');
  late final TokenOpenDart tokenOpen = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_token_open');
  late final TokenOpenDart tokenVerify = library
      .lookupFunction<TokenOpenNative, TokenOpenDart>('cb2_token_verify');
  late final TextToTextDart peekKeyId = library
      .lookupFunction<TextToTextNative, TextToTextDart>('cb2_peek_key_id');

  late final ProveDart holderProve = library
      .lookupFunction<ProveNative, ProveDart>('cb2_holder_prove');
  late final TextToTextDart holderNormalizeTarget = library
      .lookupFunction<TextToTextNative, TextToTextDart>(
        'cb2_holder_normalize_target',
      );

  late final WrapDart wrap = library.lookupFunction<WrapNative, WrapDart>(
    'cb2_wrap',
  );
  late final UnwrapDart unwrap = library
      .lookupFunction<UnwrapNative, UnwrapDart>('cb2_unwrap');
  late final WrapDart seal = library.lookupFunction<WrapNative, WrapDart>(
    'cb2_seal',
  );
  late final UnwrapDart unseal = library
      .lookupFunction<UnwrapNative, UnwrapDart>('cb2_unseal');
}
