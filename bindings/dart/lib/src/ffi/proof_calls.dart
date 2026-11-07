import 'dart:ffi';

import 'package:cb2/src/ffi/proof_signatures.dart';
import 'package:cb2/src/ffi/token_signatures.dart';

/// The holder proof and key transport entry points of cb2_c.h.
final class ProofCalls {
  /// The calls of [library].
  ProofCalls(this.library);

  /// The opened cb2 C library.
  final DynamicLibrary library;

  /// cb2_holder_prove.
  late final ProveDart holderProve = library
      .lookupFunction<ProveNative, ProveDart>('cb2_holder_prove');

  /// cb2_holder_prove_local.
  late final ProveDart holderProveLocal = library
      .lookupFunction<ProveNative, ProveDart>('cb2_holder_prove_local');

  /// cb2_holder_normalize_target.
  late final TextToTextDart holderNormalizeTarget = library
      .lookupFunction<TextToTextNative, TextToTextDart>(
        'cb2_holder_normalize_target',
      );

  /// cb2_wrap.
  late final WrapDart wrap = library.lookupFunction<WrapNative, WrapDart>(
    'cb2_wrap',
  );

  /// cb2_unwrap.
  late final UnwrapDart unwrap = library
      .lookupFunction<UnwrapNative, UnwrapDart>('cb2_unwrap');

  /// cb2_seal.
  late final WrapDart seal = library.lookupFunction<WrapNative, WrapDart>(
    'cb2_seal',
  );

  /// cb2_unseal.
  late final UnwrapDart unseal = library
      .lookupFunction<UnwrapNative, UnwrapDart>('cb2_unseal');
}
