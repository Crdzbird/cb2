import 'dart:ffi';

import 'package:cb2/src/ffi/compact_calls.dart';
import 'package:cb2/src/ffi/core_calls.dart';
import 'package:cb2/src/ffi/key_calls.dart';
import 'package:cb2/src/ffi/proof_calls.dart';
import 'package:cb2/src/ffi/token_calls.dart';

/// Every entry point of cb2_c.h, looked up lazily from a [DynamicLibrary]
/// and grouped by area.
///
/// Opaque key handles are plain [Pointer]s of [Void]; the public API gives
/// them their types.
final class Cb2Bindings {
  /// The entry points of [library].
  Cb2Bindings(DynamicLibrary library)
    : core = CoreCalls(library),
      localKey = KeyCalls(library, 'local_key'),
      secretKey = KeyCalls(library, 'secret_key'),
      publicKey = KeyCalls(library, 'public_key'),
      recipientKey = KeyCalls(library, 'recipient_key'),
      recipientPublicKey = KeyCalls(library, 'recipient_public_key'),
      tokens = TokenCalls(library),
      compact = CompactCalls(library),
      proofs = ProofCalls(library);

  /// Version, features, error names and buffer release.
  final CoreCalls core;

  /// kcb2.local keys.
  final KeyCalls localKey;

  /// kcb2.secret signing pairs.
  final KeyCalls secretKey;

  /// kcb2.public verifying keys.
  final KeyCalls publicKey;

  /// kcb2.seal recipient pairs.
  final KeyCalls recipientKey;

  /// kcb2.seal recipient public keys.
  final KeyCalls recipientPublicKey;

  /// Raw and claims tokens.
  final TokenCalls tokens;

  /// Compact claims tokens and key digests.
  final CompactCalls compact;

  /// Holder proofs, key wrapping and sealing.
  final ProofCalls proofs;
}
