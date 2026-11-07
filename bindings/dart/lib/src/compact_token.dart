import 'dart:typed_data';

import 'package:cb2/src/claims_calls.dart';
import 'package:cb2/src/digest_call.dart' as digest;
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/public_key.dart';
import 'package:cb2/src/rules.dart';
import 'package:cb2/src/secret_key.dart';

/// Compact claims tokens, the experimental cb3.local and cb3.public
/// formats: the claims, [Rules] and verdicts of `Token`, with the claims
/// carried as strict CBOR and the key id bound as a [keyDigestBytes]-byte
/// digest, for a token about half the size.
///
/// The issuer refuses with argument what the compact profile cannot carry:
/// a custom number that is not an int64 integer in canonical form (1.5,
/// 1e3, -0), a time outside years 0000 to 9999, and a cnf that is not a
/// kcb2.local or kcb2.public key. A cb2 token never opens here and a
/// compact token never opens through `Token`; either is invalid.
final class CompactToken {
  const CompactToken._();

  /// The size of a key digest in bytes.
  static const int keyDigestBytes = digest.keyDigestBytes;

  /// Seals [claims] under [key] as a cb3.local token.
  static String seal(
    LocalKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) => issueClaims(bindings.compact.seal, key.handle, claims, implicit);

  /// Signs [claims] with [key] as a cb3.public token.
  static String sign(
    SecretKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) => issueClaims(bindings.compact.sign, key.handle, claims, implicit);

  /// Opens a cb3.local [token] under [key] and checks it against [rules].
  static Map<String, Object?> open(
    LocalKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => checkClaims(bindings.compact.open, key.handle, token, rules, implicit);

  /// Verifies a cb3.public [token] with [key] and checks it against
  /// [rules].
  static Map<String, Object?> verify(
    PublicKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) =>
      checkClaims(bindings.compact.verify, key.handle, token, rules, implicit);

  /// The key digest carried by the footer of [token], unverified; null
  /// when it carries none.
  static Uint8List? peekKeyDigest(String token) =>
      digest.digestCall(bindings.compact.peekKeyDigest, token);

  /// The key digest a compact token binds for the key id [id], so a
  /// verifier holding several keys can pick the one whose digest matches
  /// [peekKeyDigest]. An id with control characters is refused with
  /// argument; the empty id is valid.
  static Uint8List keyDigest(String id) =>
      digest.digestCall(bindings.compact.keyDigest, id)!;
}
