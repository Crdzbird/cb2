import 'dart:ffi';
import 'dart:typed_data';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/claims_calls.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/memory.dart';
import 'package:cb2/src/public_key.dart';
import 'package:cb2/src/rules.dart';
import 'package:cb2/src/secret_key.dart';
import 'package:ffi/ffi.dart';

/// Claims tokens: a JSON object of registered and custom claims, sealed
/// or signed, then opened or verified against [Rules].
///
/// Registered times (exp, nbf, iat) are RFC 3339 strings; the key id of
/// the key is bound into the footer.
final class Token {
  const Token._();

  /// Seals [claims] under [key] as a cb2.local token.
  static String seal(
    LocalKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) => issueClaims(bindings.tokens.tokenSeal, key.handle, claims, implicit);

  /// Signs [claims] with [key] as a cb2.public token.
  static String sign(
    SecretKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) => issueClaims(bindings.tokens.tokenSign, key.handle, claims, implicit);

  /// Opens a cb2.local [token] under [key] and checks it against [rules].
  static Map<String, Object?> open(
    LocalKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => checkClaims(
    bindings.tokens.tokenOpen,
    key.handle,
    token,
    rules,
    implicit,
  );

  /// Verifies a cb2.public [token] with [key] and checks it against [rules].
  static Map<String, Object?> verify(
    PublicKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => checkClaims(
    bindings.tokens.tokenVerify,
    key.handle,
    token,
    rules,
    implicit,
  );

  /// The key id named by the footer of [token], unverified; null when none.
  static String? peekKeyId(String token) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(
      bindings.tokens.peekKeyId(
        arenaText(arena, token),
        textLength(token),
        out,
      ),
    );
    return takeOptionalText(out.value);
  });
}
