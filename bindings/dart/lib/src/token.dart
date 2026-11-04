import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'claims_calls.dart';
import 'library.dart';
import 'local_key.dart';
import 'memory.dart';
import 'public_key.dart';
import 'rules.dart';
import 'secret_key.dart';

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
  }) =>
      issueClaims(Cb2Library.bindings.tokenSeal, key.handle, claims, implicit);

  /// Signs [claims] with [key] as a cb2.public token.
  static String sign(
    SecretKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) =>
      issueClaims(Cb2Library.bindings.tokenSign, key.handle, claims, implicit);

  /// Opens a cb2.local [token] under [key] and checks it against [rules].
  static Map<String, Object?> open(
    LocalKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => checkClaims(
    Cb2Library.bindings.tokenOpen,
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
    Cb2Library.bindings.tokenVerify,
    key.handle,
    token,
    rules,
    implicit,
  );

  /// The key id named by the footer of [token], unverified; null when none.
  static String? peekKeyId(String token) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(
      Cb2Library.bindings.peekKeyId(
        arenaText(arena, token),
        textLength(token),
        out,
      ),
    );
    return takeOptionalText(out.value);
  });
}
