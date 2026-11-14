import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/rules.dart';
import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/public_key.dart';
import 'package:cb2/src/web/rules_js.dart';
import 'package:cb2/src/web/secret_key.dart';
import 'package:cb2/src/web/values.dart';

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
  }) => textOf(
    Engine.current.call('Token', 'seal', [
      key.handle,
      jsJson(claims),
      jsBytes(implicit),
    ]),
  );

  /// Signs [claims] with [key] as a cb2.public token.
  static String sign(
    SecretKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
  }) => textOf(
    Engine.current.call('Token', 'sign', [
      key.handle,
      jsJson(claims),
      jsBytes(implicit),
    ]),
  );

  /// Opens a cb2.local [token] under [key] and checks it against [rules].
  static Map<String, Object?> open(
    LocalKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => claimsOf(
    Engine.current.call('Token', 'open', [
      token.toJS,
      key.handle,
      rulesObject(rules),
      jsBytes(implicit),
    ]),
  );

  /// Verifies a cb2.public [token] with [key] and checks it against [rules].
  static Map<String, Object?> verify(
    PublicKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
  }) => claimsOf(
    Engine.current.call('Token', 'verify', [
      token.toJS,
      key.handle,
      rulesObject(rules),
      jsBytes(implicit),
    ]),
  );

  /// The key id named by the footer of [token], unverified; null when none.
  static String? peekKeyId(String token) =>
      optionalTextOf(Engine.current.call('Token', 'peekKeyId', [token.toJS]));
}
