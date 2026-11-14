import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cb2/src/rules.dart';
import 'package:cb2/src/web/claim_table.dart';
import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/public_key.dart';
import 'package:cb2/src/web/rules_js.dart';
import 'package:cb2/src/web/secret_key.dart';
import 'package:cb2/src/web/values.dart';

/// Compact claims tokens, the experimental cb3.local and cb3.public
/// formats: the claims, [Rules] and verdicts of `Token`, with the claims
/// carried as strict CBOR and the key id bound as a [keyDigestBytes]-byte
/// digest. Each call takes an optional [ClaimTable]; a token made under a
/// table opens only under that same table.
final class CompactToken {
  const CompactToken._();

  /// The size of a key digest in bytes.
  static const int keyDigestBytes = 16;

  /// Seals [claims] under [key] as a cb3.local token.
  static String seal(
    LocalKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
    ClaimTable? table,
  }) => textOf(
    _call('seal', [key.handle, jsJson(claims), jsBytes(implicit)], table),
  );

  /// Signs [claims] with [key] as a cb3.public token.
  static String sign(
    SecretKey key,
    Map<String, Object?> claims, {
    Uint8List? implicit,
    ClaimTable? table,
  }) => textOf(
    _call('sign', [key.handle, jsJson(claims), jsBytes(implicit)], table),
  );

  /// Opens a cb3.local [token] under [key] and checks it against [rules].
  static Map<String, Object?> open(
    LocalKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
    ClaimTable? table,
  }) => claimsOf(
    _call('open', [
      token.toJS,
      key.handle,
      rulesObject(rules),
      jsBytes(implicit),
    ], table),
  );

  /// Verifies a cb3.public [token] with [key] and checks it against
  /// [rules].
  static Map<String, Object?> verify(
    PublicKey key,
    String token,
    Rules rules, {
    Uint8List? implicit,
    ClaimTable? table,
  }) => claimsOf(
    _call('verify', [
      token.toJS,
      key.handle,
      rulesObject(rules),
      jsBytes(implicit),
    ], table),
  );

  /// The key digest carried by the footer of [token], unverified; null
  /// when it carries none.
  static Uint8List? peekKeyDigest(String token) => optionalBytesOf(
    Engine.current.call('Compact', 'peekKeyDigest', [token.toJS]),
  );

  /// The key digest a compact token binds for the key id [id].
  static Uint8List keyDigest(String id) =>
      bytesOf(Engine.current.call('Compact', 'keyDigest', [id.toJS]));

  static JSAny? _call(String method, List<JSAny?> args, ClaimTable? table) =>
      Engine.current.call('Compact', method, [...args, table?.handle]);
}
