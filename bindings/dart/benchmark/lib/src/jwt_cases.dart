import 'dart:convert';
import 'dart:math';

import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/claims.dart';
import 'package:cb2_benchmark/src/es256_keys.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/timing.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

const _library = 'dart_jsonwebtoken 3.4.1 (pure Dart)';

/// JWT HS256 with a random 32-byte secret.
FormatResult benchJwtHs256(BenchSettings settings) {
  final secret = SecretKey(base64Url.encode(_randomBytes()));
  return _bench(settings, 'JWT HS256', JWTAlgorithm.HS256, secret, secret);
}

/// JWT EdDSA (Ed25519) with a random seed.
FormatResult benchJwtEdDsa(BenchSettings settings) {
  final private = EdDSAPrivateKey(_randomBytes());
  final x = private.toJWK()['x'] as String;
  final public = EdDSAPublicKey(base64Url.decode(base64Url.normalize(x)));
  return _bench(settings, 'JWT EdDSA', JWTAlgorithm.EdDSA, private, public);
}

/// JWT ES256 (ECDSA P-256) with a fixed benchmark key pair.
FormatResult benchJwtEs256(BenchSettings settings) => _bench(
  settings,
  'JWT ES256',
  JWTAlgorithm.ES256,
  ECPrivateKey(es256PrivatePem),
  ECPublicKey(es256PublicPem),
);

FormatResult _bench(
  BenchSettings settings,
  String format,
  JWTAlgorithm algorithm,
  JWTKey signKey,
  JWTKey verifyKey,
) {
  String issue() =>
      JWT(numericClaims()).sign(signKey, algorithm: algorithm, noIssueAt: true);
  JWT check(String token) => JWT.verify(
    token,
    verifyKey,
    audience: Audience.one(benchAudience),
    issuer: benchIssuer,
  );
  final token = issue();
  final payload = check(token).payload as Map<String, dynamic>;
  if (payload['role'] != 'reader') {
    throw StateError('$format returned the wrong claims');
  }
  return FormatResult(
    format: format,
    library: _library,
    issueMicros: timeSync(settings, issue),
    checkMicros: timeSync(settings, () => check(token)),
    bytes: token.length,
  );
}

List<int> _randomBytes() {
  final random = Random.secure();
  return List<int>.generate(32, (_) => random.nextInt(256));
}
