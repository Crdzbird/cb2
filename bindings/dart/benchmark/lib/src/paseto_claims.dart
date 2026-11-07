import 'package:cb2_benchmark/src/claims.dart';

/// Validates decoded PASETO claims the way cb2 and JWT verification do:
/// issuer, audience, and expiry and issue time against the clock.
/// paseto_dart checks only the cryptography, so this is the claims step
/// a caller must add.
Map<String, dynamic> checkPasetoClaims(Map<String, dynamic> claims) {
  final now = DateTime.now().toUtc();
  final exp = DateTime.parse(claims['exp'] as String);
  final iat = DateTime.parse(claims['iat'] as String);
  final valid =
      claims['iss'] == benchIssuer &&
      claims['aud'] == benchAudience &&
      now.isBefore(exp) &&
      !now.isBefore(iat);
  if (!valid) {
    throw StateError('PASETO claims refused');
  }
  return claims;
}
