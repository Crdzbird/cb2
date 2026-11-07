import 'package:cb2/cb2.dart';
import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/claims.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/timing.dart';

const _rules = Rules(issuer: benchIssuer, audience: benchAudience);

/// cb3.local, the compact form of cb2.local: seal, then open with the
/// claims checked against the rules.
FormatResult benchCompactLocal(BenchSettings settings) {
  final key = LocalKey.generate();
  final claims = textClaims();
  final token = CompactToken.seal(key, claims);
  _expectRole(CompactToken.open(key, token, _rules));
  final result = FormatResult(
    format: 'cb3.local',
    library: 'cb2 ${version()} (native, FFI)',
    issueMicros: timeSync(settings, () => CompactToken.seal(key, claims)),
    checkMicros: timeSync(
      settings,
      () => CompactToken.open(key, token, _rules),
    ),
    bytes: token.length,
  );
  key.dispose();
  return result;
}

/// cb3.public, the compact form of cb2.public: sign, then verify with the
/// claims checked against the rules.
FormatResult benchCompactPublic(BenchSettings settings) {
  final secret = SecretKey.generate();
  final public = secret.publicKey();
  final claims = textClaims();
  final token = CompactToken.sign(secret, claims);
  _expectRole(CompactToken.verify(public, token, _rules));
  final result = FormatResult(
    format: 'cb3.public',
    library: 'cb2 ${version()} (native, FFI)',
    issueMicros: timeSync(settings, () => CompactToken.sign(secret, claims)),
    checkMicros: timeSync(
      settings,
      () => CompactToken.verify(public, token, _rules),
    ),
    bytes: token.length,
  );
  public.dispose();
  secret.dispose();
  return result;
}

void _expectRole(Map<String, Object?> claims) {
  if (claims['role'] != 'reader') {
    throw StateError('cb2 returned the wrong compact claims');
  }
}
