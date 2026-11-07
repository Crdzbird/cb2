import 'package:cb2/cb2.dart';
import 'package:cb2_benchmark/src/bench_settings.dart';
import 'package:cb2_benchmark/src/claims.dart';
import 'package:cb2_benchmark/src/format_result.dart';
import 'package:cb2_benchmark/src/timing.dart';

const _rules = Rules(issuer: benchIssuer, audience: benchAudience);

/// cb2.local: seal, then open with the claims checked against the rules.
FormatResult benchCb2Local(BenchSettings settings) {
  final key = LocalKey.generate();
  final claims = textClaims();
  final token = Token.seal(key, claims);
  _expectRole(Token.open(key, token, _rules));
  final result = FormatResult(
    format: 'cb2.local',
    library: 'cb2 ${version()} (native, FFI)',
    issueMicros: timeSync(settings, () => Token.seal(key, claims)),
    checkMicros: timeSync(settings, () => Token.open(key, token, _rules)),
    bytes: token.length,
  );
  key.dispose();
  return result;
}

/// cb2.public: sign, then verify with the claims checked against the
/// rules. Ed25519 and ML-DSA-65 both sign every token.
FormatResult benchCb2Public(BenchSettings settings) {
  final secret = SecretKey.generate();
  final public = secret.publicKey();
  final claims = textClaims();
  final token = Token.sign(secret, claims);
  _expectRole(Token.verify(public, token, _rules));
  final result = FormatResult(
    format: 'cb2.public',
    library: 'cb2 ${version()} (native, FFI)',
    issueMicros: timeSync(settings, () => Token.sign(secret, claims)),
    checkMicros: timeSync(settings, () => Token.verify(public, token, _rules)),
    bytes: token.length,
  );
  public.dispose();
  secret.dispose();
  return result;
}

void _expectRole(Map<String, Object?> claims) {
  if (claims['role'] != 'reader') {
    throw StateError('cb2 returned the wrong claims');
  }
}
