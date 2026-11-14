@TestOn('browser')
library;

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'support/native.dart';
import 'support/served_engine.dart';
import 'support/verdict.dart';

const _now = 1700000000;
const _target = 'HTTPS://Ojo.Example:443/ojo.v1.AuthService/RefreshTokens';
const _htu = 'https://ojo.example/ojo.v1.AuthService/RefreshTokens';

/// Proofs that cross between implementations at run time, in the shape
/// ojo sends them (htm POST, htu the full gRPC method): one the browser
/// makes opens with the native verifier, and one the native library
/// makes opens in the browser, under the same key, htm, htu and token.
void main() {
  late LocalKey issuer;
  late LocalKey proofKey;
  late String access;

  setUpAll(() async {
    await loadServedEngine();
    issuer = LocalKey.generate();
    proofKey = LocalKey.generate();
    access = Token.seal(issuer, claimsFor(proofKey.toPaserk()));
  });

  Future<Object?> nativeVerdict(
    String proof, {
    String htm = 'POST',
    String htu = _htu,
    int now = _now,
    List<String> seen = const [],
  }) => askNative({
    'op': 'verify',
    'issuerKey': issuer.toPaserk(),
    'token': access,
    'proof': proof,
    'htm': htm,
    'htu': htu,
    'now': now,
    'seen': seen,
  });

  String browserProof(LocalKey key, String jti) => Holder.proveLocal(
    key,
    htm: 'POST',
    htu: Holder.normalizeTarget(_target),
    accessToken: access,
    jti: jti,
    now: _now,
  );

  test('a proof made in the browser opens with the native verifier', () async {
    final key = LocalKey.fromPaserk(proofKey.toPaserk());
    final proof = browserProof(key, 'browser-1');
    key.dispose();
    expect(proof, startsWith('cb2.holder-local.'));
    expect(await nativeVerdict(proof), 'ok');
    expect(await nativeVerdict(proof, htu: _target), 'ok');
    expect(await nativeVerdict(proof, htm: 'GET'), 'proof_mismatch');
    expect(await nativeVerdict(proof, seen: ['browser-1']), 'proof_replayed');
    expect(await nativeVerdict(proof, now: _now + 120), 'proof_expired');
    final forged = browserProof(LocalKey.generate(), 'browser-2');
    expect(await nativeVerdict(forged), 'proof_invalid');
  });

  test('a proof made natively opens in the browser', () async {
    final proof = await askNative({
      'op': 'prove',
      'proofKey': proofKey.toPaserk(),
      'htm': 'POST',
      'htu': _htu,
      'token': access,
      'jti': 'native-1',
      'now': _now,
    });
    String verdict(String htm, {List<String> seen = const []}) => verdictOf(
      () => Token.open(
        issuer,
        access,
        crossRules(
          proof: proof! as String,
          htm: htm,
          htu: _target,
          now: _now,
          seen: seen,
        ),
      ),
    );
    expect(verdict('POST'), 'ok');
    expect(verdict('GET'), 'proof_mismatch');
    expect(verdict('POST', seen: ['native-1']), 'proof_replayed');
  });
}
