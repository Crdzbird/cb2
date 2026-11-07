import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('a compact token bound to a local proof key needs its proof', () {
    final k = LocalKey.generate();
    final cnf = LocalKey.generate().toPaserk();
    final access = CompactToken.seal(k, {
      'iss': issuer,
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
      'cnf': cnf,
    });
    expect(access, startsWith('cb3.local.'));
    expect(() => CompactToken.open(k, access, rules), verdict('missing_proof'));
    final proof = Holder.proveLocal(
      LocalKey.fromPaserk(cnf),
      htm: 'GET',
      htu: 'https://api.example/v1/me',
      accessToken: access,
      jti: 'p-1',
      now: 1700000000,
    );

    Rules withProof(String htm, {ReplayCheck? check, List<String>? seen}) =>
        Rules(
          issuer: issuer,
          audience: 'api',
          now: 1700000000,
          holder: HolderRules(
            proof: proof,
            request: ProofRequest(htm: htm, htu: 'https://api.example/v1/me'),
            replay: check,
            seenJti: seen,
          ),
        );

    final accepted = CompactToken.open(
      k,
      access,
      withProof('GET', check: (_) => true),
    );
    expect(accepted['cnf'], cnf);
    expect(
      () => CompactToken.open(k, access, withProof('POST', seen: const [])),
      verdict('proof_mismatch'),
    );
    expect(
      () => CompactToken.open(k, access, withProof('GET', seen: const ['p-1'])),
      verdict('proof_replayed'),
    );
  });

  test('cb3.public refuses a cnf that is not a key', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    final bound = {...claims, 'cnf': 'not-a-key'};
    final sk = SecretKey.generate();
    expect(() => CompactToken.sign(sk, bound), verdict('argument'));
  });
}
