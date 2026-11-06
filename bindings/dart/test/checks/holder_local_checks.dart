import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('a token bound to a local proof key needs a proof under it', () {
    final k = LocalKey.generate();
    final cnf = LocalKey.generate().toPaserk();
    final bound = <String, Object?>{
      'iss': issuer,
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
      'cnf': cnf,
    };
    final access = Token.seal(k, bound);
    expect(() => Token.open(k, access, rules), verdict('missing_proof'));
    String proveWith(LocalKey key, String jti) => Holder.proveLocal(
      key,
      htm: 'GET',
      htu: 'https://api.example/v1/me',
      accessToken: access,
      jti: jti,
      now: 1700000000,
    );
    final proof = proveWith(LocalKey.fromPaserk(cnf), 'p-1');
    expect(proof, startsWith('cb2.holder-local.'));
    expect(proof.length, lessThan(450));

    Rules withProof(
      String htm,
      String presented, {
      int now = 1700000000,
      List<String>? seen,
      ReplayCheck? check,
    }) => Rules(
      issuer: issuer,
      audience: 'api',
      now: now,
      proof: presented,
      request: ProofRequest(htm: htm, htu: 'https://api.example/v1/me'),
      proofSeenJti: seen,
      proofReplay: check,
    );

    expect(
      () => Token.open(k, access, withProof('GET', proof)),
      verdict('rules_incomplete'),
    );
    final accepted = Token.open(
      k,
      access,
      withProof('GET', proof, check: (_) => true),
    );
    expect(accepted['aud'], 'api');
    expect(
      () => Token.open(k, access, withProof('POST', proof, seen: const [])),
      verdict('proof_mismatch'),
    );
    expect(
      () => Token.open(k, access, withProof('GET', proof, seen: const ['p-1'])),
      verdict('proof_replayed'),
    );
    expect(
      () => Token.open(
        k,
        access,
        withProof('GET', proof, now: 1700000100, seen: const []),
      ),
      verdict('proof_expired'),
    );
    final forged = proveWith(LocalKey.generate(), 'p-2');
    expect(
      () => Token.open(k, access, withProof('GET', forged, seen: const [])),
      verdict('proof_invalid'),
    );
  });
}
