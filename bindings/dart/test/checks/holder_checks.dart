import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('a bound token needs a proof that matches the request', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    final client = SecretKey.generate();
    final bound = <String, Object?>{
      'iss': issuer,
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
      'cnf': client.publicKey().toPaserk(),
    };
    final k = LocalKey.generate();
    final access = Token.seal(k, bound);
    expect(() => Token.open(k, access, rules), verdict('missing_proof'));
    final proof = Holder.prove(
      client,
      htm: 'GET',
      htu: 'https://api.example/v1/me',
      accessToken: access,
      jti: 'p-1',
      now: 1700000000,
    );
    expect(proof, startsWith('cb2.holder-public.'));

    Rules withProof(
      String htm,
      String htu, {
      int now = 1700000000,
      List<String>? seen,
      ReplayCheck? check,
    }) => Rules(
      issuer: issuer,
      audience: 'api',
      now: now,
      holder: HolderRules(
        proof: proof,
        request: ProofRequest(htm: htm, htu: htu),
        seenJti: seen,
        replay: check,
      ),
    );

    const loud = 'HTTPS://API.EXAMPLE:443/v1/me?x=1';
    const quiet = 'https://api.example/v1/me';
    expect(
      () => Token.open(k, access, withProof('GET', loud)),
      verdict('rules_incomplete'),
    );
    final accepted = Token.open(
      k,
      access,
      withProof('GET', loud, check: (_) => true),
    );
    expect(accepted['aud'], 'api');
    expect(
      () => Token.open(k, access, withProof('POST', quiet, seen: const [])),
      verdict('proof_mismatch'),
    );
    expect(
      () => Token.open(k, access, withProof('GET', quiet, seen: const ['p-1'])),
      verdict('proof_replayed'),
    );
    expect(
      () => Token.open(
        k,
        access,
        withProof('GET', quiet, now: 1700000100, seen: const []),
      ),
      verdict('proof_expired'),
    );
    expect(Token.open(k, access, rulesWith(ignoreCnf: true))['aud'], 'api');
  });

  test('target normalization', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    expect(
      Holder.normalizeTarget('HTTPS://API.Example:443/a?b#c'),
      'https://api.example/a',
    );
    expect(() => Holder.normalizeTarget('nope'), verdict('argument'));
  });
}
