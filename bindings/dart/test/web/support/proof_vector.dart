import 'dart:typed_data';

import 'package:cb2/cb2.dart';

import 'verdict.dart';

/// The verdict the browser gives the proofs.json test [test] of the
/// vectors document [doc], opened the way tests/test_vectors.cpp opens
/// it: the access token under its key, with the document's issuer and
/// audience, the test's rules, and the proof when there is one.
String proofVectorVerdict(Map<String, Object?> doc, Map<String, Object?> test) {
  final tokens = doc['access-tokens']! as Map<String, Object?>;
  final access = tokens[test['access-token']]! as Map<String, Object?>;
  final o = test['rules']! as Map<String, Object?>;
  final request = test['request']! as Map<String, Object?>;
  final proof = test['proof']! as String;
  final rules = Rules(
    issuer: doc['issuer']! as String,
    audience: doc['audience']! as String,
    now: o['now']! as int,
    clockSkew: o['clock-skew']! as int,
    requireCnf: o['require-cnf']! as bool,
    ignoreCnf: o['ignore-cnf']! as bool,
    holder: proof.isEmpty
        ? null
        : HolderRules(
            proof: proof,
            request: ProofRequest(
              htm: request['htm']! as String,
              htu: request['htu']! as String,
              nonce: request['nonce'] as String?,
            ),
            lifetime: o['proof-lifetime']! as int,
            seenJti: (o['seen-jti']! as List).cast<String>(),
          ),
  );
  final token = access['token']! as String;
  if (access['purpose'] == 'local') {
    final key = LocalKey.fromBytes(unhex(access['key']! as String));
    return verdictOf(() => Token.open(key, token, rules));
  }
  final key = PublicKey.fromBytes(
    unhex(access['issuer-public-key']! as String),
  );
  return verdictOf(() => Token.verify(key, token, rules));
}

/// The bytes of the hex string [hex].
Uint8List unhex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);
