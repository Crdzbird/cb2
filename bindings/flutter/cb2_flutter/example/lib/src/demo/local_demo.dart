import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/demo/demo_fixtures.dart';
import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_runner.dart';

/// Seals a cb2.local token, opens it once, then has the library refuse a
/// replay of it and a tampered copy.
List<DemoStep> localSteps() {
  final key = LocalKey.generate();
  final seen = <String>{};
  final rules = Rules(issuer: demoIssuer, audience: 'api', replay: seen.add);
  final token = Token.seal(key, demoClaims('local-1'));
  final steps = [
    expectAccepted('Seal a cb2.local token', () => shorten(token)),
    expectAccepted(
      'Open it with the same key',
      () => describe(Token.open(key, token, rules)),
    ),
    expectRefused(
      'Open the same token again',
      () => Token.open(key, token, rules),
    ),
    expectRefused(
      'Open a tampered copy',
      () => Token.open(key, tamper(token), freshRules('api')),
    ),
  ];
  key.dispose();
  return steps;
}
