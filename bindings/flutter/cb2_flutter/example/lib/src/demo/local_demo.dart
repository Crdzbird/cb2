import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/demo/demo_fixtures.dart';
import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_runner.dart';

/// Seals a cb2.local token, opens it once, then has the library refuse a
/// replay of it and a tampered copy; then seals and opens the same claims
/// as a compact cb3.local token.
List<DemoStep> localSteps() {
  final key = LocalKey.generate();
  final seen = <String>{};
  final rules = Rules(issuer: demoIssuer, audience: 'api', replay: seen.add);
  final token = Token.seal(key, demoClaims('local-1'));
  final compact = CompactToken.seal(key, demoClaims('local-2'));
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
    expectAccepted('Seal a compact cb3.local token', () => shorten(compact)),
    expectAccepted(
      'Open the compact token',
      () => describe(CompactToken.open(key, compact, rules)),
    ),
  ];
  key.dispose();
  return steps;
}
