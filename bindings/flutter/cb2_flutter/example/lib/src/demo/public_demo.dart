import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/demo/demo_fixtures.dart';
import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';
import 'package:cb2_flutter_example/src/demo/step_runner.dart';

/// Signs a cb2.public token, verifies it with the public key, then has
/// the library refuse it for another audience.
List<DemoStep> publicSteps() {
  if (!hasPublic()) {
    return const [
      DemoStep(
        title: 'cb2.public',
        detail: 'not in this build of the library',
        outcome: StepOutcome.skipped,
      ),
    ];
  }
  final secret = SecretKey.generate();
  final public = secret.publicKey();
  final token = Token.sign(secret, demoClaims('public-1'));
  final steps = [
    expectAccepted('Sign a cb2.public token', () => shorten(token)),
    expectAccepted(
      'Verify it with the public key',
      () => describe(Token.verify(public, token, freshRules('api'))),
    ),
    expectRefused(
      'Verify it for another audience',
      () => Token.verify(public, token, freshRules('billing')),
    ),
  ];
  public.dispose();
  secret.dispose();
  return steps;
}
