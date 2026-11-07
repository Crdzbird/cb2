import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/local_demo.dart';
import 'package:cb2_flutter_example/src/demo/public_demo.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';

/// Runs the whole demo and returns its steps in order.
///
/// It may run in any isolate: it initializes the loader of the isolate it
/// runs in, and every key it makes is freed before it returns.
List<DemoStep> runTokenDemo() {
  Cb2Flutter.ensureInitialized();
  final features = [if (hasPublic()) 'cb2.public', if (hasSeal()) 'kcb2.seal'];
  return [
    DemoStep(
      title: 'Load the native library',
      detail: 'cb2 ${version()} with cb2.local ${features.join(' ')}',
      outcome: StepOutcome.accepted,
    ),
    ...localSteps(),
    ...publicSteps(),
  ];
}
