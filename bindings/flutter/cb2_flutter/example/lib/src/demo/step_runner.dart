import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';

/// Runs [run], which must succeed, and reports what it returned.
DemoStep expectAccepted(String title, String Function() run) {
  try {
    return DemoStep(title: title, detail: run(), outcome: StepOutcome.accepted);
  } on Cb2Exception catch (e) {
    return DemoStep(
      title: title,
      detail: 'refused with ${e.name}, which is a bug',
      outcome: StepOutcome.failed,
    );
  }
}

/// Runs [run], which the library must refuse, and reports the verdict.
DemoStep expectRefused(String title, void Function() run) {
  try {
    run();
    return DemoStep(
      title: title,
      detail: 'accepted, which is a bug',
      outcome: StepOutcome.failed,
    );
  } on Cb2Exception catch (e) {
    return DemoStep(
      title: title,
      detail: 'refused with ${e.name}',
      outcome: StepOutcome.refused,
    );
  }
}
