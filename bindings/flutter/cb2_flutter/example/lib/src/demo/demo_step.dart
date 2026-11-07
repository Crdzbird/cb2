import 'package:cb2_flutter_example/src/demo/step_outcome.dart';

/// One step of the demo: what was tried and what the library said.
final class DemoStep {
  /// A step titled [title] that ended in [outcome], told by [detail].
  const factory DemoStep({
    required String title,
    required String detail,
    required StepOutcome outcome,
  }) = DemoStep._;

  const DemoStep._({
    required this.title,
    required this.detail,
    required this.outcome,
  });

  /// What was tried.
  final String title;

  /// What the library returned, or why it refused.
  final String detail;

  /// How the step ended.
  final StepOutcome outcome;

  /// Whether the step ended the way it should.
  bool get asExpected => outcome != StepOutcome.failed;
}
