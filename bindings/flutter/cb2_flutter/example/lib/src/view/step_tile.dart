import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';
import 'package:flutter/material.dart';

/// One step of the demo: an icon for its outcome, its title and detail.
final class StepTile extends StatelessWidget {
  /// The tile of [step].
  const factory StepTile(DemoStep step, {Key? key}) = StepTile._;

  const StepTile._(this.step, {super.key});

  /// The step shown.
  final DemoStep step;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final (icon, color, label) = switch (step.outcome) {
      StepOutcome.accepted => (Icons.check_circle, colors.primary, 'accepted'),
      StepOutcome.refused => (Icons.block, colors.tertiary, 'refused'),
      StepOutcome.skipped => (Icons.remove_circle, colors.outline, 'skipped'),
      StepOutcome.failed => (Icons.error, colors.error, 'failed'),
    };
    return Semantics(
      label: '${step.title}: $label',
      child: ListTile(
        leading: Icon(icon, color: color),
        title: Text(step.title),
        subtitle: Text(step.detail),
      ),
    );
  }
}
