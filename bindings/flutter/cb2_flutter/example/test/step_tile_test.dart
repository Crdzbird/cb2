import 'package:cb2_flutter_example/src/demo/demo_step.dart';
import 'package:cb2_flutter_example/src/demo/step_outcome.dart';
import 'package:cb2_flutter_example/src/view/step_tile.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('a refused step shows its verdict and a block icon', (
    tester,
  ) async {
    const step = DemoStep(
      title: 'Open the same token again',
      detail: 'refused with replayed',
      outcome: StepOutcome.refused,
    );
    await tester.pumpWidget(
      const MaterialApp(home: Material(child: StepTile(step))),
    );
    expect(find.text('Open the same token again'), findsOneWidget);
    expect(find.text('refused with replayed'), findsOneWidget);
    expect(find.byIcon(Icons.block), findsOneWidget);
    expect(step.asExpected, isTrue);
  });
}
