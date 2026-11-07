import 'dart:io';

import 'package:cb2_flutter_example/src/demo/step_outcome.dart';
import 'package:cb2_flutter_example/src/demo/token_demo.dart';
import 'package:flutter_test/flutter_test.dart';

/// Runs the demo against the host library CB2_C_LIBRARY names.
void main() {
  test(
    'every step of the demo ends as it should',
    () {
      final steps = runTokenDemo();
      expect(steps.where((s) => !s.asExpected), isEmpty);
      final refused = steps.where((s) => s.outcome == StepOutcome.refused);
      expect(refused.map((s) => s.detail), [
        'refused with replayed',
        'refused with invalid',
        'refused with audience_mismatch',
      ]);
    },
    skip: Platform.environment['CB2_C_LIBRARY'] == null
        ? 'CB2_C_LIBRARY is not set'
        : false,
  );
}
