import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:cb2_flutter_example/src/app/cb2_example_app.dart';
import 'package:cb2_flutter_example/src/view/demo_page_state.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Runs the demo in the app on a device, against the library the plugin
/// bundles, and checks every verdict on screen.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('the demo accepts good tokens and refuses bad ones', (
    tester,
  ) async {
    Cb2Flutter.ensureInitialized();
    await tester.pumpWidget(const Cb2ExampleApp());
    await tester.tap(find.byKey(DemoPageState.runKey));
    await tester.pump();
    final running = find.text('Running...');
    for (var i = 0; i < 100 && running.evaluate().isNotEmpty; i++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    expect(running, findsNothing);
    for (final verdict in const [
      'refused with replayed',
      'refused with invalid',
      'refused with audience_mismatch',
    ]) {
      await tester.scrollUntilVisible(find.text(verdict), 120);
      expect(find.text(verdict), findsOneWidget);
    }
    expect(find.byIcon(Icons.error), findsNothing);
  });
}
