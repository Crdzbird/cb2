import 'package:cb2_benchmark/cb2_benchmark.dart';
import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Times every token format on the device with the cases of the Dart
/// benchmark, against the library the plugin bundles. Run it in profile
/// mode through test_driver/integration_test.dart; the table is printed
/// and written to build/integration_response_data.json.
void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('times every token format on the device', (tester) async {
    Cb2Flutter.ensureInitialized();
    final results = await runBenchmarks(BenchSettings.full);
    final rows = [for (final result in results) result.toRow()];
    binding.reportData = <String, Object>{
      'cb2': version(),
      'public': hasPublic(),
      'rows': rows,
    };
    rows.forEach(debugPrint);
    expect(rows, isNotEmpty);
  }, timeout: const Timeout(Duration(minutes: 10)));
}
