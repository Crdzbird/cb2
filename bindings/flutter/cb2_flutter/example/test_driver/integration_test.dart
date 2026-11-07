import 'package:integration_test/integration_test_driver.dart';

/// Drives the integration tests and writes what they report to
/// build/integration_response_data.json.
Future<void> main() => integrationDriver();
