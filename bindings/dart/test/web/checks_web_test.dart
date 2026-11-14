@TestOn('browser')
library;

import 'package:test/test.dart';

import '../checks/claim_table_checks.dart' as claim_table;
import '../checks/compact_checks.dart' as compact;
import '../checks/compact_holder_checks.dart' as compact_holder;
import '../checks/holder_checks.dart' as holder;
import '../checks/holder_local_checks.dart' as holder_local;
import '../checks/local_key_checks.dart' as local_key;
import '../checks/local_token_checks.dart' as local_token;
import '../checks/public_checks.dart' as public;
import '../checks/seal_checks.dart' as seal;
import '../checks/tabled_token_checks.dart' as tabled_token;
import 'support/served_engine.dart';

/// The checks the native suite runs, unchanged, against the WebAssembly
/// engine in the browser: the same API gives the same verdicts. Some
/// groups make keys while they are declared, so the engine is loaded
/// before any group is.
Future<void> main() async {
  await loadServedEngine();
  group('local keys', local_key.run);
  group('local tokens', local_token.run);
  group('public', public.run);
  group('holder', holder.run);
  group('holder local', holder_local.run);
  group('seal', seal.run);
  group('compact', compact.run);
  group('compact holder', compact_holder.run);
  group('claim table', claim_table.run);
  group('tabled tokens', tabled_token.run);
}
