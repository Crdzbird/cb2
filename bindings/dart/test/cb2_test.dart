import 'package:test/test.dart';

import 'checks/compact_checks.dart' as compact;
import 'checks/compact_holder_checks.dart' as compact_holder;
import 'checks/holder_checks.dart' as holder;
import 'checks/holder_local_checks.dart' as holder_local;
import 'checks/local_key_checks.dart' as local_key;
import 'checks/local_token_checks.dart' as local_token;
import 'checks/public_checks.dart' as public;
import 'checks/seal_checks.dart' as seal;

/// The checks of bindings/c/test/test_c.c, one group per area, run against
/// the library named by CB2_C_LIBRARY.
void main() {
  group('local keys', local_key.run);
  group('local tokens', local_token.run);
  group('public', public.run);
  group('holder', holder.run);
  group('holder local', holder_local.run);
  group('seal', seal.run);
  group('compact', compact.run);
  group('compact holder', compact_holder.run);
}
