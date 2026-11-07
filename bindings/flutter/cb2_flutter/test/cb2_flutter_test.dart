import 'dart:io';

import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

/// Checks the plugin wiring, and a round trip through the native library
/// when CB2_C_LIBRARY names a host build of it.
void main() {
  final hostLibrary = Platform.environment['CB2_C_LIBRARY'];

  test('ensureInitialized names the bundled library', () {
    Cb2Flutter.ensureInitialized();
    expect(Cb2Library.name, Cb2Flutter.libraryName);
    expect(Cb2Library.preferBundled, isTrue);
    expect(Cb2Library.candidates(), isNotEmpty);
  });

  test('a cb2.local token round trip through the re-exported API', () {
    Cb2Flutter.ensureInitialized();
    final key = LocalKey.generate();
    final token = Token.seal(key, const {
      'iss': 'https://issuer.example',
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
    });
    const rules = Rules(issuer: 'https://issuer.example', audience: 'api');
    expect(Token.open(key, token, rules)['aud'], 'api');
    key.dispose();
  }, skip: hostLibrary == null ? 'CB2_C_LIBRARY is not set' : false);
}
