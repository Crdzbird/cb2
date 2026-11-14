import 'dart:io';

import 'package:cb2_flutter/cb2_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

/// Checks the plugin wiring, and cb2.local and compact cb3.local round
/// trips, with and without a claim table, through the native library when
/// CB2_C_LIBRARY names a host build of it.
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

  test('a compact cb3.local token through the re-exported API', () {
    Cb2Flutter.ensureInitialized();
    final key = LocalKey.generate();
    const claims = {
      'iss': 'https://issuer.example',
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
    };
    final token = CompactToken.seal(key, claims);
    expect(token, startsWith('cb3.local.'));
    expect(token.length, lessThan(Token.seal(key, claims).length));
    const rules = Rules(issuer: 'https://issuer.example', audience: 'api');
    expect(CompactToken.open(key, token, rules)['aud'], 'api');
    expect(
      CompactToken.peekKeyDigest(token),
      CompactToken.keyDigest(key.keyId!),
    );
    key.dispose();
  }, skip: hostLibrary == null ? 'CB2_C_LIBRARY is not set' : false);

  test('a compact token under a claim table through the re-exported API', () {
    Cb2Flutter.ensureInitialized();
    final key = LocalKey.generate();
    final table = ClaimTable.fromEntries(const [
      'https://issuer.example',
      'api',
    ]);
    const claims = {
      'iss': 'https://issuer.example',
      'aud': 'api',
      'exp': '2099-01-01T00:00:00+00:00',
    };
    final token = CompactToken.seal(key, claims, table: table);
    expect(token.length, lessThan(CompactToken.seal(key, claims).length));
    expect(table.digest, hasLength(ClaimTable.digestBytes));
    const rules = Rules(issuer: 'https://issuer.example', audience: 'api');
    final opened = CompactToken.open(key, token, rules, table: table);
    expect(opened['iss'], 'https://issuer.example');
    expect(
      () => CompactToken.open(key, token, rules),
      throwsA(isA<Cb2Exception>().having((e) => e.name, 'name', 'invalid')),
    );
    table.dispose();
    key.dispose();
  }, skip: hostLibrary == null ? 'CB2_C_LIBRARY is not set' : false);
}
