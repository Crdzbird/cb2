@TestOn('browser')
library;

import 'package:test/test.dart';

import 'support/native.dart';
import 'support/served_engine.dart';
import 'support/verdict.dart';

/// Request targets in the shapes ojo sends, and ones the library refuses,
/// normalize to the same text, or are refused alike, in the browser and
/// natively, so a proof binds the same htu on both sides.
void main() {
  setUpAll(loadServedEngine);

  test('targets normalize alike in the browser and natively', () async {
    const uris = [
      'HTTPS://Ojo.Example:443/ojo.v1.AuthService/RefreshTokens',
      'https://ojo.example:7443/ojo.v1.Devices/List?x=1#f',
      'https://127.0.0.1:7474/ojo.v1.Ledger/Records',
      'http://[::1]:80/a',
      'not a uri',
      'https://user@ojo.example/',
    ];
    final native = await askNative({'op': 'normalize', 'uris': uris});
    final browser = uris.map(normalizedOrVerdict).toList();
    expect(browser, native);
    expect(
      browser.first,
      'https://ojo.example/ojo.v1.AuthService/RefreshTokens',
    );
    expect(browser.where((b) => b.startsWith('!')), hasLength(2));
  });
}
