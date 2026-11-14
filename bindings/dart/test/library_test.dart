@TestOn('vm')
library;

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

/// The native loader: load opens the library the rules of Cb2Library
/// find, which needs no await before calls outside a browser.
void main() {
  test('load opens the library and calls are served', () async {
    await Cb2Library.load();
    expect(Cb2Library.isLoaded, isTrue);
    expect(version(), isNotEmpty);
    expect(Cb2Library.engineUrl, 'assets/packages/cb2/js/src/cb2.js');
  });
}
