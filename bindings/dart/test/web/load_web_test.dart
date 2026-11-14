@TestOn('browser')
library;

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'support/served_engine.dart';

final Matcher _unavailable = throwsA(
  isA<Cb2Exception>()
      .having((e) => e.code, 'code', Cb2Exception.unavailable)
      .having((e) => e.name, 'name', 'unavailable'),
);

/// The engine fails closed until it is loaded: every call is refused as
/// unavailable, a load that fails leaves it so and can be retried, and a
/// completed load serves every call.
void main() {
  test('every call is refused as unavailable before the engine loads', () {
    expect(Cb2Library.isLoaded, isFalse);
    expect(() => LocalKey.fromPaserk('kcb2.local.x'), _unavailable);
    expect(() => Holder.normalizeTarget('https://ojo.example/'), _unavailable);
    expect(LocalKey.generate, _unavailable);
    expect(version, _unavailable);
    expect(Cb2Exception.nameOf(3), 'unknown');
  });

  test('a load that fails leaves the engine unloaded', () async {
    Cb2Library.engineUrl = Uri.base.resolve('missing/cb2.js').toString();
    await expectLater(Cb2Library.load(), throwsA(anything));
    expect(Cb2Library.isLoaded, isFalse);
    Cb2Library.engineUrl = Uri.base.resolve('../../js/src/error.js').toString();
    await expectLater(Cb2Library.load(), _unavailable);
    expect(Cb2Library.isLoaded, isFalse);
    expect(LocalKey.generate, _unavailable);
  });

  test('loading is shared, idempotent, and then serves calls', () async {
    Cb2Library.engineUrl = servedEngineUrl;
    expect(Cb2Library.candidates(), [servedEngineUrl]);
    await Future.wait([Cb2Library.load(), Cb2Library.load()]);
    await Cb2Library.load();
    expect(Cb2Library.isLoaded, isTrue);
    expect(version(), isNotEmpty);
    expect(hasPublic(), isTrue);
    expect(hasSeal(), isTrue);
    expect(Cb2Exception.nameOf(3), 'argument');
  });

  test('a disposed key is refused like a native one', () {
    final key = LocalKey.generate()..dispose();
    expect(() => key.handle, throwsStateError);
    expect(key.toPaserk, throwsStateError);
    key.dispose();
  });

  test('the bundled engine path is where Flutter serves the assets', () {
    expect(Cb2Library.bundledEngine, 'assets/packages/cb2/js/src/cb2.js');
  });
}
