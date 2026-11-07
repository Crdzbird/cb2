import 'dart:typed_data';

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('library loads and names its verdicts', () {
    expect(version(), isNotEmpty);
    expect(Cb2Exception.nameOf(0), 'ok');
    expect(Cb2Exception.nameOf(3), 'argument');
    expect(Cb2Exception.nameOf(24), 'proof_replayed');
    expect(Cb2Exception.nameOf(99), 'unknown');
  });

  test('paserk and identifiers round trip', () {
    final k = LocalKey.generate();
    final paserk = k.toPaserk();
    expect(paserk, startsWith('kcb2.local.'));
    expect(paserk.length, 54);
    expect(k.paserkId, startsWith('kcb2.lid.'));
    expect(k.keyId, k.paserkId);
    final same = LocalKey.fromPaserk(paserk);
    expect(same.paserkId, k.paserkId);
  });

  test('wrapping', () {
    final k = LocalKey.generate();
    final wrapping = LocalKey.generate();
    final wrapped = KeyWrap.wrap(wrapping, k);
    expect(wrapped, startsWith('kcb2.local-wrap.'));
    expect(wrapped.length, 144);
    final unwrapped = KeyWrap.unwrap(wrapped, wrapping);
    expect(unwrapped.paserkId, k.paserkId);
    expect(() => KeyWrap.unwrap(wrapped, k), verdict('invalid'));
    unwrapped.dispose();
    wrapping.dispose();
  });

  test('key id and weak key material', () {
    final fresh = LocalKey.generate()..keyId = 'rotation-1';
    expect(fresh.keyId, 'rotation-1');
    expect(() => fresh.keyId = 'a\u200b', verdict('argument'));
    fresh.clearKeyId();
    expect(fresh.keyId, isNull);
    fresh.dispose();
    expect(() => fresh.paserkId, throwsStateError);
    final weak = Uint8List(32)..fillRange(0, 32, 7);
    expect(() => LocalKey.fromBytes(weak), verdict('argument'));
  });
}
