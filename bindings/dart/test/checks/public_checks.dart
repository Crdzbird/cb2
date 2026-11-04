import 'dart:typed_data';

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  test('sign and verify', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    final sk = SecretKey.generate();
    final pk = sk.publicKey();
    final pub = pk.toPaserk();
    expect(pub.length, 2658);
    expect(pk.paserkId, startsWith('kcb2.pid.'));
    final pk2 = PublicKey.fromPaserk(pub);
    final token = Token.sign(sk, claims);
    expect(Token.verify(pk2, token, rules)['sub'], 'user-1');
    final stranger = SecretKey.generate();
    final spk = stranger.publicKey();
    expect(() => Token.verify(spk, token, rules), verdict('invalid'));
    final raw = Public.sign(sk, Uint8List.fromList([1, 2, 3]));
    expect(Public.verify(pk, raw), [1, 2, 3]);
    expect(() => Public.verify(spk, raw), verdict('invalid'));
    sk.keyId = 'signer-1';
    expect(sk.keyId, 'signer-1');
    sk.clearKeyId();
    expect(sk.keyId, isNull);
  });
}
