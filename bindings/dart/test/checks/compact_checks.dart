import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  final k = LocalKey.generate();
  final compact = CompactToken.seal(k, claims);
  final full = Token.seal(k, claims);

  test('a compact token is shorter and opens to the same claims', () {
    expect(compact, startsWith('cb3.local.'));
    expect(compact.length, lessThan(full.length));
    expect(CompactToken.open(k, compact, rules), Token.open(k, full, rules));
  });

  test('neither format opens as the other', () {
    expect(() => Token.open(k, compact, rules), verdict('invalid'));
    expect(() => CompactToken.open(k, full, rules), verdict('invalid'));
  });

  test('rules verdicts', () {
    expect(
      () => CompactToken.open(k, compact, const Rules()),
      verdict('rules_incomplete'),
    );
    expect(
      () => CompactToken.open(k, compact, rulesWith(audience: 'web')),
      verdict('audience_mismatch'),
    );
    expect(
      () => CompactToken.open(k, compact, rulesWith(now: 4102444800)),
      verdict('expired'),
    );
    expect(
      () => CompactToken.open(k, compact, rulesWith(seenJti: const ['id-1'])),
      verdict('replayed'),
    );
    final remembered = <String>[];
    bool remember(String jti) {
      remembered.add(jti);
      return remembered.length == 1;
    }

    final once = rulesWith(replay: remember);
    expect(CompactToken.open(k, compact, once)['jti'], 'id-1');
    expect(() => CompactToken.open(k, compact, once), verdict('replayed'));
  });

  test('the peeked key digest is the digest of the key id', () {
    final peeked = CompactToken.peekKeyDigest(compact);
    expect(peeked, hasLength(CompactToken.keyDigestBytes));
    expect(peeked, CompactToken.keyDigest(k.keyId!));
    expect(CompactToken.peekKeyDigest(full), isNull);
    expect(() => CompactToken.keyDigest('a\nb'), verdict('argument'));
    expect(CompactToken.keyDigest(''), hasLength(16));
  });

  test('a key without an id', () {
    final bare = LocalKey.fromPaserk(k.toPaserk())..clearKeyId();
    final token = CompactToken.seal(bare, claims);
    expect(CompactToken.peekKeyDigest(token), isNull);
    expect(CompactToken.open(bare, token, rules)['sub'], 'user-1');
    expect(() => CompactToken.open(bare, compact, rules), verdict('invalid'));
  });

  test('a fraction is refused by the compact issuer only', () {
    final fraction = {...claims, 'n': 1.5};
    expect(() => CompactToken.seal(k, fraction), verdict('argument'));
    expect(Token.seal(k, fraction), startsWith('cb2.local.'));
  });

  test('cb3.public sign and verify', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    final sk = SecretKey.generate();
    final pk = sk.publicKey();
    final signed = CompactToken.sign(sk, claims);
    final signedFull = Token.sign(sk, claims);
    expect(signed, startsWith('cb3.public.'));
    expect(signed.length, lessThan(signedFull.length));
    expect(CompactToken.verify(pk, signed, rules)['role'], 'admin');
    expect(() => Token.verify(pk, signed, rules), verdict('invalid'));
    expect(
      () => CompactToken.verify(pk, signedFull, rules),
      verdict('invalid'),
    );
    expect(
      () => CompactToken.verify(pk, signed, rulesWith(audience: 'web')),
      verdict('audience_mismatch'),
    );
    expect(
      CompactToken.peekKeyDigest(signed),
      CompactToken.keyDigest(sk.keyId!),
    );
  });
}
