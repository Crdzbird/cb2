import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const List<String> entries = [issuer, 'api', 'billing'];

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void run() {
  final t = ClaimTable.fromEntries(entries);
  final other = ClaimTable.fromEntries(const ['api', issuer, 'billing']);

  test('refused entries', () {
    final refused = [
      <String>[],
      ['a', 'a'],
      ['a', ''],
      ['a\nb'],
      [for (var i = 0; i < 257; i++) 'e$i'],
    ];
    for (final bad in refused) {
      expect(() => ClaimTable.fromEntries(bad), verdict('argument'));
    }
    expect(ClaimTable.fromEntries(['a']).digest, hasLength(32));
  });

  test('the digest names the entries and their order', () {
    expect(
      hex(t.digest),
      '767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d',
    );
    expect(t.digest, hasLength(ClaimTable.digestBytes));
    expect(ClaimTable.fromEntries(entries).digest, t.digest);
    expect(other.digest, isNot(t.digest));
  });

  test('a disposed table is refused', () {
    final k = LocalKey.generate();
    final gone = ClaimTable.fromEntries(entries)
      ..dispose()
      ..dispose();
    expect(() => gone.digest, throwsStateError);
    expect(() => CompactToken.seal(k, claims, table: gone), throwsStateError);
  });

  test('cb3.public under a table', () {
    if (!hasPublic()) {
      markTestSkipped('cb2.public unavailable in this build');
      return;
    }
    final sk = SecretKey.generate();
    final pk = sk.publicKey();
    final signed = CompactToken.sign(sk, claims, table: t);
    final plain = CompactToken.sign(sk, claims);
    expect(signed, startsWith('cb3.public.'));
    expect(signed.length, lessThan(plain.length));
    final same = ClaimTable.fromEntries(entries);
    expect(CompactToken.verify(pk, signed, rules, table: same)['aud'], 'api');
    expect(() => CompactToken.verify(pk, signed, rules), verdict('invalid'));
    expect(
      () => CompactToken.verify(pk, signed, rules, table: other),
      verdict('invalid'),
    );
    expect(
      () => CompactToken.verify(pk, plain, rules, table: t),
      verdict('invalid'),
    );
  });
}
