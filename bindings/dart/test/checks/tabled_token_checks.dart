import 'dart:convert';

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'claim_table_checks.dart' show entries;
import 'fixtures.dart';

void run() {
  final k = LocalKey.generate();
  final t = ClaimTable.fromEntries(entries);
  final same = ClaimTable.fromEntries(entries);
  final other = ClaimTable.fromEntries(const ['api', issuer, 'billing']);
  final tabled = CompactToken.seal(k, claims, table: t);
  final plain = CompactToken.seal(k, claims);

  test('a tabled token is shorter and opens to the same claims', () {
    expect(tabled, startsWith('cb3.local.'));
    expect(tabled.length + 30, lessThan(plain.length));
    expect(
      CompactToken.open(k, tabled, rules, table: same),
      CompactToken.open(k, plain, rules),
    );
  });

  test('a token opens only under the table it was made under', () {
    expect(() => CompactToken.open(k, tabled, rules), verdict('invalid'));
    expect(
      () => CompactToken.open(k, tabled, rules, table: other),
      verdict('invalid'),
    );
    expect(
      () => CompactToken.open(k, plain, rules, table: t),
      verdict('invalid'),
    );
  });

  test('issuer and audience rules keep their meaning', () {
    expect(
      () => CompactToken.open(
        k,
        tabled,
        rulesWith(audience: 'billing'),
        table: t,
      ),
      verdict('audience_mismatch'),
    );
    const otherIssuer = Rules(
      issuer: 'https://other.example',
      audience: 'api',
      now: 1700000000,
    );
    expect(
      () => CompactToken.open(k, tabled, otherIssuer, table: t),
      verdict('issuer_mismatch'),
    );
    const any = Rules(
      allowAnyIssuer: true,
      allowAnyAudience: true,
      now: 1700000000,
    );
    final opened = CompactToken.open(k, tabled, any, table: t);
    expect(opened['iss'], issuer);
    expect(opened['aud'], 'api');
  });

  test('the reserved implicit assertion needs a table', () {
    final reserved = utf8.encode('kcb3.table.');
    expect(
      () => CompactToken.seal(k, claims, implicit: reserved),
      verdict('argument'),
    );
    expect(
      () => CompactToken.open(k, plain, rules, implicit: reserved),
      verdict('argument'),
    );
    final bound = CompactToken.seal(k, claims, implicit: reserved, table: t);
    expect(
      CompactToken.open(k, bound, rules, implicit: reserved, table: t)['sub'],
      'user-1',
    );
  });
}
