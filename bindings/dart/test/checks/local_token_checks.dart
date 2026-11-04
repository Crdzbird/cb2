import 'dart:convert';
import 'dart:typed_data';

import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void run() {
  final k = LocalKey.generate();

  test('raw seal and open', () {
    final msg = Uint8List.fromList(utf8.encode('hello'));
    final footer = Uint8List.fromList(utf8.encode('{"kid":"x"}'));
    final token = Local.seal(k, msg, footer: footer);
    expect(token, startsWith('cb2.local.'));
    expect(Local.open(k, token, footer: footer), msg);
    expect(() => Local.open(k, token), verdict('invalid'));
    final last = token[token.length - 1] == 'A' ? 'B' : 'A';
    final tampered = token.substring(0, token.length - 1) + last;
    expect(() => Local.open(k, tampered, footer: footer), verdict('invalid'));
  });

  test('claims token opens and peeks its key id', () {
    final ct = Token.seal(k, claims);
    final opened = Token.open(k, ct, rules);
    expect(opened['role'], 'admin');
    expect(opened['jti'], 'id-1');
    expect(Token.peekKeyId(ct), k.paserkId);
  });

  test('rules verdicts', () {
    final ct = Token.seal(k, claims);
    expect(() => Token.open(k, ct, const Rules()), verdict('rules_incomplete'));
    expect(
      () => Token.open(k, ct, rulesWith(audience: 'other')),
      verdict('audience_mismatch'),
    );
    expect(
      () => Token.open(k, ct, rulesWith(now: 4102444801)),
      verdict('expired'),
    );
    expect(
      () => Token.open(k, ct, rulesWith(seenJti: const ['id-1'])),
      verdict('replayed'),
    );
    expect(
      () => Token.open(k, ct, rulesWith(maxLifetime: 60)),
      verdict('lifetime_exceeded'),
    );
  });

  test('replay callback remembers, refuses, and survives a throw', () {
    final ct = Token.seal(k, claims);
    final seen = <String>[];
    bool remember(String jti) {
      if (seen.contains(jti)) {
        return false;
      }
      seen.add(jti);
      return true;
    }

    expect(Token.open(k, ct, rulesWith(replay: remember))['jti'], 'id-1');
    expect(
      () => Token.open(k, ct, rulesWith(replay: remember)),
      verdict('replayed'),
    );
    expect(seen, ['id-1']);
    final throwing = rulesWith(replay: (_) => throw StateError('store down'));
    expect(() => Token.open(k, ct, throwing), verdict('replayed'));
  });

  test('a hidden character in a claim is refused', () {
    final hidden = {'sub': 'a\u200bb', 'exp': '2099-01-01T00:00:00+00:00'};
    expect(() => Token.seal(k, hidden), verdict('argument'));
  });
}
