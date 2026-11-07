import 'dart:io';

import 'package:cb2/cb2.dart';

const _issuer = 'https://issuer.example';

/// Issues a cb2.local and a cb2.public token, opens and verifies them, and
/// shows the library refusing a replay, a tampered token and a token for
/// another audience.
///
/// Run it from bindings/dart against a build of the C library:
/// CB2_C_LIBRARY=../../build/bindings/c/libcb2_c.dylib dart run example/cb2_example.dart
void main() {
  stdout.writeln('cb2 ${version()}, public ${hasPublic()}, seal ${hasSeal()}');
  _local();
  if (!hasPublic()) {
    stdout.writeln('cb2.public is not in this build of the library');
    return;
  }
  _public();
}

void _local() {
  final key = LocalKey.generate();
  final seen = <String>{};
  final rules = Rules(issuer: _issuer, audience: 'api', replay: seen.add);
  final token = Token.seal(key, _claims('local-1'));
  stdout.writeln('cb2.local token: ${_short(token)}');
  final claims = Token.open(key, token, rules);
  stdout.writeln('opened: sub ${claims['sub']}, role ${claims['role']}');
  _refuse('the same token again', () => Token.open(key, token, rules));
  _refuse(
    'a tampered token',
    () => Token.open(key, _tamper(token), _fresh('api')),
  );
  key.dispose();
}

void _public() {
  final secret = SecretKey.generate();
  final public = secret.publicKey();
  final token = Token.sign(secret, _claims('public-1'));
  stdout.writeln('cb2.public token: ${_short(token)}');
  final claims = Token.verify(public, token, _fresh('api'));
  stdout.writeln('verified: sub ${claims['sub']}, role ${claims['role']}');
  _refuse(
    'a token for another audience',
    () => Token.verify(public, token, _fresh('billing')),
  );
  public.dispose();
  secret.dispose();
}

Map<String, Object?> _claims(String jti) => {
  'iss': _issuer,
  'aud': 'api',
  'sub': 'user-1',
  'exp': '2099-01-01T00:00:00+00:00',
  'jti': jti,
  'role': 'reader',
};

Rules _fresh(String audience) =>
    Rules(issuer: _issuer, audience: audience, replay: (_) => true);

void _refuse(String what, void Function() check) {
  try {
    check();
    stdout.writeln('$what: accepted, which is a bug');
    exitCode = 1;
  } on Cb2Exception catch (e) {
    stdout.writeln('$what: refused with ${e.name}');
  }
}

String _tamper(String token) {
  final at = token.length - 8;
  final swapped = token[at] == 'A' ? 'B' : 'A';
  return token.replaceRange(at, at + 1, swapped);
}

String _short(String token) =>
    '${token.substring(0, 24)}...(${token.length} chars)';
