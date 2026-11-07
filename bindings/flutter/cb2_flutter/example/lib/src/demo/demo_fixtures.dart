import 'package:cb2_flutter/cb2_flutter.dart';

/// The issuer every demo token names.
const demoIssuer = 'https://issuer.example';

/// The claims of a demo token identified by [jti].
Map<String, Object?> demoClaims(String jti) => {
  'iss': demoIssuer,
  'aud': 'api',
  'sub': 'user-1',
  'exp': '2099-01-01T00:00:00+00:00',
  'jti': jti,
  'role': 'reader',
};

/// Rules for [audience] that accept every token id.
Rules freshRules(String audience) =>
    Rules(issuer: demoIssuer, audience: audience, replay: (_) => true);

/// [token] with one character of its payload changed.
String tamper(String token) {
  final at = token.length - 8;
  final swapped = token[at] == 'A' ? 'B' : 'A';
  return token.replaceRange(at, at + 1, swapped);
}

/// The start of [token] and its length, for display.
String shorten(String token) =>
    '${token.substring(0, 28)}... (${token.length} chars)';

/// The claims shown for an accepted token.
String describe(Map<String, Object?> claims) =>
    'sub ${claims['sub']}, role ${claims['role']}, jti ${claims['jti']}';
