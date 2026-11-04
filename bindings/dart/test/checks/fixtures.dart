import 'package:cb2/cb2.dart';
import 'package:test/test.dart';

const issuer = 'https://issuer.example';

const claims = <String, Object?>{
  'iss': issuer,
  'sub': 'user-1',
  'aud': 'api',
  'exp': '2099-01-01T00:00:00+00:00',
  'jti': 'id-1',
  'role': 'admin',
};

const rules = Rules(issuer: issuer, audience: 'api', now: 1700000000);

/// Matches a thrown [Cb2Exception] whose name is [name].
Matcher verdict(String name) =>
    throwsA(isA<Cb2Exception>().having((e) => e.name, 'name', name));

/// The standard rules with one or two members changed.
Rules rulesWith({
  int now = 1700000000,
  String audience = 'api',
  ReplayCheck? replay,
  List<String>? seenJti,
  int? maxLifetime,
  bool? ignoreCnf,
}) => Rules(
  issuer: issuer,
  audience: audience,
  now: now,
  replay: replay,
  seenJti: seenJti,
  maxLifetime: maxLifetime,
  ignoreCnf: ignoreCnf,
);
