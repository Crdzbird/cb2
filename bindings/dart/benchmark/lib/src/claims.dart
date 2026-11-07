/// The issuer every benchmark token names.
const benchIssuer = 'https://issuer.example';

/// The audience every benchmark token names.
const benchAudience = 'api';

/// The claims of every benchmark token, iss, sub, aud, exp, iat, jti and
/// one short custom claim, with the times as RFC 3339 text, the form cb2
/// and PASETO use.
Map<String, Object?> textClaims() => {
  'iss': benchIssuer,
  'sub': 'user-1',
  'aud': benchAudience,
  'exp': '2099-01-01T00:00:00+00:00',
  'iat': '2026-01-01T00:00:00+00:00',
  'jti': 'id-1',
  'role': 'reader',
};

/// The same claims with the times as seconds since the epoch, the form
/// JWT uses.
Map<String, Object?> numericClaims() => {
  ...textClaims(),
  'exp': DateTime.utc(2099).millisecondsSinceEpoch ~/ 1000,
  'iat': DateTime.utc(2026).millisecondsSinceEpoch ~/ 1000,
};
