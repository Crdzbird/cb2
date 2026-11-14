import 'package:cb2/cb2.dart';

/// ok when [check] returns, else the name of the verdict it threw.
String verdictOf(void Function() check) {
  try {
    check();
    return 'ok';
  } on Cb2Exception catch (e) {
    return e.name;
  }
}

/// The canonical form of [uri], or ! and the verdict name when refused.
String normalizedOrVerdict(String uri) {
  try {
    return Holder.normalizeTarget(uri);
  } on Cb2Exception catch (e) {
    return '!${e.name}';
  }
}

/// The rules every cross check opens its access token with: the issuer
/// and audience of [claimsFor], at [now], with the holder proof [proof]
/// for [htm] [htu], refused when its id is in [seen].
Rules crossRules({
  required String proof,
  required String htm,
  required String htu,
  required int now,
  List<String> seen = const [],
}) => Rules(
  issuer: 'https://issuer.example',
  audience: 'api',
  now: now,
  holder: HolderRules(
    proof: proof,
    request: ProofRequest(htm: htm, htu: htu),
    seenJti: seen,
  ),
);

/// The claims of an access token bound to the proof key [cnf].
Map<String, Object?> claimsFor(String cnf) => {
  'iss': 'https://issuer.example',
  'aud': 'api',
  'sub': 'device-1',
  'exp': '2099-01-01T00:00:00+00:00',
  'cnf': cnf,
};
