import 'dart:io';

import 'package:cb2/cb2.dart';
import 'package:stream_channel/stream_channel.dart';

import '../support/verdict.dart';

/// The native side of the cross checks. A browser suite spawns it in the
/// VM with spawnHybridUri, and it answers the one request it is given
/// with the C library that CB2_C_LIBRARY names, through dart:ffi.
Future<void> hybridMain(StreamChannel<Object?> channel, Object? message) async {
  final request = (message! as Map).cast<String, Object?>();
  channel.sink.add(switch (request['op']) {
    'vectors' => File('../../tests/vectors/proofs.json').readAsStringSync(),
    'prove' => _prove(request),
    'verify' => _verify(request),
    'normalize' => _normalize(request),
    _ => throw ArgumentError.value(request['op'], 'op'),
  });
  await channel.sink.close();
}

String _prove(Map<String, Object?> r) {
  final key = LocalKey.fromPaserk(r['proofKey']! as String);
  final proof = Holder.proveLocal(
    key,
    htm: r['htm']! as String,
    htu: r['htu']! as String,
    accessToken: r['token']! as String,
    jti: r['jti']! as String,
    now: r['now']! as int,
  );
  key.dispose();
  return proof;
}

String _verify(Map<String, Object?> r) {
  final key = LocalKey.fromPaserk(r['issuerKey']! as String);
  final rules = crossRules(
    proof: r['proof']! as String,
    htm: r['htm']! as String,
    htu: r['htu']! as String,
    now: r['now']! as int,
    seen: (r['seen']! as List).cast<String>(),
  );
  final verdict = verdictOf(
    () => Token.open(key, r['token']! as String, rules),
  );
  key.dispose();
  return verdict;
}

List<String> _normalize(Map<String, Object?> r) => [
  for (final uri in (r['uris']! as List).cast<String>())
    normalizedOrVerdict(uri),
];
