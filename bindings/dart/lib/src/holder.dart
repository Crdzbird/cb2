import 'dart:ffi';

import 'package:cb2/src/cb2_exception.dart';
import 'package:cb2/src/ffi/loaded.dart';
import 'package:cb2/src/local_key.dart';
import 'package:cb2/src/memory.dart';
import 'package:cb2/src/prove_call.dart';
import 'package:cb2/src/secret_key.dart';
import 'package:ffi/ffi.dart';

/// Holder proofs: made by the client for one request and one access
/// token, presented alongside the token to prove possession of the key
/// its cnf claim binds.
final class Holder {
  const Holder._();

  /// A public-mode proof by [client] for the request [htm] [htu] and
  /// [accessToken], identified by [jti], valid from [now] for [lifetime]
  /// seconds.
  static String prove(
    SecretKey client, {
    required String htm,
    required String htu,
    required String accessToken,
    required String jti,
    required int now,
    String? nonce,
    int lifetime = 60,
  }) => proveCall(
    bindings.proofs.holderProve,
    client.handle,
    htm: htm,
    htu: htu,
    accessToken: accessToken,
    jti: jti,
    now: now,
    nonce: nonce,
    lifetime: lifetime,
  );

  /// A local-mode proof under [proofKey], the kcb2.local key the issuer
  /// put in cnf of a cb2.local [accessToken], for the request [htm] [htu],
  /// identified by [jti], valid from [now] for [lifetime] seconds.
  static String proveLocal(
    LocalKey proofKey, {
    required String htm,
    required String htu,
    required String accessToken,
    required String jti,
    required int now,
    String? nonce,
    int lifetime = 60,
  }) => proveCall(
    bindings.proofs.holderProveLocal,
    proofKey.handle,
    htm: htm,
    htu: htu,
    accessToken: accessToken,
    jti: jti,
    now: now,
    nonce: nonce,
    lifetime: lifetime,
  );

  /// The canonical form of a request target [uri] as the proof binds it.
  static String normalizeTarget(String uri) => using((arena) {
    final out = arena<Pointer<Char>>();
    Cb2Exception.check(
      bindings.proofs.holderNormalizeTarget(
        arenaText(arena, uri),
        textLength(uri),
        out,
      ),
    );
    return takeText(out.value);
  });
}
