import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'local_key.dart';
import 'memory.dart';
import 'prove_call.dart';
import 'secret_key.dart';

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
    Cb2Library.bindings.holderProve,
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
    Cb2Library.bindings.holderProveLocal,
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
      Cb2Library.bindings.holderNormalizeTarget(
        arenaText(arena, uri),
        textLength(uri),
        out,
      ),
    );
    return takeText(out.value);
  });
}
