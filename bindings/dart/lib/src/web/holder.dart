import 'dart:js_interop';

import 'package:cb2/src/proof_request.dart';
import 'package:cb2/src/web/engine.dart';
import 'package:cb2/src/web/local_key.dart';
import 'package:cb2/src/web/secret_key.dart';
import 'package:cb2/src/web/values.dart';

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
  }) => _prove('prove', client.handle, [
    jsJson(ProofRequest(htm: htm, htu: htu, nonce: nonce).toJson()),
    accessToken.toJS,
    jti.toJS,
    now.toJS,
    lifetime.toJS,
  ]);

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
  }) => _prove('proveLocal', proofKey.handle, [
    jsJson(ProofRequest(htm: htm, htu: htu, nonce: nonce).toJson()),
    accessToken.toJS,
    jti.toJS,
    now.toJS,
    lifetime.toJS,
  ]);

  /// The canonical form of a request target [uri] as the proof binds it.
  static String normalizeTarget(String uri) =>
      textOf(Engine.current.call('Holder', 'normalizeTarget', [uri.toJS]));

  static String _prove(String method, JSObject key, List<JSAny?> rest) =>
      textOf(Engine.current.call('Holder', method, [key, ...rest]));
}
