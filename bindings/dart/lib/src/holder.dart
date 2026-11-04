import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'cb2_exception.dart';
import 'library.dart';
import 'memory.dart';
import 'secret_key.dart';

/// Holder proofs: a client's signature over one request and one access
/// token, presented alongside the token to prove possession of the key
/// named in its cnf claim.
final class Holder {
  const Holder._();

  /// A proof by [client] for the request [htm] [htu] and [accessToken],
  /// identified by [jti], valid from [now] for [lifetime] seconds.
  static String prove(
    SecretKey client, {
    required String htm,
    required String htu,
    required String accessToken,
    required String jti,
    required int now,
    String? nonce,
    int lifetime = 60,
  }) => using((arena) {
    final outProof = arena<Pointer<Char>>();
    final outLen = arena<Size>();
    Cb2Exception.check(
      Cb2Library.bindings.holderProve(
        client.handle,
        arenaText(arena, htm),
        textLength(htm),
        arenaText(arena, htu),
        textLength(htu),
        arenaText(arena, nonce),
        textLength(nonce),
        arenaText(arena, accessToken),
        textLength(accessToken),
        arenaText(arena, jti),
        textLength(jti),
        now,
        lifetime,
        outProof,
        outLen,
      ),
    );
    return takeText(outProof.value, outLen.value);
  });

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
