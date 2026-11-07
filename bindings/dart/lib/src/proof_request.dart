/// The request a holder proof must match: method, target and nonce.
final class ProofRequest {
  /// The request [htm] [htu], with the [nonce] the server issued.
  const factory ProofRequest({
    required String htm,
    required String htu,
    String? nonce,
  }) = ProofRequest._;

  const ProofRequest._({required this.htm, required this.htu, this.nonce});

  /// The HTTP method of the request.
  final String htm;

  /// The target URI of the request, normalized by the library.
  final String htu;

  /// The server nonce the proof must carry, when one was issued.
  final String? nonce;

  /// The JSON object the rules carry under "request".
  Map<String, Object?> toJson() => {
    'htm': htm,
    'htu': htu,
    if (nonce != null) 'nonce': nonce,
  };
}
