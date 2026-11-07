import 'package:cb2/src/proof_request.dart';
import 'package:cb2/src/replay_check.dart';

/// How the holder proof presented with a token is checked: the proof, the
/// request it must match, its lifetime, and its replay check.
///
/// A proof needs a replay check, [seenJti] or [replay]; without one the
/// library refuses the rules as rules_incomplete.
final class HolderRules {
  /// The checks for [proof], made for [request].
  const factory HolderRules({
    required String proof,
    required ProofRequest request,
    int? lifetime,
    List<String>? seenJti,
    ReplayCheck? replay,
  }) = HolderRules._;

  const HolderRules._({
    required this.proof,
    required this.request,
    this.lifetime,
    this.seenJti,
    this.replay,
  });

  /// The holder proof text presented with the request.
  final String proof;

  /// The request the proof must match.
  final ProofRequest request;

  /// The longest proof lifetime accepted, in seconds.
  final int? lifetime;

  /// Proof ids already seen; a proof whose jti is listed is refused.
  final List<String>? seenJti;

  /// The replay check run for the jti of the proof; throwing refuses it.
  final ReplayCheck? replay;
}
