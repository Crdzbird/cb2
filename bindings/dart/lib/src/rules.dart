import 'proof_request.dart';
import 'replay_check.dart';

/// The rules a claims token is checked against, one field per member of
/// the rules JSON of cb2_c.h. Times are Unix seconds.
///
/// [replay] and [proofReplay] are run for the token's jti and the proof's
/// jti; a callback that throws refuses the id.
final class Rules {
  const factory Rules({
    int? now,
    int? clockSkew,
    bool? requireExp,
    bool? allowAnyAudience,
    bool? allowAnyIssuer,
    String? issuer,
    String? audience,
    String? subject,
    int? maxTokenBytes,
    int? maxLifetime,
    ReplayCheck? replay,
    List<String>? seenJti,
    bool? requireCnf,
    bool? ignoreCnf,
    String? proof,
    ProofRequest? request,
    int? proofLifetime,
    List<String>? proofSeenJti,
    ReplayCheck? proofReplay,
  }) = Rules._;

  const Rules._({
    this.now,
    this.clockSkew,
    this.requireExp,
    this.allowAnyAudience,
    this.allowAnyIssuer,
    this.issuer,
    this.audience,
    this.subject,
    this.maxTokenBytes,
    this.maxLifetime,
    this.replay,
    this.seenJti,
    this.requireCnf,
    this.ignoreCnf,
    this.proof,
    this.request,
    this.proofLifetime,
    this.proofSeenJti,
    this.proofReplay,
  });

  final int? now;
  final int? clockSkew;
  final bool? requireExp;
  final bool? allowAnyAudience;
  final bool? allowAnyIssuer;
  final String? issuer;
  final String? audience;
  final String? subject;
  final int? maxTokenBytes;
  final int? maxLifetime;
  final ReplayCheck? replay;
  final List<String>? seenJti;
  final bool? requireCnf;
  final bool? ignoreCnf;
  final String? proof;
  final ProofRequest? request;
  final int? proofLifetime;
  final List<String>? proofSeenJti;
  final ReplayCheck? proofReplay;

  /// The rules JSON object; "replay" is set when [replay] is given.
  Map<String, Object?> toJson() => {
    if (now != null) 'now': now,
    if (clockSkew != null) 'clock_skew': clockSkew,
    if (requireExp != null) 'require_exp': requireExp,
    if (allowAnyAudience != null) 'allow_any_audience': allowAnyAudience,
    if (allowAnyIssuer != null) 'allow_any_issuer': allowAnyIssuer,
    if (issuer != null) 'issuer': issuer,
    if (audience != null) 'audience': audience,
    if (subject != null) 'subject': subject,
    if (maxTokenBytes != null) 'max_token_bytes': maxTokenBytes,
    if (maxLifetime != null) 'max_lifetime': maxLifetime,
    if (replay != null) 'replay': true,
    if (seenJti != null) 'seen_jti': seenJti,
    if (requireCnf != null) 'require_cnf': requireCnf,
    if (ignoreCnf != null) 'ignore_cnf': ignoreCnf,
    if (proof != null) 'proof': proof,
    if (request != null) 'request': request!.toJson(),
    if (proofLifetime != null) 'proof_lifetime': proofLifetime,
    if (proofSeenJti != null) 'proof_seen_jti': proofSeenJti,
  };
}
